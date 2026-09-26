import spaces
import gradio as gr
import threading
import os
from src.retriever import SecurityRetriever
from src.ensemble import EnsembleClassifier, REMEDIATIONS, OWNERS, determine_severity
from src.controls import resolve_control
from src.findings import canonicalize_finding
from src.providers import ProviderRouter
from src.ingestion import FindingIngestionError, load_json_upload, normalize_payload
from src.github_workflow import GitHubWorkflowClient, GitHubWorkflowError
from src.memory import ConversationMemory
from src.chain_of_thought import generate_chain_of_thought
from src.input_validation import validate_input
from src.output_filter import filter_output
from src.observability import (
    setup_logging, PerformanceTimer, record_request, record_validation_block,
    record_output_filter_issue, record_rag_retrieval, record_ensemble_disagreement,
    record_human_review, record_error, record_session, record_finding_in_session,
    get_metrics, get_health_status, reset_metrics,
)

setup_logging(level="INFO", json_format=False)

retriever = SecurityRetriever(top_k=5)
classifier = EnsembleClassifier(confidence_threshold=0.55)
memory = ConversationMemory(max_sessions=10)
provider_router = ProviderRouter()

SESSION_COUNTER = 0
SESSION_LOCK = threading.Lock()


def analyze_finding(finding, session_id=None, metadata=None):
    global SESSION_COUNTER

    trace_id = None
    from src.observability import _get_trace_id
    trace_id = _get_trace_id()

    with PerformanceTimer("input_validation", trace_id):
        valid, errors, warnings = validate_input(finding)
        if not valid:
            record_validation_block(errors[0] if errors else "unknown")
            record_error("validation", errors[0])
            return {"error": errors[0]}

    if session_id is None:
        with SESSION_LOCK:
            global SESSION_COUNTER
            SESSION_COUNTER += 1
            session_id = f"session_{SESSION_COUNTER}"
        record_session(session_id)

    with PerformanceTimer("classification", trace_id):
        classification = classifier.classify(finding)
        if classification.get("method") == "ensemble" and not classification.get("ensemble_agreement", True):
            record_ensemble_disagreement()
        if classification.get("human_review_required"):
            record_human_review()
        control = resolve_control(finding, classification["category"])
        adapter = provider_router.select(finding, metadata)
        canonical_finding = canonicalize_finding(
            finding, classification, control, adapter.normalize(finding, metadata)
        )

    with PerformanceTimer("rag_retrieval", trace_id):
        rag_context, rag_sources = retriever.build_context(
            finding,
            top_k=5,
            control_id=canonical_finding.control_id,
            provider=canonical_finding.provider,
        )
        if rag_sources:
            for source in rag_sources:
                record_rag_retrieval(source.get("relevance", 0))

    with PerformanceTimer("memory_lookup", trace_id):
        memory_context = memory.get_context(session_id)
        related_context = memory.get_related_history(session_id, finding)

    combined_context = rag_context
    if memory_context:
        combined_context = f"{memory_context}\n\n{rag_context}"
    if related_context:
        combined_context = f"{related_context}\n\n{combined_context}"

    recommendation = REMEDIATIONS.get(
        classification["category"],
        "Review the finding and apply standard security hardening practices.",
    )
    provider_overlay = adapter.remediation_overlay(classification["control_id"])
    if provider_overlay:
        recommendation += f"\n\nAWS implementation guidance: {provider_overlay}"

    primary_source = rag_sources[0] if rag_sources else {}
    validation_step = primary_source.get(
        "validation", classification["validation_step"]
    )
    rollback_guidance = primary_source.get(
        "rollback_guidance",
        "Check dependent services and use a reviewed change with a documented rollback plan.",
    )
    evidence = list(canonical_finding.evidence)
    risk_summary = (
        f"{classification['severity'].capitalize()} severity {classification['category']} "
        f"finding for control {canonical_finding.control_id} "
        f"(confidence {classification['confidence']:.0%})."
    )
    citations = [
        {
            "id": source["id"],
            "title": source["title"],
            "source": source["source_name"],
            "version": source["source_version"],
            "references": source["references"],
        }
        for source in rag_sources
    ]

    recommendation += (
        f"\n\nRisk: {risk_summary}"
        f"\nEvidence: {'; '.join(evidence)}"
        f"\nOwner: {classification.get('owner', OWNERS.get(classification['category'], 'Platform Security'))}"
        f"\nValidation: {validation_step}"
        f"\nRollback and dependencies: {rollback_guidance}"
    )
    if citations:
        citation_text = "; ".join(
            f"[{citation['id']}] {citation['source']} v{citation['version']}: "
            f"{', '.join(citation['references']) or 'reference unavailable'}"
            for citation in citations
        )
        recommendation += f"\nSources: {citation_text}"

    if rag_context:
        recommendation += f"\n\nKnowledge base guidance:\n{rag_context}"

    if memory_context:
        recommendation += f"\n\nSession context:\n{memory_context}"

    with PerformanceTimer("output_filter", trace_id):
        filtered = filter_output(
            recommendation,
            finding=finding,
            category=classification.get("category", ""),
        )
        if not filtered["safe"]:
            recommendation = filtered["filtered_text"]
            for issue in filtered.get("issues", []):
                record_output_filter_issue(issue.split(":")[0] if ":" in issue else "unknown")

    record_request(
        category=classification["category"],
        severity=classification["severity"],
        method=classification.get("method", "unknown"),
        trace_id=trace_id,
    )
    record_finding_in_session(session_id)

    result = {
        "category": classification["category"],
        "control_id": classification["control_id"],
        "severity": classification["severity"],
        "confidence": classification["confidence"],
        "method": classification.get("method", "unknown"),
        "ensemble_agreement": classification.get("ensemble_agreement", True),
        "recommendation": recommendation,
        "owner": classification.get("owner", OWNERS.get(classification["category"], "Platform Security")),
        "risk_summary": risk_summary,
        "evidence": evidence,
        "validation_step": validation_step,
        "rollback_guidance": rollback_guidance,
        "citations": citations,
        "finding": canonical_finding.to_dict(),
        "human_review_required": classification["severity"] in {"high", "critical"} or classification["confidence"] < 0.60,
        "automation_allowed": False,
        "rag_sources": rag_sources,
        "session_id": session_id,
        "trace_id": trace_id,
    }

    if warnings:
        result["input_warnings"] = warnings

    if not filtered["safe"]:
        result["output_warnings"] = filtered["issues"]

    memory.add_interaction(session_id, finding, result)

    risk_summary = memory.get_risk_summary(session_id)
    if risk_summary:
        result["session_risk_summary"] = risk_summary

    return result


def analyze_ingested_findings(source, payload, session_id=None):
    """Analyze exported scanner findings while retaining manual analysis compatibility."""
    return [
        analyze_finding(finding, session_id=session_id, metadata=metadata)
        for finding, metadata in normalize_payload(source, payload)
    ]


def analyze_uploaded_findings(source, upload, session_id=None):
    """UI-safe JSON upload entry point; manual text analysis remains available."""
    try:
        payload = load_json_upload(upload)
        results = analyze_ingested_findings(source, payload, session_id)
        return {"source": source, "finding_count": len(results), "results": results}
    except FindingIngestionError as exc:
        return {"error": str(exc)}


def create_github_draft_issue(assessment, repository):
    try:
        return GitHubWorkflowClient(repository).create_draft_issue(assessment)
    except GitHubWorkflowError as exc:
        return {"error": str(exc)}


def comment_on_github_pr(assessment, repository, pull_request):
    try:
        return GitHubWorkflowClient(repository).comment_on_pull_request(
            pull_request, assessment
        )
    except GitHubWorkflowError as exc:
        return {"error": str(exc)}


@spaces.GPU
def review_finding(finding, session_id=None):
    try:
        return analyze_finding(finding, session_id)
    except Exception as e:
        record_error("exception", str(e))
        return {"error": str(e)}


@spaces.GPU
def review_finding_with_cot(finding, session_id=None):
    try:
        result = analyze_finding(finding, session_id)

        rag_context, _ = retriever.build_context(finding, top_k=5)
        memory_context = memory.get_context(session_id) if session_id else ""

        classification = {
            "category": result["category"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "method": result.get("method", "unknown"),
            "model_results": result.get("model_results", []),
            "ensemble_agreement": result.get("ensemble_agreement", True),
            "owner": result["owner"],
            "human_review_required": result["human_review_required"],
        }

        chain_of_thought = generate_chain_of_thought(
            finding, classification, rag_context, memory_context
        )

        result["chain_of_thought"] = chain_of_thought
        return result
    except Exception as e:
        record_error("exception", str(e))
        return {"error": str(e)}


def clear_session(session_id):
    memory.clear_session(session_id)
    return {"status": f"Session {session_id} cleared."}


def get_observability_metrics():
    return get_metrics()


def get_system_health():
    return get_health_status()


def reset_observability_metrics():
    reset_metrics()
    return {"status": "Metrics reset successfully."}


TEST_FINDINGS = [
    ("An IAM role grants wildcard permissions to all AWS resources.", "IAM"),
    ("The production security group allows SSH from 0.0.0.0/0.", "Network"),
    ("The Kubernetes workload runs as root in a privileged container.", "Container"),
    ("A database password is hardcoded in the Git repository.", "Secrets"),
    ("The storage bucket contains customer records with no encryption.", "Data"),
]

with gr.Blocks(
    title="AI DevSecOps Advisor",
    theme=gr.themes.Soft(primary_hue="green", secondary_hue="emerald"),
) as demo:
    gr.Markdown("# AI DevSecOps Advisor")
    gr.Markdown(
        "Classifies infrastructure risks with RAG, multi-model ensemble, "
        "conversation memory, and chain-of-thought reasoning. "
        "No infrastructure changes are executed."
    )

    with gr.Row():
        with gr.Column(scale=2):
            finding_input = gr.Textbox(
                lines=5,
                label="Infrastructure security finding",
                placeholder="Example: A Kubernetes workload runs as root in a privileged container.",
            )
            session_input = gr.Textbox(
                lines=1,
                label="Session ID (optional — for multi-turn context)",
                placeholder="Leave blank for new session",
            )

            with gr.Accordion("Upload scanner export (JSON)", open=False):
                upload_source = gr.Dropdown(
                    choices=["checkov", "trivy", "security_hub"],
                    value="checkov",
                    label="Export source",
                )
                finding_upload = gr.File(
                    file_types=[".json"], type="filepath", label="JSON export (max 1 MB)"
                )
                upload_btn = gr.Button("Analyze uploaded findings")

            with gr.Row():
                submit_btn = gr.Button("Analyze", variant="primary")
                submit_cot_btn = gr.Button("Analyze with Chain-of-Thought")
                clear_btn = gr.Button("Clear Session")

            examples = gr.Examples(
                examples=[[item[0]] for item in TEST_FINDINGS],
                inputs=[finding_input],
                label="Example findings",
            )

        with gr.Column(scale=3):
            output_json = gr.JSON(label="Assessment")

    with gr.Accordion("Observability and Monitoring", open=False):
        with gr.Row():
            metrics_btn = gr.Button("View Metrics")
            health_btn = gr.Button("Health Check")
            reset_btn = gr.Button("Reset Metrics")
        observability_output = gr.JSON(label="Metrics / Health")

    with gr.Accordion("GitHub workflow handoff", open=False):
        gr.Markdown("Creates a draft issue or an advisory PR comment. Set `GITHUB_TOKEN` in the app environment.")
        github_repository = gr.Textbox(
            label="GitHub repository (owner/repository)",
            value=os.getenv("GITHUB_REPOSITORY", ""),
        )
        pull_request_number = gr.Number(label="Pull request number", precision=0)
        with gr.Row():
            draft_issue_btn = gr.Button("Create draft issue from assessment")
            pr_comment_btn = gr.Button("Comment on pull request")
        workflow_output = gr.JSON(label="GitHub handoff result")

    metrics_btn.click(fn=get_observability_metrics, outputs=[observability_output])
    health_btn.click(fn=get_system_health, outputs=[observability_output])
    reset_btn.click(fn=reset_observability_metrics, outputs=[observability_output])
    draft_issue_btn.click(
        fn=create_github_draft_issue,
        inputs=[output_json, github_repository],
        outputs=[workflow_output],
    )
    pr_comment_btn.click(
        fn=comment_on_github_pr,
        inputs=[output_json, github_repository, pull_request_number],
        outputs=[workflow_output],
    )

    submit_btn.click(
        fn=review_finding,
        inputs=[finding_input, session_input],
        outputs=[output_json],
    )
    submit_cot_btn.click(
        fn=review_finding_with_cot,
        inputs=[finding_input, session_input],
        outputs=[output_json],
    )
    upload_btn.click(
        fn=analyze_uploaded_findings,
        inputs=[upload_source, finding_upload, session_input],
        outputs=[output_json],
    )
    clear_btn.click(
        fn=clear_session,
        inputs=[session_input],
        outputs=[output_json],
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860, share=False)
