import spaces
import gradio as gr
from src.retriever import SecurityRetriever
from src.ensemble import EnsembleClassifier, REMEDIATIONS, OWNERS, determine_severity
from src.memory import ConversationMemory
from src.chain_of_thought import generate_chain_of_thought
from src.input_validation import validate_input
from src.output_filter import filter_output

retriever = SecurityRetriever(top_k=5)
classifier = EnsembleClassifier(confidence_threshold=0.55)
memory = ConversationMemory(max_sessions=10)

SESSION_COUNTER = 0


def analyze_finding(finding, session_id=None):
    global SESSION_COUNTER

    valid, errors, warnings = validate_input(finding)
    if not valid:
        return {"error": errors[0], "validation_errors": errors}

    if session_id is None:
        SESSION_COUNTER += 1
        session_id = f"session_{SESSION_COUNTER}"

    classification = classifier.classify(finding)

    rag_context, rag_sources = retriever.build_context(finding, top_k=5)

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

    if rag_context:
        recommendation += f"\n\nKnowledge base guidance:\n{rag_context}"

    if memory_context:
        recommendation += f"\n\nSession context:\n{memory_context}"

    filtered = filter_output(
        recommendation,
        finding=finding,
        category=classification.get("category", ""),
    )
    if not filtered["safe"]:
        recommendation = filtered["filtered_text"]

    result = {
        "category": classification["category"],
        "severity": classification["severity"],
        "confidence": classification["confidence"],
        "method": classification.get("method", "unknown"),
        "ensemble_agreement": classification.get("ensemble_agreement", True),
        "recommendation": recommendation,
        "owner": OWNERS.get(classification["category"], "Platform Security"),
        "human_review_required": classification["severity"] in {"high", "critical"} or classification["confidence"] < 0.60,
        "automation_allowed": False,
        "rag_sources": rag_sources,
        "session_id": session_id,
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


@spaces.GPU
def review_finding(finding, session_id=None):
    try:
        return analyze_finding(finding, session_id)
    except Exception as e:
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
        return {"error": str(e)}


def clear_session(session_id):
    memory.clear_session(session_id)
    return {"status": f"Session {session_id} cleared."}


TEST_FINDINGS = [
    ("An IAM role grants wildcard permissions to all AWS resources.", "IAM"),
    ("The production security group allows SSH from 0.0.0.0/0.", "Network"),
    ("The Kubernetes workload runs as root in a privileged container.", "Container"),
    ("A database password is hardcoded in the Git repository.", "Secrets"),
    ("The storage bucket contains customer records with no encryption.", "Data"),
]

with gr.Blocks(title="AI DevSecOps Advisor") as demo:
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
    clear_btn.click(
        fn=clear_session,
        inputs=[session_input],
        outputs=[output_json],
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
