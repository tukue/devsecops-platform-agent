def generate_chain_of_thought(finding, classification, rag_context, memory_context=""):
    steps = []

    steps.append({
        "step": 1,
        "name": "Input Analysis",
        "description": f"Received security finding: \"{finding[:100]}{'...' if len(finding) > 100 else ''}\"",
    })

    method = classification.get("method", "unknown")
    category = classification.get("category", "Unknown")
    confidence = classification.get("confidence", 0)

    if method == "rule_match":
        steps.append({
            "step": 2,
            "name": "Classification",
            "description": (
                f"Rule-based match identified this as a **{category}** issue. "
                f"Confidence: {confidence:.0%} (exact pattern match)."
            ),
        })
    elif method == "ensemble":
        model_results = classification.get("model_results", [])
        agreement = classification.get("ensemble_agreement", False)

        model_summary = ", ".join(
            f"{r['model'].split('/')[-1]}: {r['category']} ({r['confidence']:.0%})"
            for r in model_results
        )

        if agreement:
            desc = (
                f"All {len(model_results)} models agree on **{category}** "
                f"(ensemble confidence: {confidence:.0%}). Models: {model_summary}"
            )
        else:
            desc = (
                f"Ensemble classified as **{category}** "
                f"(confidence: {confidence:.0%}). Model results: {model_summary}. "
                f"Models did not fully agree — human review recommended."
            )

        steps.append({
            "step": 2,
            "name": "Classification",
            "description": desc,
        })
    else:
        steps.append({
            "step": 2,
            "name": "Classification",
            "description": f"Classified as **{category}** via {method} (confidence: {confidence:.0%}).",
        })

    severity = classification.get("severity", "unknown")
    severity_reasons = _explain_severity(finding, severity)
    steps.append({
        "step": 3,
        "name": "Severity Assessment",
        "description": (
            f"Severity: **{severity.upper()}**. "
            f"Reasons: {severity_reasons}"
        ),
    })

    if rag_context:
        kb_entries = rag_context.count("[")
        steps.append({
            "step": 4,
            "name": "Knowledge Retrieval",
            "description": (
                f"Retrieved {kb_entries} relevant entries from the security knowledge base "
                f"to inform remediation guidance."
            ),
        })

    if memory_context:
        steps.append({
            "step": 5,
            "name": "Session Context",
            "description": (
                "Incorporated previous findings from this session to provide "
                "consistent and context-aware guidance."
            ),
        })

    human_review = classification.get("human_review_required", True)
    if human_review:
        review_reasons = []
        if severity in ("critical", "high"):
            review_reasons.append(f"{severity} severity finding")
        if confidence < 0.60:
            review_reasons.append(f"low model confidence ({confidence:.0%})")
        if not classification.get("ensemble_agreement", True):
            review_reasons.append("models disagree on classification")

        steps.append({
            "step": len(steps) + 1,
            "name": "Human Review",
            "description": (
                f"Human review required: {'; '.join(review_reasons)}. "
                f"Recommended owner: {classification.get('owner', 'Platform Security')}."
            ),
        })

    return steps


def _explain_severity(finding, severity):
    finding_lower = finding.lower()
    reasons = []

    if severity == "critical":
        if any(w in finding_lower for w in ["0.0.0.0/0", "publicly", "public"]):
            reasons.append("public exposure")
        if any(w in finding_lower for w in ["admin", "root", "cluster-admin"]):
            reasons.append("admin/root access")
        if any(w in finding_lower for w in ["secret committed", "password", "private key"]):
            reasons.append("committed secret")
        if any(w in finding_lower for w in ["wildcard", "action: *"]):
            reasons.append("unrestricted permissions")

    elif severity == "high":
        if any(w in finding_lower for w in ["privileged", "root"]):
            reasons.append("privileged workload")
        if any(w in finding_lower for w in ["unencrypted", "no encryption"]):
            reasons.append("missing encryption")
        if any(w in finding_lower for w in ["wildcard", "hardcoded"]):
            reasons.append("excessive permissions or exposed credentials")

    elif severity == "medium":
        if any(w in finding_lower for w in ["no network policy", "missing mfa"]):
            reasons.append("missing security control")
        if any(w in finding_lower for w in ["old image", "latest tag"]):
            reasons.append("outdated configuration")

    if not reasons:
        reasons.append("standard security review")

    return "; ".join(reasons)
