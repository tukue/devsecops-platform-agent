import spaces
import gradio as gr
from transformers import pipeline

# Re-define all necessary functions and variables
MODEL_NAME = "facebook/bart-large-mnli"
CATEGORIES = ["identity and access management", "network security", "container security", "secrets management", "data protection"]
CATEGORY_NAMES = {
    "identity and access management": "IAM",
    "network security": "Network",
    "container security": "Container",
    "secrets management": "Secrets",
    "data protection": "Data",
}

SEVERITY_RULES = [
    ("critical", ["publicly accessible", "0.0.0.0/0", "action: *", "resource: *", "admin access", "root user", "secret committed", "private key committed"]),
    ("high", ["privileged container", "runs as root", "unencrypted", "no encryption", "wildcard permission", "hardcoded password", "hardcoded secret"]),
    ("medium", ["no network policy", "missing mfa", "old image", "outdated image", "no rotation", "security group allows"]),
]

REMEDIATIONS = {
    "IAM": "Apply least privilege, remove wildcard permissions, require MFA for privileged identities, and review access through policy analysis.",
    "Network": "Restrict ingress and egress to required ports and trusted CIDRs; add segmentation and Kubernetes NetworkPolicies where applicable.",
    "Container": "Use a minimal patched image, run as a non-root user, drop Linux capabilities, enable a read-only filesystem, and scan the image in CI.",
    "Secrets": "Revoke and rotate the exposed value, remove it from source history, use a managed secret store, and add secret scanning to CI.",
    "Data": "Enable encryption at rest and in transit, restrict data access, enable audit logging, and verify backup protection.",
}

OWNERS = {
    "IAM": "Platform Security",
    "Network": "Cloud Platform",
    "Container": "Container Platform",
    "Secrets": "Platform Security",
    "Data": "Data Platform",
}

def determine_severity(finding):
    normalized = finding.lower()
    for severity, signals in SEVERITY_RULES:
        if any(signal in normalized for signal in signals):
            return severity
    return "low"

def analyze_finding(finding, confidence_threshold=0.60):
    if not finding or not finding.strip():
        raise ValueError("A security finding is required.")

    classifier = pipeline("zero-shot-classification", model=MODEL_NAME) # Classifier needs to be initialized here or passed in
    prediction = classifier(finding, CATEGORIES, multi_label=False)
    category = CATEGORY_NAMES[prediction["labels"][0]]
    confidence = float(prediction["scores"][0])
    severity = determine_severity(finding)

    return {
        "category": category,
        "severity": severity,
        "confidence": round(confidence, 3),
        "recommendation": REMEDIATIONS[category],
        "owner": OWNERS[category],
        "human_review_required": confidence < confidence_threshold or severity in {"high", "critical"},
        "automation_allowed": False,
    }

@spaces.GPU
def review_finding(finding):
    try:
        return analyze_finding(finding)
    except ValueError as error:
        return {"error": str(error)}

# Note: TEST_FINDINGS are typically for evaluation, not part of the deployed app
# However, if you want to use them for examples in the Gradio interface:
TEST_FINDINGS = [
    ("An IAM role grants wildcard permissions to all AWS resources.", "IAM"),
    ("The production security group allows SSH from 0.0.0.0/0.", "Network"),
    ("The Kubernetes workload runs as root in a privileged container.", "Container"),
    ("A database password is hardcoded in the Git repository.", "Secrets"),
    ("The storage bucket contains customer records with no encryption.", "Data"),
]

demo = gr.Interface(
    fn=review_finding,
    inputs=gr.Textbox(
        lines=5,
        label="Infrastructure security finding",
        placeholder="Example: A Kubernetes workload runs as root in a privileged container.",
    ),
    outputs=gr.JSON(label="DevSecOps assessment"),
    title="AI DevSecOps Advisor",
    description="Classifies infrastructure risks and recommends human-reviewed remediation. No infrastructure changes are executed.",
    examples=[[item[0]] for item in TEST_FINDINGS],
)

# Start the web server and keep the Space running.
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
