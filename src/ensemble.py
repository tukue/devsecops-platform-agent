from transformers import pipeline
import logging
import threading
from src.controls import resolve_control

logger = logging.getLogger(__name__)

MODELS = [
    {"name": "facebook/bart-large-mnli", "weight": 0.5},
    {"name": "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7", "weight": 0.3},
    {"name": "cross-encoder/nli-deberta-v3-base", "weight": 0.2},
]

CATEGORY_MAP = {
    "identity and access management": "IAM",
    "network security": "Network",
    "container security": "Container",
    "secrets management": "Secrets",
    "data protection": "Data",
}

CATEGORIES = list(CATEGORY_MAP.keys())

CATEGORY_RULES = [
    ("IAM", [
        "iam role", "wildcard permission", "action: *", "resource: *",
        "mfa", "identity", "rbac", "service account", "cluster-admin",
        "access key", "assume role", "trust policy", "permission boundary",
    ]),
    ("Network", [
        "security group", "0.0.0.0/0", "ingress", "egress", "network policy",
        "cidr", "load balancer", "waf", "dns", "vpc", "subnet",
        "nacl", "port", "firewall",
    ]),
    ("Container", [
        "kubernetes", "container", "image", "runs as root", "privileged",
        "helm", "docker", "pod", "deployment", "workload",
    ]),
    ("Secrets", [
        "secret committed", "private key", "hardcoded password",
        "hardcoded secret", "credential", "api key", "token exposed",
    ]),
    ("Data", [
        "storage bucket", "customer records", "encryption", "unencrypted",
        "backup", "rds", "database", "pii", "phi",
    ]),
]

SEVERITY_RULES = [
    ("critical", [
        "publicly accessible", "0.0.0.0/0", "action: *", "resource: *",
        "admin access", "root user", "secret committed", "private key committed",
        "cluster-admin", "hardcoded password",
    ]),
    ("high", [
        "privileged container", "runs as root", "unencrypted", "no encryption",
        "wildcard permission", "hardcoded secret", "api key committed", "no waf",
    ]),
    ("medium", [
        "no network policy", "missing mfa", "old image", "outdated image",
        "no rotation", "security group allows", "latest tag",
    ]),
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


def determine_category(finding):
    normalized = finding.lower()
    for category, signals in CATEGORY_RULES:
        if any(signal in normalized for signal in signals):
            return category
    return None


def determine_control(finding, category=None):
    """Return a stable control identifier while preserving legacy categories."""
    resolved = resolve_control(finding, category or determine_category(finding))
    return resolved["id"] if resolved else "unclassified"


class EnsembleClassifier:
    def __init__(self, confidence_threshold=0.55):
        self.confidence_threshold = confidence_threshold
        self._models = {}
        self._model_lock = threading.Lock()

    def _get_model(self, model_name):
        if model_name not in self._models:
            with self._model_lock:
                if model_name not in self._models:
                    try:
                        self._models[model_name] = pipeline(
                            "zero-shot-classification",
                            model=model_name,
                        )
                    except Exception as e:
                        logger.warning("Failed to load model %s: %s", model_name, e)
                        return None
        return self._models[model_name]

    def classify_with_model(self, finding, model_name):
        classifier = self._get_model(model_name)
        if classifier is None:
            return None
        try:
            result = classifier(finding, CATEGORIES, multi_label=False)
            label = result["labels"][0]
            score = float(result["scores"][0])
            return {
                "category": CATEGORY_MAP.get(label, "IAM"),
                "raw_label": label,
                "confidence": score,
            }
        except Exception as e:
            logger.warning("Model %s classification failed: %s", model_name, e)
            return None

    def ensemble_classify(self, finding):
        rule_category = determine_category(finding)
        if rule_category:
            return {
                "category": rule_category,
                "confidence": 1.0,
                "method": "rule_match",
                "model_results": [],
            }

        model_results = []
        category_scores = {}
        total_weight = 0

        for model_cfg in MODELS:
            result = self.classify_with_model(finding, model_cfg["name"])
            if result:
                result["model"] = model_cfg["name"]
                result["weight"] = model_cfg["weight"]
                model_results.append(result)

                cat = result["category"]
                weighted_score = result["confidence"] * model_cfg["weight"]
                category_scores[cat] = category_scores.get(cat, 0) + weighted_score
                total_weight += model_cfg["weight"]

        if not model_results:
            return {
                "category": "IAM",
                "confidence": 0.0,
                "method": "fallback",
                "model_results": [],
            }

        best_category = max(category_scores, key=category_scores.get)
        ensemble_confidence = category_scores[best_category] / total_weight if total_weight else 0

        confidence_gap = 0
        sorted_scores = sorted(category_scores.values(), reverse=True)
        if len(sorted_scores) >= 2:
            confidence_gap = sorted_scores[0] - sorted_scores[1]

        return {
            "category": best_category,
            "confidence": round(ensemble_confidence, 3),
            "confidence_gap": round(confidence_gap, 3),
            "method": "ensemble",
            "model_results": model_results,
        }

    def classify(self, finding):
        rule_category = determine_category(finding)
        severity = determine_severity(finding)

        if rule_category:
            control = resolve_control(finding, rule_category)
            return {
                "category": rule_category,
                "control_id": control["id"] if control else "unclassified",
                "owner": control["owner"] if control else OWNERS[rule_category],
                "validation_step": control["validation"] if control else "Review the finding with the owning team.",
                "severity": severity,
                "confidence": 1.0,
                "method": "rule_match",
                "model_results": [],
                "ensemble_agreement": True,
            }

        ensemble = self.ensemble_classify(finding)

        agreement = len(set(r["category"] for r in ensemble["model_results"])) == 1

        control = resolve_control(finding, ensemble["category"])
        return {
            "category": ensemble["category"],
            "control_id": control["id"] if control else "unclassified",
            "owner": control["owner"] if control else OWNERS.get(ensemble["category"], "Platform Security"),
            "validation_step": control["validation"] if control else "Review the finding with the owning team.",
            "severity": severity,
            "confidence": ensemble["confidence"],
            "method": ensemble["method"],
            "model_results": ensemble["model_results"],
            "ensemble_agreement": agreement,
            "confidence_gap": ensemble.get("confidence_gap", 0),
        }
