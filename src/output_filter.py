import re

SENSITIVE_DATA_PATTERNS = [
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b"),
    ("ssn", r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    ("phone", r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    ("aws_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("private_key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ("api_key", r"\b(?:sk|pk|api)[_-]?[a-zA-Z0-9]{20,}\b"),
    ("password", r"(?:password|passwd|pwd)\s*[:=]\s*\S+"),
]

BLOCKED_ADVICE_PATTERNS = [
    r"run\s+(?:as\s+)?root",
    r"disable\s+(?:all\s+|the\s+)?(?:firewall|security|logging|encryption)",
    r"open\s+(?:all|every)\s+(?:port|access)",
    r"allow\s+(?:all|every|any)\s+(?:traffic|access|connection)",
    r"share\s+(?:your|the)\s+(?:password|secret|key|credential)",
    r"commit\s+(?:the\s+)?(?:secret|password|key|credential)",
    r"skip\s+(?:all\s+)?(?:security|validation|scan|check)",
    r"remove\s+(?:all\s+)?(?:encryption|authentication|access\s+control)",
    r"expose\s+(?:the\s+)?(?:secret|password|key|credential|token)",
    r"store\s+(?:secrets?\s+)?(?:in|on)\s+(?:git|github|plaintext|text\s+file)",
]

SAFE_OUTPUT_INDICATORS = [
    "remediation", "recommend", "review", "audit", "least privilege",
    "restrict", "rotate", "encrypt", "monitor", "scan", "validate",
    "enforce", "apply", "configure", "enable", "update", "patch",
]

HALLUCINATION_INDICATORS = [
    "definitely will fix",
    "guaranteed to prevent",
    "100% secure",
    "no risk",
    "always safe",
    "never fails",
    "completely eliminates",
]

UNPROFESSIONAL_PATTERNS = [
    r"\b(dumb|stupid|idiot|moron|suck|sucks)\b",
    r"(lmao|rofl|lol|omg|wtf)",
]


def _mask_sensitive(text):
    masked = text
    for pii_type, pattern in SENSITIVE_DATA_PATTERNS:
        masked = re.sub(pattern, f"[REDACTED:{pii_type.upper()}]", masked, flags=re.IGNORECASE)
    return masked


def _check_blocked_advice(text):
    violations = []
    for pattern in BLOCKED_ADVICE_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            violations.append(match.group())
    return violations


def _check_hallucination_risk(text):
    risks = []
    for indicator in HALLUCINATION_INDICATORS:
        if indicator.lower() in text.lower():
            risks.append(indicator)
    return risks


def _is_professional_tone(text):
    for pattern in UNPROFESSIONAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return False
    return True


def _check_prompt_leakage(text):
    leakage_indicators = [
        r"system\s*prompt",
        r"my\s+instructions\s+are",
        r"i\s+was\s+told\s+to",
        r"my\s+rules\s+are",
        r"i\s+must\s+not",
        r"i\s+cannot\s+reveal",
        r"as\s+an?\s+ai\s+language\s+model",
    ]
    for pattern in leakage_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _validate_remediation_quality(response, category):
    required_sections = {
        "IAM": ["least privilege", "permission", "review"],
        "Network": ["restrict", "ingress", "segment"],
        "Container": ["image", "non-root", "scan"],
        "Secrets": ["revoke", "rotate", "secret"],
        "Data": ["encrypt", "access", "audit"],
    }

    required = required_sections.get(category, [])
    found = sum(1 for kw in required if kw.lower() in response.lower())
    return found >= 1


def filter_output(response, finding="", category=""):
    issues = []
    filtered = response

    filtered = _mask_sensitive(filtered)

    violations = _check_blocked_advice(filtered)
    if violations:
        issues.append(f"Blocked unsafe advice: {', '.join(violations)}")
        for v in violations:
            filtered = filtered.replace(v, "[REDACTED]")

    hallucination_risks = _check_hallucination_risk(filtered)
    if hallucination_risks:
        issues.append(f"Hallucination risk: {', '.join(hallucination_risks)}")

    if not _is_professional_tone(filtered):
        issues.append("Non-professional tone detected")

    if _check_prompt_leakage(filtered):
        issues.append("Response may contain prompt leakage")

    if category and not _validate_remediation_quality(filtered, category):
        issues.append(f"Remediation may be incomplete for {category} category")

    return {
        "filtered_text": filtered,
        "issues": issues,
        "safe": len(issues) == 0,
    }
