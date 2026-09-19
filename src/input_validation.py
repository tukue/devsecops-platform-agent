import re
import hashlib
import time
from collections import defaultdict

MAX_INPUT_LENGTH = 2000
MIN_INPUT_LENGTH = 10
MAX_REQUESTS_PER_MINUTE = 30

_request_log = defaultdict(list)

# ──────────────────────────────────────────────
# Layer 1: Prompt Injection Detection
# ──────────────────────────────────────────────

DIRECT_COMMAND_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?prior",
    r"forget\s+everything",
    r"override\s+instructions",
    r"bypass\s+(all\s+)?safety",
    r"do\s+not\s+follow\s+(your|the)\s+rules",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*",
    r"dev\s*mode",
    r"debug\s*mode",
    r"admin\s*mode",
]

ROLE_HIJACK_PATTERNS = [
    r"you\s+are\s+now\s+",
    r"act\s+as\s+if\s+you\s+are",
    r"pretend\s+you\s+are",
    r"your\s+new\s+role",
    r"from\s+now\s+on\s+you\s+are",
    r"switch\s+to\s+",
    r"enter\s+(?:developer|admin|debug|god)\s+mode",
    r"enable\s+(?:developer|admin|debug|god)\s+mode",
]

EXFILTRATION_PATTERNS = [
    r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
    r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
    r"repeat\s+(your|the)\s+(system\s+)?prompt",
    r"print\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"output\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"dump\s+(your|the)\s+(system\s+)?(prompt|instructions)",
]

ENCODING_EVASION_PATTERNS = [
    r"base64\s*[:=]",
    r"rot13",
    r"hex\s*[:=]",
    r"url\s*encode",
    r"unicode\s*escape",
    r"html\s*entity",
]

MULTILINGUAL_INJECTION = [
    r"ignora\s+(las\s+)?instrucciones",
    r"ignorer\s+(les\s+)?instructions",
    r"ignoriere\s+(die\s+)?Anweisungen",
    r"前の指示を無視",
    r"무시하\s+이전\s+지시",
]

INSTRUCTION_SEPARATOR_PATTERNS = [
    r"\n\s*---\s*\n",
    r"\n\s*===\s*\n",
    r"\n\s*\*\*\*\s*\n",
    r"---END\s+OF\s+(SYSTEM\s+)?PROMPT---",
    r"<\|im_end\|>",
    r"<\|endoftext\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
]

ALL_INJECTION_PATTERNS = (
    DIRECT_COMMAND_PATTERNS
    + ROLE_HIJACK_PATTERNS
    + EXFILTRATION_PATTERNS
    + ENCODING_EVASION_PATTERNS
    + MULTILINGUAL_INJECTION
    + INSTRUCTION_SEPARATOR_PATTERNS
)

# ──────────────────────────────────────────────
# Layer 2: Sensitive Data Detection
# ──────────────────────────────────────────────

SENSITIVE_DATA_PATTERNS = [
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b"),
    ("ssn", r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    ("phone", r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    ("ip_private", r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    ("aws_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("private_key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ("api_token", r"\b(?:ghp|gho|ghu|ghs|ghr|sk-|pk-)[a-zA-Z0-9]{20,}\b"),
]

# ──────────────────────────────────────────────
# Layer 3: Content Validation
# ──────────────────────────────────────────────

OFF_TOPIC_PATTERNS = [
    r"^\s*(hi|hello|hey|thanks|thank you|bye|goodbye)\s*[!.]?\s*$",
    r"^(what|how|tell me)\s+(is|are)\s+(the\s+)?(weather|time|date|day)",
    r"^(write|create|generate)\s+(a\s+)?(poem|story|song|joke)",
    r"^what\s+(is|are)\s+your\s+(name|purpose)",
]

SECURITY_KEYWORDS = [
    "security", "vulnerability", "threat", "risk", "incident", "breach",
    "exposure", "misconfiguration", "attack", "exploit", "remediation",
    "firewall", "encryption", "authentication", "authorization", "access",
    "permission", "credential", "secret", "key", "certificate", "token",
    "iam", "rbac", "network", "container", "kubernetes", "docker",
    "aws", "azure", "gcp", "cloud", "s3", "rds", "ec2", "lambda",
    "ingress", "egress", "security group", "nacl", "waf",
    "patch", "update", "upgrade", "scan", "audit", "compliance",
    "hardening", "least privilege", "segmentation", "isolation",
    "backup", "recovery", "drift", "configuration",
]


def _rate_limit(client_id="default"):
    now = time.time()
    window = 60
    _request_log[client_id] = [
        t for t in _request_log[client_id] if now - t < window
    ]
    if len(_request_log[client_id]) >= MAX_REQUESTS_PER_MINUTE:
        return False
    _request_log[client_id].append(now)
    return True


def _detect_injection_layers(finding):
    layers_triggered = []
    normalized = finding.strip()

    encoded = hashlib.sha256(normalized.encode()).hexdigest()

    for pattern in ALL_INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            layers_triggered.append("pattern_match")
            break

    suspicious_chars = sum(1 for c in normalized if c in "<>{}[]|\\^~`")
    if suspicious_chars > len(normalized) * 0.1:
        layers_triggered.append("suspicious_chars")

    if normalized.count("\n") > 10:
        layers_triggered.append("excessive_newlines")

    repeated = re.search(r"(.)\1{10,}", normalized)
    if repeated:
        layers_triggered.append("repeated_chars")

    if len(set(normalized.split())) < 3 and len(normalized) > 50:
        layers_triggered.append("low_entropy")

    for pattern in INSTRUCTION_SEPARATOR_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            layers_triggered.append("separator_injection")
            break

    return layers_triggered


def _detect_pii(finding):
    detected = []
    for pii_type, pattern in SENSITIVE_DATA_PATTERNS:
        if re.search(pattern, finding):
            detected.append(pii_type)
    return detected


def validate_input(finding, client_id="default"):
    errors = []
    warnings = []

    if not finding or not finding.strip():
        return False, ["Input cannot be empty."], []

    finding = finding.strip()

    if not _rate_limit(client_id):
        return False, ["Rate limit exceeded. Please wait before submitting again."], []

    if len(finding) < MIN_INPUT_LENGTH:
        errors.append(f"Input too short. Minimum {MIN_INPUT_LENGTH} characters required.")
    if len(finding) > MAX_INPUT_LENGTH:
        errors.append(f"Input too long. Maximum {MAX_INPUT_LENGTH} characters allowed.")

    injection_layers = _detect_injection_layers(finding)
    if injection_layers:
        errors.append(
            f"Input contains potentially unsafe content "
            f"(detected: {', '.join(injection_layers)}). "
            f"Please submit a security finding only."
        )

    pii_detected = _detect_pii(finding)
    if pii_detected:
        errors.append(
            f"Input contains sensitive data ({', '.join(pii_detected)}). "
            f"Please remove personal information before submitting."
        )

    for pattern in OFF_TOPIC_PATTERNS:
        if re.search(pattern, finding, re.IGNORECASE):
            errors.append("Please submit a security finding, not a general question.")
            break

    has_security_keyword = any(
        kw in finding.lower() for kw in SECURITY_KEYWORDS
    )
    if not has_security_keyword and len(finding) > 20 and not injection_layers:
        warnings.append(
            "Input may not be a security finding. "
            "Results are optimized for infrastructure security issues."
        )

    if errors:
        return False, errors, warnings
    return True, [], warnings
