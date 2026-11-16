import re
import hashlib
import time
import threading
import unicodedata
from collections import defaultdict

MAX_INPUT_LENGTH = 2000
MIN_INPUT_LENGTH = 10
MAX_REQUESTS_PER_MINUTE = 30

_request_log = defaultdict(list)
_rate_limit_lock = threading.Lock()

# ──────────────────────────────────────────────
# Layer 0: Adversarial Encoding Normalization
# Strips characters attackers use to evade the regex layers below while
# leaving ordinary findings byte-identical after normalization.
# ──────────────────────────────────────────────

_INVISIBLE_CHARS = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e"
    "\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff]"
)

# Confusables that survive NFKC: Cyrillic/Greek lookalikes and a few legacy
# forms used to spell attack keywords ("іgnore", "іnstructiоns", "sуstem:").
_HOMOGLYPH_FOLD = str.maketrans({
    "\u0430": "a", "\u0410": "a",
    "\u0432": "b", "\u0412": "b",
    "\u0441": "c", "\u0421": "c",
    "\u0435": "e", "\u0415": "e",
    "\u0456": "i", "\u0406": "i",
    "\u0458": "j", "\u0408": "j",
    "\u043a": "k", "\u041a": "k",
    "\u043c": "m", "\u041c": "m",
    "\u043d": "h", "\u041d": "h",
    "\u043e": "o", "\u041e": "o",
    "\u0440": "p", "\u0420": "p",
    "\u0442": "t", "\u0422": "t",
    "\u0443": "y", "\u0423": "y",
    "\u0445": "x", "\u0425": "x",
    "\u03b1": "a", "\u0391": "a",
    "\u03bf": "o", "\u039f": "o",
    "\u03c1": "p", "\u03a1": "p",
    "\u03c4": "t", "\u03a4": "t",
    "\u03ba": "k", "\u039a": "k",
    "\u03c7": "x", "\u03a7": "x",
    "\u03b9": "i", "\u0399": "i",
    "\u03bd": "v", "\u039d": "v",
    "\u03c5": "u", "\u03a5": "u",
    "\u0131": "i",
    "\u017f": "s",
})


def contains_evasion_chars(text):
    """True when the text hides data in zero-width, bidi, or soft-hyphen chars."""
    if not text:
        return False
    return bool(_INVISIBLE_CHARS.search(unicodedata.normalize("NFKC", text)))


def normalize_for_detection(text):
    """Fold adversarial encodings so detection layers see the real payload.

    NFKC collapses fullwidth forms (ｓｙｓｔｅｍ: -> system:), invisible
    characters are removed, homoglyphs are folded to ASCII, and combining
    marks are stripped so "ïgnore" matches "ignore". Returns "" for
    non-string input.
    """
    if not isinstance(text, str):
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _INVISIBLE_CHARS.sub("", normalized)
    normalized = normalized.translate(_HOMOGLYPH_FOLD)
    decomposed = unicodedata.normalize("NFKD", normalized)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))

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
    with _rate_limit_lock:
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


def validate_input(finding, client_id="default", enforce_rate_limit=True):
    errors = []
    warnings = []

    if not finding or not finding.strip():
        return False, ["A security finding is required."], []

    finding = finding.strip()

    if enforce_rate_limit and not _rate_limit(client_id):
        return False, ["Rate limit exceeded. Please wait before submitting again."], []

    # Detect against the normalized form so encoded evasions cannot bypass
    # the regex layers. Length floors also use the normalized form so
    # invisible-character padding cannot fake a valid finding.
    probe = normalize_for_detection(finding)

    if len(probe) < MIN_INPUT_LENGTH:
        errors.append(f"Input too short. Minimum {MIN_INPUT_LENGTH} characters required.")
    if len(finding) > MAX_INPUT_LENGTH:
        errors.append(f"Input too long. Maximum {MAX_INPUT_LENGTH} characters allowed.")

    injection_layers = _detect_injection_layers(probe)
    if contains_evasion_chars(finding):
        injection_layers.append("unicode_evasion")
    if injection_layers:
        errors.append(
            f"Input contains potentially unsafe content "
            f"(detected: {', '.join(injection_layers)}). "
            f"Please submit a security finding only."
        )

    pii_detected = _detect_pii(probe)
    if pii_detected:
        errors.append(
            f"Input contains sensitive data ({', '.join(pii_detected)}). "
            f"Please remove personal information before submitting."
        )

    for pattern in OFF_TOPIC_PATTERNS:
        if re.search(pattern, probe, re.IGNORECASE):
            errors.append("Please submit a security finding, not a general question.")
            break

    has_security_keyword = any(
        kw in probe.lower() for kw in SECURITY_KEYWORDS
    )
    if not has_security_keyword and len(finding) > 20 and not injection_layers:
        warnings.append(
            "Input may not be a security finding. "
            "Results are optimized for infrastructure security issues."
        )

    if errors:
        return False, errors, warnings
    return True, [], warnings
