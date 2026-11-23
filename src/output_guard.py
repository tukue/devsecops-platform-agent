"""Fail-closed postcondition guard for the full assessment payload.

``filter_output`` only inspects the rendered recommendation string. Evidence,
risk summaries, chain-of-thought text, session context, and the canonical
finding echo all bypass it. This module re-applies the output boundary to
*every* string in the payload so no field can leak data or unsafe guidance.

Policy:
- secrets/PII: masked in every field (the value never leaves the process).
- unsafe advice spans: replaced in every field.
- prompt leakage: the whole field is replaced with a refusal message and the
  payload is reported as blocked. Fields that merely echo untrusted user
  input are exempt from the leakage block -- echoing the user's own words is
  not an instruction leak -- but are still scrubbed for secrets and advice.
"""

import re

from src.output_filter import (
    BLOCKED_ADVICE_PATTERNS,
    PROMPT_LEAKAGE_PATTERNS,
    SENSITIVE_DATA_PATTERNS,
    _check_blocked_advice,
    _mask_sensitive,
)

REDACTED = "[REDACTED]"

REFUSAL_MESSAGE = (
    "Assessment withheld: the response contained restricted content. "
    "Remove secrets and personal data from the finding and resubmit."
)

UNTRUSTED_ECHO_KEYS = {
    "finding",
}

# Diagnostics and control flags are produced by this process, not generated
# text: they quote blocked spans on purpose ("Blocked unsafe advice: ..."),
# so scrubbing them would corrupt the signal. They never carry raw secrets --
# the filter masks secrets before a diagnostic is ever written.
SKIP_KEYS = {
    "error",
    "input_warnings",
    "output_warnings",
    "assessment_errors",
    "output_blocked",
    "output_guard_violations",
    # Server-generated control fields. Their digit runs (timestamps in
    # trace ids, hex segments in session ids) trip the loose PII patterns.
    "trace_id",
    "session_id",
}


def find_sensitive_data(text):
    """Return the sensitive-data categories present in ``text``."""
    return [
        name
        for name, pattern in SENSITIVE_DATA_PATTERNS
        if re.search(pattern, text, re.IGNORECASE)
    ]


def find_blocked_advice(text):
    """Return the unsafe-advice spans present in ``text``."""
    return [
        match
        for pattern in BLOCKED_ADVICE_PATTERNS
        for match in re.findall(pattern, text, flags=re.IGNORECASE)
    ]


def _scrub(text, allow_leakage_block):
    types = []

    scrubbed = _mask_sensitive(text)
    if scrubbed != text:
        types.append("sensitive_data")

    advice = _check_blocked_advice(scrubbed)
    if advice:
        types.append("unsafe_advice")
        for span in advice:
            scrubbed = scrubbed.replace(span, REDACTED)

    if allow_leakage_block:
        for pattern in PROMPT_LEAKAGE_PATTERNS:
            if re.search(pattern, scrubbed, re.IGNORECASE):
                types.append("prompt_leakage")
                return REFUSAL_MESSAGE, types, True

    return scrubbed, types, False


def _scrub_value(value, path, untrusted, violations, state):
    if isinstance(value, str):
        scrubbed, types, blocked = _scrub(value, allow_leakage_block=not untrusted)
        if types:
            violations[path] = sorted(set(types))
            if blocked:
                state["blocked"] = True
        return scrubbed

    if isinstance(value, dict):
        for key in list(value):
            if key in SKIP_KEYS:
                continue
            child_path = f"{path}.{key}" if path else str(key)
            child_untrusted = untrusted or key in UNTRUSTED_ECHO_KEYS
            value[key] = _scrub_value(
                value[key], child_path, child_untrusted, violations, state
            )
        return value

    if isinstance(value, (list, tuple)):
        scrubbed_items = [
            _scrub_value(item, f"{path}[{index}]", untrusted, violations, state)
            for index, item in enumerate(value)
        ]
        return type(value)(scrubbed_items)

    return value


def guard_result(payload):
    """Scrub ``payload`` in place and return the guard report.

    Returns ``{"safe", "blocked", "violations"}`` where ``violations`` maps
    each offending payload path to the violation types found there.
    """
    violations = {}
    state = {"blocked": False}
    guarded = _scrub_value(payload, "", False, violations, state)
    return {
        "safe": not violations,
        "blocked": state["blocked"],
        "violations": violations,
        "payload": guarded,
    }
