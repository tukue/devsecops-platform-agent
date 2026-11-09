"""Versioned, provider-neutral contract for workflow findings."""

from dataclasses import asdict, dataclass, field
import json
import math
import re
from typing import Any

from src.input_validation import SENSITIVE_DATA_PATTERNS
from src.providers import is_aws_finding

CANONICAL_FINDING_SCHEMA_VERSION = "1.0"
VALID_PROVIDERS = {"aws", "azure", "gcp", "generic"}
VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
REQUIRED_CLASSIFICATION_FIELDS = {"category", "severity", "confidence"}
TEXT_METADATA_FIELDS = {
    "finding_id", "product_arn", "workflow_status", "compliance_status",
    "record_state", "account", "region", "environment", "scanner", "rule_id",
    "resource_type", "resource_id",
}


@dataclass(frozen=True)
class CanonicalFinding:
    schema_version: str
    provider: str
    source_type: str
    native_finding: str
    category: str
    control_id: str
    severity: str
    owner: str
    confidence: float
    evidence: tuple[str, ...] = field(default_factory=tuple)
    finding_id: str | None = None
    product_arn: str | None = None
    native_severity: dict = field(default_factory=dict)
    workflow_status: str | None = None
    compliance_status: str | None = None
    record_state: str | None = None
    resources: tuple[dict, ...] = field(default_factory=tuple)
    source_timestamps: dict = field(default_factory=dict)
    account: str | None = None
    region: str | None = None
    environment: str | None = None
    scanner: str | None = None
    rule_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    source_references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self):
        """Return a JSON-compatible representation of this contract version."""
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["resources"] = list(self.resources)
        result["source_references"] = list(self.source_references)
        return result


def _redact(text: str) -> str:
    for label, pattern in SENSITIVE_DATA_PATTERNS:
        text = re.sub(pattern, f"[REDACTED:{label.upper()}]", text, flags=re.IGNORECASE)
    return text


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text.")
    return _redact(value.strip())


def _optional_text(value: Any, name: str) -> str | None:
    return None if value is None else _required_text(value, name)


def _text_sequence(value: Any, name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a sequence of text values.")
    return tuple(_redact(item.strip()) for item in value if item.strip())


def _safe_mapping(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a dictionary.")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be text.")
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain JSON-compatible values.") from exc
    return _redact_json(value)


def _redact_json(value: Any) -> Any:
    """Preserve JSON structure while applying the contract's text redaction."""
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json(item) for key, item in value.items()}
    return value


def _resources(value: Any) -> tuple[dict, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("resources must be a sequence of dictionaries.")
    return tuple(_safe_mapping(item, "resource") for item in value)


def infer_provider(finding, provider=None):
    if provider in VALID_PROVIDERS:
        return provider
    return "aws" if is_aws_finding(finding) else "generic"


def canonicalize_finding(finding: str, classification: dict[str, Any], control: dict | None, metadata=None):
    """Create a validated, redacted, safely serializable canonical finding.

    Scanner imports may bypass the UI. Text is redacted at this boundary while
    malformed contract data fails closed with ``ValueError``.
    """
    finding = _required_text(finding, "finding")
    if not isinstance(classification, dict):
        raise ValueError("Classification must be a dictionary.")
    missing = REQUIRED_CLASSIFICATION_FIELDS.difference(classification)
    if missing:
        raise ValueError("Classification is missing: %s." % ", ".join(sorted(missing)))
    category = _required_text(classification["category"], "category")
    severity = _required_text(classification["severity"], "severity").lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError("severity must be one of: %s." % ", ".join(sorted(VALID_SEVERITIES)))
    confidence = classification["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("confidence must be a finite number between 0 and 1.")

    metadata = metadata or {}
    if not isinstance(metadata, dict):
        raise ValueError("Finding metadata must be a dictionary.")
    provider = infer_provider(finding, metadata.get("provider"))
    source_type = _required_text(metadata.get("source_type", "manual"), "source_type")
    evidence = _text_sequence(metadata.get("evidence", (finding,)), "evidence") or (finding,)
    references = _text_sequence(metadata.get("source_references", ()), "source_references")
    validated_text_fields = {
        name: _optional_text(metadata.get(name), name)
        for name in TEXT_METADATA_FIELDS
    }
    native_severity = _safe_mapping(metadata.get("native_severity", {}), "native_severity")
    timestamps = _safe_mapping(metadata.get("source_timestamps", {}), "source_timestamps")
    resources = _resources(metadata.get("resources", []))
    if control is not None and not isinstance(control, dict):
        raise ValueError("control must be a dictionary when provided.")
    control_id = _required_text(control.get("id"), "control_id") if control else "unclassified"
    owner = _required_text(control.get("owner"), "owner") if control else "Platform Security"

    return CanonicalFinding(
        schema_version=CANONICAL_FINDING_SCHEMA_VERSION, provider=provider,
        source_type=source_type, native_finding=finding, category=category,
        control_id=control_id, severity=severity, owner=owner,
        confidence=float(confidence), evidence=evidence,
        native_severity=native_severity, resources=resources,
        source_timestamps=timestamps, source_references=references,
        **validated_text_fields,
    )
