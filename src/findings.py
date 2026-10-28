"""Canonical finding contract for provider-neutral workflow processing."""

from dataclasses import asdict, dataclass, field
from typing import Any
from src.providers import is_aws_finding

VALID_PROVIDERS = {"aws", "azure", "gcp", "generic"}


@dataclass(frozen=True)
class CanonicalFinding:
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
    resources: list = field(default_factory=list)
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
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["source_references"] = list(self.source_references)
        return result


def infer_provider(finding, provider=None):
    if provider in VALID_PROVIDERS:
        return provider
    return "aws" if is_aws_finding(finding) else "generic"


def canonicalize_finding(finding: str, classification: dict[str, Any], control: dict | None, metadata=None):
    """Create a validated, serializable canonical finding from existing analysis."""
    if not isinstance(finding, str) or not finding.strip():
        raise ValueError("A non-empty finding is required.")
    if not isinstance(classification, dict):
        raise ValueError("Classification must be a dictionary.")

    metadata = metadata or {}
    if not isinstance(metadata, dict):
        raise ValueError("Finding metadata must be a dictionary.")
    provider = infer_provider(finding, metadata.get("provider"))
    evidence = metadata.get("evidence") or (finding.strip(),)
    if isinstance(evidence, str):
        evidence = (evidence,)
    if not isinstance(evidence, (list, tuple)) or not all(isinstance(item, str) for item in evidence):
        raise ValueError("Evidence must be text.")

    return CanonicalFinding(
        provider=provider,
        source_type=str(metadata.get("source_type", "manual")),
        native_finding=finding.strip(),
        category=classification["category"],
        control_id=control["id"] if control else "unclassified",
        severity=classification["severity"],
        owner=control["owner"] if control else "Platform Security",
        confidence=float(classification["confidence"]),
        evidence=tuple(evidence),
        finding_id=metadata.get("finding_id"),
        product_arn=metadata.get("product_arn"),
        native_severity=metadata.get("native_severity", {}),
        workflow_status=metadata.get("workflow_status"),
        compliance_status=metadata.get("compliance_status"),
        record_state=metadata.get("record_state"),
        resources=metadata.get("resources", []),
        source_timestamps=metadata.get("source_timestamps", {}),
        account=metadata.get("account"),
        region=metadata.get("region"),
        environment=metadata.get("environment"),
        scanner=metadata.get("scanner"),
        rule_id=metadata.get("rule_id"),
        resource_type=metadata.get("resource_type"),
        resource_id=metadata.get("resource_id"),
        source_references=tuple(metadata.get("source_references", ())),
    )
