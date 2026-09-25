"""Read-only adapters for scanner findings and cloud security-service exports."""

import json
import os

MAX_UPLOAD_BYTES = 1_000_000


class FindingIngestionError(ValueError):
    pass


def _text(*values):
    return " ".join(str(value) for value in values if value).strip()


def _checkov(payload):
    checks = payload.get("results", {}).get("failed_checks", [])
    records = []
    for check in checks:
        finding = _text(check.get("check_name"), check.get("resource"), check.get("guideline"))
        if not finding:
            continue
        resource = str(check.get("resource", ""))
        records.append((finding, {
            "provider": "aws" if resource.lower().startswith("aws_") else "generic",
            "source_type": "scanner",
            "scanner": "Checkov",
            "rule_id": check.get("check_id"),
            "resource_type": check.get("check_type"),
            "resource_id": resource,
            "source_references": [check.get("file_path", "")],
            "evidence": [finding],
        }))
    return records


def _trivy(payload):
    records = []
    for result in payload.get("Results", []):
        target = result.get("Target", "")
        for key, kind in (("Misconfigurations", "misconfiguration"), ("Vulnerabilities", "vulnerability"), ("Secrets", "secret")):
            for item in result.get(key, []) or []:
                finding = _text(item.get("Title"), item.get("Description"), item.get("Message"), target)
                if not finding:
                    continue
                records.append((finding, {
                    "provider": "aws" if "aws" in finding.lower() else "generic",
                    "source_type": "scanner",
                    "scanner": "Trivy",
                    "rule_id": item.get("ID") or item.get("VulnerabilityID"),
                    "resource_type": kind,
                    "resource_id": target,
                    "evidence": [finding],
                }))
    return records


def _security_hub(payload):
    records = []
    for finding_data in payload.get("Findings", []):
        resource = (finding_data.get("Resources") or [{}])[0]
        finding = _text(
            finding_data.get("Title"), finding_data.get("Description"),
            finding_data.get("GeneratorId"), resource.get("Id"),
        )
        if not finding:
            continue
        records.append((finding, {
            "provider": "aws",
            "source_type": "cloud_security_service",
            "scanner": "AWS Security Hub",
            "rule_id": finding_data.get("GeneratorId") or finding_data.get("Id"),
            "resource_type": resource.get("Type"),
            "resource_id": resource.get("Id"),
            "account": finding_data.get("AwsAccountId"),
            "region": finding_data.get("Region"),
            "evidence": [finding],
        }))
    return records


ADAPTERS = {"checkov": _checkov, "trivy": _trivy, "security_hub": _security_hub}


def normalize_payload(source, payload):
    """Return validated finding text and metadata from a supported exported payload."""
    if source not in ADAPTERS:
        raise FindingIngestionError("Unsupported finding source: %s" % source)
    if not isinstance(payload, dict):
        raise FindingIngestionError("Finding payload must be a JSON object.")
    records = ADAPTERS[source](payload)
    if not records:
        raise FindingIngestionError("No supported findings were present in the payload.")
    return records


def load_json_upload(file_path):
    """Load a bounded JSON export from Gradio's temporary upload path."""
    if not isinstance(file_path, str) or not file_path.lower().endswith(".json"):
        raise FindingIngestionError("Upload a JSON finding export.")
    if not os.path.isfile(file_path) or os.path.getsize(file_path) > MAX_UPLOAD_BYTES:
        raise FindingIngestionError("Upload a valid JSON export smaller than 1 MB.")
    try:
        with open(file_path, "r", encoding="utf-8") as upload_file:
            payload = json.load(upload_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise FindingIngestionError("The uploaded file is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise FindingIngestionError("The uploaded JSON must be an object.")
    return payload
