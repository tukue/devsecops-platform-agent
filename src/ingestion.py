"""Read-only adapters for scanner findings and cloud security-service exports."""

import json
import math
import os
import stat
import tempfile

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


MAX_SECURITY_HUB_FINDINGS = 500


def prepare_security_hub_import(payload):
    """Validate an ASFF export and partition records before advisory analysis.

    Invalid rows are reported by index without echoing untrusted input. Duplicate
    identities keep the first valid occurrence; no status is inferred as a pass.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("Findings"), list):
        raise FindingIngestionError("Expected an AWS Security Hub object with a Findings array.")
    findings = payload["Findings"]
    if len(findings) > MAX_SECURITY_HUB_FINDINGS:
        raise FindingIngestionError("Export exceeds the 500-record import limit; split the export into batches.")
    summary = {
        "total_records": len(findings), "imported_count": 0,
        "actionable_count": 0, "duplicate_count": 0, "invalid_count": 0,
        "status_counts": {key: 0 for key in (
            "actionable", "passed", "resolved", "suppressed", "archived", "unknown_check"
        )},
        "accounts": [], "regions": [], "partial_export": bool(payload.get("NextToken")),
        "coverage": "Uploaded findings only. Resources and controls outside this export were not assessed.",
        "warnings": [], "rejected_records": [],
    }
    records, excluded, seen = [], [], set()
    accounts, regions = set(), set()
    for index, row in enumerate(findings):
        try:
            if not isinstance(row, dict):
                raise ValueError("Finding must be an object.")
            text_fields = ("Title", "Description", "GeneratorId", "Id", "ProductArn",
                           "AwsAccountId", "Region", "RecordState", "CreatedAt", "UpdatedAt",
                           "FirstObservedAt", "LastObservedAt")
            for key in text_fields:
                if key in row and not isinstance(row[key], str):
                    raise ValueError("%s must be text." % key)
            if not (row.get("Title", "").strip() or row.get("Description", "").strip()):
                raise ValueError("Finding needs a title or description.")
            for key in ("Workflow", "Compliance", "Severity"):
                if key in row and not isinstance(row[key], dict):
                    raise ValueError("%s must be an object." % key)
            workflow = row.get("Workflow", {}).get("Status")
            compliance = row.get("Compliance", {}).get("Status")
            state = row.get("RecordState")
            for value, allowed, name in (
                (workflow, {"NEW", "NOTIFIED", "SUPPRESSED", "RESOLVED"}, "Workflow.Status"),
                (compliance, {"PASSED", "FAILED", "WARNING", "NOT_AVAILABLE"}, "Compliance.Status"),
                (state, {"ACTIVE", "ARCHIVED"}, "RecordState"),
            ):
                if value is not None and (not isinstance(value, str) or value not in allowed):
                    raise ValueError("Unsupported %s." % name)
            severity = row.get("Severity", {})
            if "Label" in severity and severity["Label"] not in (
                "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
            ):
                raise ValueError("Unsupported Severity.Label.")
            for key in ("Original",):
                if key in severity and not isinstance(severity[key], str):
                    raise ValueError("Severity.Original must be text.")
            for key in ("Normalized", "Product"):
                if key in severity and (type(severity[key]) not in (int, float) or not math.isfinite(severity[key])):
                    raise ValueError("Severity.%s must be a finite number." % key)
            if "Normalized" in severity and not 0 <= severity["Normalized"] <= 100:
                raise ValueError("Severity.Normalized must be between 0 and 100.")
            resources = row.get("Resources", [])
            if not isinstance(resources, list):
                raise ValueError("Resources must be an array.")
            clean_resources = []
            for resource in resources:
                if not isinstance(resource, dict):
                    raise ValueError("Each resource must be an object.")
                for key in ("Id", "Type", "Region", "Partition"):
                    if key in resource and not isinstance(resource[key], str):
                        raise ValueError("Resource %s must be text." % key)
                clean_resources.append({key: resource[key] for key in (
                    "Id", "Type", "Region", "Partition"
                ) if key in resource})
        except ValueError as exc:
            summary["rejected_records"].append({"index": index, "error": str(exc)})
            summary["invalid_count"] += 1
            continue

        identity = (row.get("ProductArn"), row.get("Id"))
        if all(identity):
            if identity in seen:
                summary["duplicate_count"] += 1
                continue
            seen.add(identity)
        else:
            if "Some records lack a product ARN or finding ID; these cannot be deduplicated." not in summary["warnings"]:
                summary["warnings"].append("Some records lack a product ARN or finding ID; these cannot be deduplicated.")

        disposition = "actionable"
        if state == "ARCHIVED":
            disposition = "archived"
        elif workflow == "SUPPRESSED":
            disposition = "suppressed"
        elif compliance == "PASSED":
            disposition = "passed"
        elif workflow == "RESOLVED":
            disposition = "resolved"
        elif compliance in {"WARNING", "NOT_AVAILABLE"}:
            disposition = "unknown_check"
        resource = next(iter(clean_resources), {})
        # Resource IDs remain structured evidence rather than classifier input.
        finding = _text(row.get("Title"), row.get("Description"), row.get("GeneratorId"))
        metadata = {
            "provider": "aws", "source_type": "cloud_security_service",
            "scanner": "AWS Security Hub", "rule_id": row.get("GeneratorId") or row.get("Id"),
            "resource_type": resource.get("Type"), "resource_id": resource.get("Id"),
            "account": row.get("AwsAccountId"), "region": row.get("Region"),
            "evidence": [finding], "finding_id": row.get("Id"),
            "product_arn": row.get("ProductArn"),
            "native_severity": {key: severity[key] for key in (
                "Label", "Original", "Normalized", "Product"
            ) if key in severity},
            "workflow_status": workflow, "compliance_status": compliance,
            "record_state": state, "resources": clean_resources,
            "source_timestamps": {key: row[key] for key in (
                "CreatedAt", "UpdatedAt", "FirstObservedAt", "LastObservedAt"
            ) if key in row},
        }
        if metadata["account"]:
            accounts.add(metadata["account"])
        if metadata["region"]:
            regions.add(metadata["region"])
        regions.update(item["Region"] for item in clean_resources if item.get("Region"))
        summary["imported_count"] += 1
        summary["status_counts"][disposition] += 1
        if disposition == "actionable":
            records.append((finding, metadata))
        else:
            excluded.append({"disposition": disposition, "source": metadata})
    summary["actionable_count"] = len(records)
    summary["accounts"], summary["regions"] = sorted(accounts), sorted(regions)
    if summary["partial_export"]:
        summary["warnings"].append("Export contains a continuation token; additional findings were not imported.")
    if not findings:
        summary["warnings"].append("No findings imported. This does not establish that the infrastructure is secure.")
    return {"records": records, "summary": summary, "excluded_findings": excluded}


def _security_hub(payload):
    return prepare_security_hub_import(payload)["records"]


ADAPTERS = {"checkov": _checkov, "trivy": _trivy, "security_hub": _security_hub}


def normalize_payload(source, payload):
    """Return validated finding text and metadata from a supported exported payload."""
    if source not in ADAPTERS:
        raise FindingIngestionError("Unsupported finding source: %s" % source)
    if not isinstance(payload, dict):
        raise FindingIngestionError("Finding payload must be a JSON object.")
    records = ADAPTERS[source](payload)
    if not records and source != "security_hub":
        raise FindingIngestionError("No supported findings were present in the payload.")
    return records


def load_json_upload(file_path):
    """Load a bounded JSON export using safe, directory-relative file access."""
    if not isinstance(file_path, str) or not file_path.lower().endswith(".json"):
        raise FindingIngestionError("Upload a JSON finding export.")

    temp_root = os.path.realpath(tempfile.gettempdir())
    candidate = os.path.abspath(os.path.normpath(file_path))
    try:
        if os.path.commonpath((temp_root, candidate)) != temp_root:
            raise FindingIngestionError("Invalid upload path.")
    except ValueError as exc:
        raise FindingIngestionError("Invalid upload path.") from exc

    relative_path = os.path.relpath(candidate, temp_root)
    components = relative_path.split(os.sep)
    if not components or any(part in ("", ".", "..") for part in components):
        raise FindingIngestionError("Invalid upload path.")

    directory_fds = []
    file_fd = None
    try:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(temp_root, directory_flags)
        directory_fds.append(directory_fd)

        for component in components[:-1]:
            directory_fd = os.open(
                component,
                directory_flags | no_follow,
                dir_fd=directory_fd,
            )
            directory_fds.append(directory_fd)

        file_fd = os.open(
            components[-1],
            os.O_RDONLY | no_follow,
            dir_fd=directory_fd,
        )
        file_info = os.fstat(file_fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_size > MAX_UPLOAD_BYTES:
            raise FindingIngestionError("Upload a valid JSON export smaller than 1 MB.")

        with os.fdopen(file_fd, "rb") as upload_file:
            file_fd = None
            raw_payload = upload_file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw_payload) > MAX_UPLOAD_BYTES:
            raise FindingIngestionError("Upload a valid JSON export smaller than 1 MB.")
        payload = json.loads(raw_payload.decode("utf-8"))
    except FindingIngestionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FindingIngestionError("The uploaded file is not valid JSON.") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)

    if not isinstance(payload, dict):
        raise FindingIngestionError("The uploaded JSON must be an object.")
    return payload
