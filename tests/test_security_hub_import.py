"""Security Hub import contracts independent of models and UI dependencies."""
import copy
import json
from pathlib import Path

import pytest

from src.findings import canonicalize_finding
from src.ingestion import FindingIngestionError, prepare_security_hub_import


def finding(**changes):
    row = {
        "Id": "finding-1", "ProductArn": "arn:aws:securityhub:eu-north-1:123456789012:product/example",
        "Title": "Security group allows SSH from 0.0.0.0/0",
        "Description": "Restrict public ingress to production.",
        "AwsAccountId": "123456789012", "Region": "eu-north-1",
        "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
        "Compliance": {"Status": "FAILED"}, "Severity": {"Label": "HIGH", "Normalized": 70},
        "UpdatedAt": "2026-10-28T12:00:00Z",
        "Resources": [{"Id": "sg-example", "Type": "AwsEc2SecurityGroup", "Region": "eu-north-1"},
                      {"Id": "sg-second", "Type": "AwsEc2SecurityGroup", "Region": "eu-west-1"}],
    }
    row.update(changes)
    return row


def test_preserves_evidence_and_keeps_native_severity_separate():
    batch = prepare_security_hub_import({"Findings": [finding()]})
    text, metadata = batch["records"][0]
    canonical = canonicalize_finding(text, {"category": "Network", "severity": "critical", "confidence": .9}, None, metadata).to_dict()
    assert canonical["severity"] == "critical"
    assert canonical["native_severity"] == {"Label": "HIGH", "Normalized": 70}
    assert canonical["finding_id"] == "finding-1"
    assert canonical["resources"][1]["Id"] == "sg-second"
    assert canonical["source_timestamps"]["UpdatedAt"] == "2026-10-28T12:00:00Z"
    assert batch["summary"]["regions"] == ["eu-north-1", "eu-west-1"]


@pytest.mark.parametrize("changes,disposition", [
    ({"Compliance": {"Status": "PASSED"}, "Workflow": {"Status": "RESOLVED"}}, "passed"),
    ({"Workflow": {"Status": "RESOLVED"}}, "resolved"),
    ({"Workflow": {"Status": "SUPPRESSED"}}, "suppressed"),
    ({"RecordState": "ARCHIVED"}, "archived"),
    ({"Compliance": {"Status": "WARNING"}}, "unknown_check"),
    ({"Compliance": {"Status": "NOT_AVAILABLE"}}, "unknown_check"),
])
def test_nonactionable_records_are_retained_without_classification(changes, disposition):
    batch = prepare_security_hub_import({"Findings": [finding(**changes)]})
    assert batch["records"] == []
    assert batch["excluded_findings"][0]["disposition"] == disposition
    assert batch["summary"]["status_counts"][disposition] == 1


@pytest.mark.parametrize("bad", [None, [], {"Title": 4}, finding(Resources="invalid"),
    finding(Resources=[None]), finding(Workflow=[]), finding(Compliance={"Status": []}),
    finding(Severity={"Label": {}}), finding(Severity={"Normalized": True}), finding(Severity={"Product": float("nan")}),
    finding(Severity={"Normalized": 101}), finding(Region=[])])
def test_malformed_rows_do_not_discard_valid_findings(bad):
    batch = prepare_security_hub_import({"Findings": [bad, finding()]})
    assert len(batch["records"]) == 1
    assert batch["summary"]["invalid_count"] == 1
    assert batch["summary"]["rejected_records"][0]["index"] == 0


def test_duplicate_identity_uses_product_and_id_and_reports_partial_export():
    row = finding()
    batch = prepare_security_hub_import({"Findings": [row, copy.deepcopy(row), finding(ProductArn="other")], "NextToken": "do-not-echo"})
    assert len(batch["records"]) == 2
    assert batch["summary"]["duplicate_count"] == 1
    assert batch["summary"]["partial_export"]
    assert "do-not-echo" not in json.dumps(batch)


def test_missing_identity_is_not_silently_deduplicated():
    row = finding(Id="")
    batch = prepare_security_hub_import({"Findings": [row, row]})
    assert len(batch["records"]) == 2
    assert batch["summary"]["warnings"]


def test_empty_export_does_not_claim_security():
    batch = prepare_security_hub_import({"Findings": []})
    assert batch["summary"]["imported_count"] == 0
    assert "does not establish" in batch["summary"]["warnings"][0]


@pytest.mark.parametrize("payload", [{}, {"Findings": {}}, {"Findings": [finding()] * 501}])
def test_invalid_envelopes_and_oversized_batches_are_rejected(payload):
    with pytest.raises(FindingIngestionError):
        prepare_security_hub_import(payload)


def test_sanitized_example_reconciles_all_records():
    path = Path(__file__).parent / "fixtures" / "security_hub_export.json"
    batch = prepare_security_hub_import(json.loads(path.read_text()))
    summary = batch["summary"]
    assert summary["total_records"] == summary["imported_count"] + summary["duplicate_count"] + summary["invalid_count"]
    assert summary["actionable_count"] == 1
    assert summary["status_counts"]["passed"] == 1
