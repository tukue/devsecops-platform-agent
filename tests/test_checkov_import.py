"""Checkov JSON import contracts, independent of models and UI dependencies."""
import json
from pathlib import Path

import pytest

from src.ingestion import FindingIngestionError, normalize_payload, prepare_checkov_import


FIXTURE = Path(__file__).parent / "fixtures" / "checkov_terraform_export.json"


def test_sanitized_checkov_export_partitions_checks_and_maps_failed_evidence():
    batch = prepare_checkov_import(json.loads(FIXTURE.read_text()))
    finding, metadata = batch["records"][0]
    assert "0.0.0.0/0" in finding
    assert metadata["scanner"] == "Checkov"
    assert metadata["provider"] == "aws"
    assert metadata["rule_id"] == "CKV_AWS_24"
    assert metadata["source_references"] == ["main.tf:12-24"]
    assert batch["summary"]["failed_count"] == 1
    assert batch["summary"]["passed_count"] == 1
    assert batch["summary"]["actionable_count"] == 1


@pytest.mark.parametrize("payload", [{}, {"results": []}, {"results": {"failed_checks": {}}}])
def test_malformed_checkov_envelopes_are_rejected(payload):
    with pytest.raises(FindingIngestionError):
        prepare_checkov_import(payload)


@pytest.mark.parametrize("check", [None, {"check_id": 12, "check_name": "bad"}, {}])
def test_malformed_checkov_rows_are_reported_without_echoing_input(check):
    batch = prepare_checkov_import({"results": {"failed_checks": [check]}})
    assert batch["summary"]["invalid_count"] == 1
    assert batch["records"] == []


def test_checkov_duplicate_findings_are_counted_once():
    payload = json.loads(FIXTURE.read_text())
    payload["results"]["failed_checks"].append(payload["results"]["failed_checks"][0])
    batch = prepare_checkov_import(payload)
    assert len(batch["records"]) == 1
    assert batch["summary"]["duplicate_count"] == 1


def test_checkov_normalize_payload_returns_only_failed_checks():
    payload = json.loads(FIXTURE.read_text())
    assert len(normalize_payload("checkov", payload)) == 1
