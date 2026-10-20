"""End-to-end assessment tests driven through the real Gradio event wiring."""

import asyncio
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

gr = pytest.importorskip("gradio")

sys.modules.setdefault("transformers", MagicMock())


class _PassthroughGPU:
    """Stand in for @spaces.GPU when no Hugging Face runtime is present."""

    def __call__(self, fn=None):
        if callable(fn):
            return fn
        return lambda wrapped: wrapped


_existing_spaces = sys.modules.get("spaces")
if not isinstance(_existing_spaces, types.ModuleType) or isinstance(
    _existing_spaces, MagicMock
):
    spaces_stub = types.ModuleType("spaces")
    spaces_stub.GPU = _PassthroughGPU()
    sys.modules["spaces"] = spaces_stub

import app  # noqa: E402
from src import input_validation  # noqa: E402
from src.observability import get_metrics, reset_metrics  # noqa: E402
from src.retriever import SOURCE_FIELDS  # noqa: E402
from src.sessions import SessionRegistry  # noqa: E402

SSH_FINDING = "The production security group allows SSH from 0.0.0.0/0."
PRIVILEGED_FINDING = "The Kubernetes workload runs as root in a privileged container."


class _FakeRequest:
    def __init__(self, session_hash):
        self.session_hash = session_hash


@pytest.fixture(autouse=True)
def clean_assessment_state():
    """Isolate every test from shared rate limits, sessions, and metrics."""
    input_validation._request_log.clear()
    app.memory.sessions.clear()
    app.sessions = SessionRegistry()
    reset_metrics()
    yield
    input_validation._request_log.clear()
    app.memory.sessions.clear()


def _fn_index(fn_name):
    for index, block_fn in app.demo.fns.items():
        if getattr(block_fn.fn, "__name__", None) == fn_name:
            return index
    raise AssertionError(f"No Gradio event is wired to {fn_name}")


def _call(fn_name, inputs, session_hash):
    """Run one UI event the way the browser would, with an injected request."""

    async def run():
        response = await app.demo.process_api(
            _fn_index(fn_name),
            inputs=inputs,
            state=None,
            request=gr.Request(None, session_hash=session_hash),
            session_hash=session_hash,
        )
        value = response["data"][0]
        return getattr(value, "root", value)

    return asyncio.run(run())


def test_successful_assessment_returns_grounded_citations_and_guidance():
    result = _call("review_finding", [SSH_FINDING], "browser-success")

    assert "error" not in result
    assert result["category"] == "Network"
    assert result["control_id"] == "network.public-ingress"
    assert result["severity"] == "critical"
    assert result["confidence"] > 0
    assert result["evidence"]
    assert isinstance(result["evidence"], list)
    assert result["validation_step"]
    assert result["rollback_guidance"]
    assert result["human_review_required"]
    assert "Sources:" in result["recommendation"]
    assert result["session_id"].startswith("session_")

    assert result["citations"]
    for citation in result["citations"]:
        assert citation["id"]
        assert citation["source"]
        assert citation["version"]
        assert citation["references"]

    assert result["rag_sources"]
    for source in result["rag_sources"]:
        assert set(source) == set(SOURCE_FIELDS)

    grounding = get_metrics()["grounding"]
    assert grounding["responses_total"] == 1
    assert grounding["citation_covered_responses_total"] == 1
    assert grounding["exact_control_responses_total"] == 1


def test_review_finding_rejects_empty_input():
    assert app.review_finding("") == {"error": "A security finding is required."}


def test_sessions_are_server_generated_and_bound_to_one_browser_session():
    first = _call("review_finding", [SSH_FINDING], "browser-alpha")
    second = _call("review_finding", [PRIVILEGED_FINDING], "browser-alpha")

    assert first["session_id"].startswith("session_")
    assert first["session_id"] == second["session_id"]
    assert second["session_risk_summary"]["total_findings"] == 2


def test_blank_session_ids_never_share_a_history_entry():
    first = app.analyze_finding(SSH_FINDING, session_id="")
    second = app.analyze_finding(PRIVILEGED_FINDING, session_id="   ")

    assert first["session_id"] and second["session_id"]
    assert first["session_id"] != second["session_id"]
    assert "" not in app.memory.sessions


def test_foreign_session_ids_cannot_reach_another_owners_history():
    mine = app.analyze_finding(SSH_FINDING, owner="browser-alpha")
    hijack = app.analyze_finding(
        PRIVILEGED_FINDING, session_id=mine["session_id"], owner="browser-beta"
    )

    assert hijack["session_id"] != mine["session_id"]
    assert app.memory.get_risk_summary(mine["session_id"])["total_findings"] == 1
    assert app.memory.get_risk_summary(hijack["session_id"])["total_findings"] == 1


def test_two_browser_sessions_keep_independent_histories():
    mine = _call("review_finding", [SSH_FINDING], "browser-alpha")
    theirs = _call("review_finding", [SSH_FINDING], "browser-beta")

    assert mine["session_id"] != theirs["session_id"]
    assert app.memory.get_risk_summary(mine["session_id"])["total_findings"] == 1
    assert app.memory.get_risk_summary(theirs["session_id"])["total_findings"] == 1


def test_unowned_callers_can_reuse_their_own_session_id():
    first = app.analyze_finding(SSH_FINDING, session_id="review-42")
    second = app.analyze_finding(PRIVILEGED_FINDING, session_id="review-42")

    assert first["session_id"] == "review-42"
    assert second["session_id"] == "review-42"
    assert app.memory.get_risk_summary("review-42")["total_findings"] == 2


def _checkov_payload():
    return {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_name": "S3 bucket public access",
                    "resource": "aws_s3_bucket.logs",
                    "framework": "terraform",
                    "check_type": "resource",
                    "file_path": "main.tf",
                },
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 bucket encryption at rest",
                    "resource": "aws_s3_bucket.logs",
                    "framework": "terraform",
                    "check_type": "resource",
                    "file_path": "main.tf",
                },
            ]
        }
    }


def test_batch_ingestion_shares_one_session_across_all_findings():
    results = app.analyze_ingested_findings("checkov", _checkov_payload())
    session_ids = {result["session_id"] for result in results}

    assert len(results) == 2
    assert len(session_ids) == 1
    batch_session = session_ids.pop()
    assert batch_session.startswith("session_")
    assert app.memory.get_risk_summary(batch_session)["total_findings"] == 2

    follow_up = app.analyze_ingested_findings("checkov", _checkov_payload())
    assert {result["session_id"] for result in follow_up} != {batch_session}


def test_batch_ingestion_with_an_owner_keeps_one_bound_session():
    first = app.analyze_ingested_findings("checkov", _checkov_payload(), owner="browser-batch")
    second = app.analyze_ingested_findings("checkov", _checkov_payload(), owner="browser-batch")

    bound_session = first[0]["session_id"]
    assert {result["session_id"] for result in first} == {bound_session}
    assert {result["session_id"] for result in second} == {bound_session}
    assert app.memory.get_risk_summary(bound_session)["total_findings"] == 4


def test_chain_of_thought_assessment_reads_the_bound_session_context():
    _call("review_finding", [SSH_FINDING], "browser-cot")
    result = _call("review_finding_with_cot", [PRIVILEGED_FINDING], "browser-cot")

    assert "chain_of_thought" in result
    assert result["session_risk_summary"]["total_findings"] == 2


def test_clear_session_only_clears_the_owners_session():
    mine = app.analyze_finding(SSH_FINDING, owner="browser-alpha")
    theirs = app.analyze_finding(SSH_FINDING, owner="browser-beta")

    cleared = app.clear_session(request=_FakeRequest("browser-alpha"))
    assert mine["session_id"] in cleared["status"]
    assert app.memory.get_context(mine["session_id"]) == ""
    assert app.memory.get_context(theirs["session_id"]) != ""

    foreign = app.clear_session(
        session_id=theirs["session_id"], request=_FakeRequest("browser-alpha")
    )
    assert theirs["session_id"] not in foreign["status"]
    assert app.memory.get_context(theirs["session_id"]) != ""


def test_clear_session_reports_when_no_session_is_bound():
    assert app.clear_session(request=_FakeRequest("browser-unused")) == {
        "status": "No active session to clear."
    }
    assert "" not in app.memory.sessions


def test_github_handoff_requires_access_token_then_allowlist(monkeypatch):
    assessment = {"control_id": "c", "severity": "high"}

    monkeypatch.delenv("GITHUB_HANDOFF_TOKEN", raising=False)
    disabled = app.create_github_issue(assessment, "org/repo", "anything")
    assert "GITHUB_HANDOFF_TOKEN" in disabled["error"]

    monkeypatch.setenv("GITHUB_HANDOFF_TOKEN", "correct-horse")
    wrong = app.create_github_issue(assessment, "org/repo", "wrong")
    assert "Invalid handoff access token" in wrong["error"]
    wrong_pr = app.comment_on_github_pr(assessment, "org/repo", 1, "")
    assert "Invalid handoff access token" in wrong_pr["error"]

    monkeypatch.delenv("GITHUB_ALLOWED_REPOSITORIES", raising=False)
    no_allowlist = app.create_github_issue(assessment, "org/repo", "correct-horse")
    assert "GITHUB_ALLOWED_REPOSITORIES" in no_allowlist["error"]
