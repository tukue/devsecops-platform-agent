import hashlib
import json
import logging

import pytest

from src.github_security import authorize_handoff, audit_handoff
from src.github_workflow import GitHubWorkflowError


def configure(monkeypatch, **changes):
    identity = dict(actor="test_user1", token_sha256=[hashlib.sha256(b"personal-secret").hexdigest()],
                    repositories=["org/repo"], actions=["create_issue"], expires_at="2099-01-01T00:00:00Z")
    identity.update(changes)
    monkeypatch.setenv("GITHUB_HANDOFF_IDENTITIES", json.dumps([identity]))
    return identity


def test_personal_permissions(monkeypatch):
    configure(monkeypatch)
    assert authorize_handoff("personal-secret", "org/repo", "create_issue") == "test_user1"
    for token, repo, action in [("wrong", "org/repo", "create_issue"),
                                ("personal-secret", "other/repo", "create_issue"),
                                ("personal-secret", "org/repo", "comment_pr")]:
        with pytest.raises(GitHubWorkflowError):
            authorize_handoff(token, repo, action)


def test_rotation_and_revocation(monkeypatch):
    old = hashlib.sha256(b"old-secret").hexdigest()
    new = hashlib.sha256(b"new-secret").hexdigest()
    configure(monkeypatch, token_sha256=[old, new])
    assert authorize_handoff("old-secret", "org/repo", "create_issue") == "test_user1"
    assert authorize_handoff("new-secret", "org/repo", "create_issue") == "test_user1"
    configure(monkeypatch, token_sha256=[new])
    with pytest.raises(GitHubWorkflowError):
        authorize_handoff("old-secret", "org/repo", "create_issue")


@pytest.mark.parametrize("changes", [dict(expires_at="2000-01-01T00:00:00Z"),
    dict(expires_at="2099-01-01"), dict(token_sha256=["invalid"]), dict(actions="create_issue")])
def test_invalid_or_expired_personal_credentials_never_fall_back(monkeypatch, changes):
    configure(monkeypatch, **changes)
    # A matching legacy token must not rescue invalid personal configuration.
    monkeypatch.setenv("GITHUB_HANDOFF_TOKEN", "personal-secret")
    with pytest.raises(GitHubWorkflowError):
        authorize_handoff("personal-secret", "org/repo", "create_issue")


def test_production_disables_shared_token(monkeypatch):
    monkeypatch.delenv("GITHUB_HANDOFF_IDENTITIES", raising=False)
    monkeypatch.setenv("GITHUB_HANDOFF_REQUIRE_IDENTITIES", "true")
    monkeypatch.setenv("GITHUB_HANDOFF_TOKEN", "shared")
    with pytest.raises(GitHubWorkflowError):
        authorize_handoff("shared", "org/repo", "create_issue")


def test_audit_is_structured(caplog):
    with caplog.at_level(logging.INFO, logger="devsecops_advisor.github_security"):
        audit_handoff("trace", "test_user1", "create_issue", "org/repo", "issue_created")
    event = json.loads(caplog.records[-1].message)
    assert event["actor"] == "test_user1"
    assert event["outcome"] == "issue_created"
    assert "token" not in event


@pytest.mark.parametrize("raw", ["not-json", "[]", '[{"actor":"test_user1"}]'])
def test_malformed_identity_configuration_returns_generic_error(monkeypatch, raw):
    monkeypatch.setenv("GITHUB_HANDOFF_IDENTITIES", raw)
    with pytest.raises(GitHubWorkflowError, match=r"^Invalid handoff access token\.$"):
        authorize_handoff("anything", "org/repo", "create_issue")


def test_legacy_token_works_only_without_personal_configuration(monkeypatch):
    monkeypatch.delenv("GITHUB_HANDOFF_IDENTITIES", raising=False)
    monkeypatch.delenv("GITHUB_HANDOFF_REQUIRE_IDENTITIES", raising=False)
    monkeypatch.setenv("GITHUB_HANDOFF_TOKEN", "shared")
    assert authorize_handoff("shared", "org/repo", "create_issue") == "legacy-shared-token"
