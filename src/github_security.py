"""Deployment-managed handoff identities and redacted security audit events."""
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from src.github_workflow import GitHubWorkflowError

logger = logging.getLogger("devsecops_advisor.github_security")


def authorize_handoff(token, repository, action):
    """Verify a personal token against hashed, scoped, expiring credentials.

    Configuration is read on each operation so revocation/rotation needs no
    process-local credential cache. Explicit personal configuration fails closed.
    """
    raw = os.getenv("GITHUB_HANDOFF_IDENTITIES")
    presented = str(token or "").strip()
    if raw is not None:
        try:
            identities = json.loads(raw)
            if not isinstance(identities, list) or not identities:
                raise ValueError()
            for identity in identities:
                if not isinstance(identity, dict):
                    raise ValueError()
                if not isinstance(identity.get("actor"), str) or not identity["actor"].strip():
                    raise ValueError()
                hashes = identity["token_sha256"]
                if not isinstance(hashes, list) or not hashes or any(
                    not isinstance(item, str) or len(item) != 64
                    or any(c not in "0123456789abcdef" for c in item) for item in hashes
                ):
                    raise ValueError()
                for key in ("repositories", "actions"):
                    if not isinstance(identity[key], list) or not identity[key] or any(
                        not isinstance(item, str) for item in identity[key]
                    ):
                        raise ValueError()
                expiry = datetime.fromisoformat(identity["expires_at"].replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError):
            raise GitHubWorkflowError("Invalid GitHub handoff identity configuration.") from None
        digest = hashlib.sha256(presented.encode()).hexdigest()
        matches = [identity for identity in identities if any(
            hmac.compare_digest(digest, item) for item in identity["token_sha256"]
        )] if presented else []
        if len(matches) != 1:
            raise GitHubWorkflowError("Invalid handoff access token.")
        identity = matches[0]
        expiry = datetime.fromisoformat(identity["expires_at"].replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc):
            raise GitHubWorkflowError("Handoff credential has expired.")
        if repository not in identity["repositories"] or action not in identity["actions"]:
            raise GitHubWorkflowError("Handoff identity is not authorized for this repository/action.")
        return identity["actor"]

    expected = str(os.getenv("GITHUB_HANDOFF_TOKEN") or "").strip()
    if os.getenv("GITHUB_HANDOFF_REQUIRE_IDENTITIES", "").lower() == "true" or not expected:
        raise GitHubWorkflowError(
            "GitHub handoff is disabled: set GITHUB_HANDOFF_IDENTITIES or GITHUB_HANDOFF_TOKEN."
        )
    if not presented or not hmac.compare_digest(presented, expected):
        raise GitHubWorkflowError("Invalid handoff access token.")
    return "legacy-shared-token"


def audit_handoff(event_id, actor, action, repository, outcome):
    # Never record credentials, assessment evidence, HTTP bodies or exception text.
    logger.info(json.dumps({
        "event": "github_handoff", "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor, "action": action, "repository": repository,
        "outcome": outcome,
    }, sort_keys=True))


def handoff_event_id():
    return uuid.uuid4().hex
