"""Explicit, draft-only GitHub issue and pull-request handoff."""

import hashlib
import json
import os
import re
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


GITHUB_API = "https://api.github.com"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ISSUE_DEDUP_LOCK = threading.Lock()


class GitHubWorkflowError(RuntimeError):
    pass


def finding_fingerprint(assessment):
    finding = assessment.get("finding") or {}
    identity = {
        "provider": finding.get("provider", "generic"),
        "control_id": assessment.get("control_id", finding.get("control_id", "unclassified")),
        "resource_id": finding.get("resource_id"),
        "rule_id": finding.get("rule_id"),
        "evidence": finding.get("evidence", assessment.get("evidence", [])),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _safe_markdown(value):
    text = str(value or "Not provided")
    text = text.replace("\r", " ").replace("\n", " ")
    return text.replace("`", "'")


def build_work_item(assessment):
    if not isinstance(assessment, dict) or assessment.get("error"):
        raise GitHubWorkflowError("A successful assessment is required.")
    fingerprint = finding_fingerprint(assessment)
    control_id = assessment.get("control_id", "unclassified")
    severity = assessment.get("severity", "unknown")
    provider = (assessment.get("finding") or {}).get("provider", "generic")
    resource = (assessment.get("finding") or {}).get("resource_id") or "resource unavailable"
    title = f"[Agent draft] {severity.upper()} {control_id}: {resource}"

    evidence = assessment.get("evidence") or (assessment.get("finding") or {}).get("evidence", [])
    evidence_lines = "\n".join(f"- {_safe_markdown(item)}" for item in evidence) or "- Not provided"
    citation_lines = []
    for citation in assessment.get("citations", []):
        refs = ", ".join(citation.get("references", [])) or "reference unavailable"
        citation_lines.append(
            f"- [{_safe_markdown(citation.get('id'))}] "
            f"{_safe_markdown(citation.get('source'))} "
            f"v{_safe_markdown(citation.get('version'))}: {refs}"
        )
    citations = "\n".join(citation_lines) or "- No retrieved citation; validate guidance before use."

    body = (
        f"<!-- devsecops-finding:{fingerprint} -->\n"
        "## Draft security finding\n\n"
        f"- Provider: {_safe_markdown(provider)}\n"
        f"- Control: `{_safe_markdown(control_id)}`\n"
        f"- Severity: {_safe_markdown(severity)}\n"
        f"- Confidence: {_safe_markdown(assessment.get('confidence'))}\n"
        f"- Owner: {_safe_markdown(assessment.get('owner'))}\n"
        f"- Human review required: {bool(assessment.get('human_review_required', True))}\n\n"
        f"### Evidence\n{evidence_lines}\n\n"
        f"### Proposed remediation\n{_safe_markdown(assessment.get('recommendation'))}\n\n"
        f"### Validation\n{_safe_markdown(assessment.get('validation_step'))}\n\n"
        f"### Rollback and dependencies\n{_safe_markdown(assessment.get('rollback_guidance'))}\n\n"
        f"### Sources\n{citations}\n\n"
        "This is an advisory draft. Review the finding and proposed change; no source code or infrastructure was modified."
    )
    return fingerprint, title, body


class GitHubWorkflowClient:
    """Uses GitHub REST only when an explicit issue or PR handoff is requested."""

    def __init__(self, repository, token=None, timeout=10):
        if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
            raise GitHubWorkflowError("Repository must use the owner/repository format.")
        self.repository = repository
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise GitHubWorkflowError("Set GITHUB_TOKEN to enable GitHub handoff.")
        self.timeout = timeout

    def _request(self, method, path, payload=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            f"{GITHUB_API}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "devsecops-platform-agent",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise GitHubWorkflowError("GitHub response exceeded the size limit.")
                return json.loads(raw.decode("utf-8")) if raw else {}
        except HTTPError as exc:
            raise GitHubWorkflowError(f"GitHub request failed with HTTP {exc.code}.") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise GitHubWorkflowError("GitHub request failed.") from exc

    def _open_issues(self):
        issues = []
        for page in range(1, 11):
            path = f"/repos/{self.repository}/issues?{urlencode({'state': 'all', 'per_page': 100, 'page': page})}"
            items = self._request("GET", path)
            if not isinstance(items, list):
                raise GitHubWorkflowError("Unexpected GitHub issues response.")
            issues.extend(item for item in items if "pull_request" not in item)
            if len(items) < 100:
                break
        return issues

    def create_draft_issue(self, assessment):
        fingerprint, title, body = build_work_item(assessment)
        marker = f"<!-- devsecops-finding:{fingerprint} -->"
        with _ISSUE_DEDUP_LOCK:
            for issue in self._open_issues():
                if marker in issue.get("body", ""):
                    return {"status": "existing", "number": issue["number"], "url": issue["html_url"]}
            created = self._request(
                "POST", f"/repos/{self.repository}/issues", {"title": title, "body": body}
            )
            return {"status": "draft_created", "number": created["number"], "url": created["html_url"]}

    def comment_on_pull_request(self, pull_request, assessment):
        try:
            number = int(pull_request)
        except (TypeError, ValueError) as exc:
            raise GitHubWorkflowError("Pull request number must be a positive integer.") from exc
        if number <= 0:
            raise GitHubWorkflowError("Pull request number must be a positive integer.")

        self._request("GET", f"/repos/{self.repository}/pulls/{number}")

        fingerprint, _, body = build_work_item(assessment)
        marker = f"<!-- devsecops-finding:{fingerprint} -->"
        for page in range(1, 11):
            comments = self._request(
                "GET",
                f"/repos/{self.repository}/issues/{number}/comments?"
                f"{urlencode({'per_page': 100, 'page': page})}",
            )
            if not isinstance(comments, list):
                raise GitHubWorkflowError("Unexpected GitHub comments response.")
            for comment in comments:
                if marker in comment.get("body", ""):
                    return {"status": "existing", "url": comment.get("html_url")}
            if len(comments) < 100:
                break
        created = self._request(
            "POST", f"/repos/{self.repository}/issues/{number}/comments", {"body": body}
        )
        return {"status": "comment_created", "url": created["html_url"]}
