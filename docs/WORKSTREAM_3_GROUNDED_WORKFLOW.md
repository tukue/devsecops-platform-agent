# Workstream 3: Grounded remediation and workflow handoff

## Knowledge document contract

Every remediation entry carries a stable `control_id`, provider, source name,
source version, validation procedure, rollback/dependency guidance, and source
references. Entries marked `generic` can apply across providers; provider
specific entries are selected only for the matching provider.

## Retrieval and evaluation

Retrieval ranks exact control matches first, filters to the requested provider
and generic guidance, then applies the existing hybrid TF-IDF/keyword relevance
ranking. Results expose citation IDs, source/version, and references.

The current deterministic benchmark in `tests/test_pipeline.py` covers 12 AWS
and platform-security queries. Its acceptance thresholds are:

- Recall@3 at least 0.90.
- Precision@3 at least 0.35.

These are baseline engineering gates, not a substitute for expert review. As
the knowledge base grows, expand the benchmark and keep a held-out set for
release evaluation.

The runtime observability panel also reports citation coverage, exact-control
hit rate, and provider-compatible source rate. These operational rates expose
grounding regressions on real requests; they do not replace the labeled
Recall@K/Precision@K benchmark. Rates are `null` until their denominator has
observations and are process-local because the current metrics backend is
in-memory.

## Assessment response

Each analysis response exposes risk summary, evidence, owner, remediation,
validation, rollback/dependency guidance, and citations. If retrieval finds no
source, the response does not invent a citation and retains the human-review
signal.

## GitHub workflow handoff

The assessment view provides explicit actions to create a `[Agent draft]`
GitHub issue or post an advisory comment to a pull request. Configure
`GITHUB_TOKEN` as an application secret with repository issue and pull-request
comment permissions, and set the target `owner/repository` in the UI.

The integration fingerprints provider, control, resource/rule, and evidence.
It searches existing issues/comments and reuses matching work rather than
creating duplicates. The marker contains only a digest. Issues are marked
`[Agent draft]`; GitHub issues do not have a native draft state. Comments and
issues contain a review request and do not update source, merge a pull request,
or change cloud infrastructure.

### Secure handoff deployment

Set `GITHUB_HANDOFF_REQUIRE_IDENTITIES=true` for production. Configure
`GITHUB_HANDOFF_IDENTITIES` as a JSON array in deployment secrets, for example:

```json
[{"actor":"alice","token_sha256":["<64-character lowercase SHA-256 digest>"],"repositories":["org/repo"],"actions":["create_issue","comment_pr"],"expires_at":"2027-01-01T00:00:00Z"}]
```

Issue a unique, cryptographically random token (at least 32 random bytes) to
each person over a secure channel; store only its SHA-256 digest in this
configuration. The person supplies the original token in the password field.
These are bearer credentials, so individual attribution depends on keeping them
private. They do not replace organization SSO. Each operation checks identity
scope and expiry as well as the global `GITHUB_ALLOWED_REPOSITORIES` allowlist.
Malformed personal configuration never falls back to the shared token.

For rotation, temporarily include both old and new digests in the person's
`token_sha256` array, distribute the new token, then remove the old digest.
Remove the identity to revoke all its tokens. Update deployment secrets and
restart/redeploy if required by the hosting provider to refresh environment
variables. Credentials are read afresh for each operation. Legacy
`GITHUB_HANDOFF_TOKEN` works only when personal configuration is absent and
mandatory identities are disabled; it cannot identify individual users.

Use a fine-grained, expiring `GITHUB_TOKEN` restricted to the selected
repositories, with Issues write permission and Pull requests read permission
for PR verification/comments. Do not grant contents write or administration
permissions. The application cannot restrict permissions already granted to a
GitHub token: enforce them in GitHub. Rotate this server credential through the
hosting secret store and redeploy; never give it to UI users.

Every handoff attempt emits a structured `github_handoff` log with a unique
event ID, UTC timestamp, actor, action, repository and outcome, including denied
and failed operations and deduplicated results. Tokens and assessment bodies
are excluded. Forward stdout logs to access-controlled centralized storage with
an explicit retention policy; local logs alone are not a durable audit archive.
