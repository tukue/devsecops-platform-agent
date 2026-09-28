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
