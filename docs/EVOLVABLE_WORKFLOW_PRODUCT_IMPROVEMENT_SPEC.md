# Evolvable DevSecOps Workflow Product: Improvement Specification

## Product objective

Evolve the DevSecOps advisor from a manual finding-analysis interface into a
trusted workflow product that helps engineers triage, route, remediate, and
verify platform-security findings. It remains advisory-only: infrastructure
changes stay in reviewed infrastructure-as-code (IaC) and authorized human
workflows.

## Product outcomes

The product must improve at least one of these outcomes with every release:

- faster finding triage;
- clearer ownership and prioritization;
- safer, more actionable remediation;
- lower SRE and DevSecOps operational toil;
- measurable trust in agent recommendations.

## Constraints

- Preserve current manual free-text analysis and existing AWS behavior during
  migration.
- Do not modify cloud resources, IAM permissions, networking, Kubernetes, or
  production deployments.
- Do not log or retain raw findings, prompts, secrets, credentials, PII, or
  response text in telemetry.
- New integrations are read-only by default and use least-privilege credentials.
- High/critical, low-confidence, and policy-sensitive findings require human
  review; they cannot trigger automation.
- Provider-specific logic belongs in adapters. Shared classification uses a
  cloud-agnostic control taxonomy.
- AI-agent behavior changes require at least 90% test coverage for the affected
  scope, plus regression and safety tests.

## Non-goals

- Replacing Security Hub, Defender for Cloud, Security Command Center, or other
  scanners.
- Autonomous remediation or automatic PR merge/deployment.
- Replacing security, SRE, or platform-engineering approval authority.
- Supporting every cloud service in the first multi-cloud release.

## Target workflow

```text
Scanner, CI, or manual finding
  -> provider adapter and validation
  -> canonical finding + control classification
  -> severity, owner, and grounded remediation
  -> PR comment, draft ticket, or advisor response
  -> human review where required
  -> remediation through normal change management
  -> outcome feedback for evaluation
```

## Workstream 1 — Canonical findings and AWS foundation

### Scope

- Define canonical fields: provider, account, region, environment, scanner,
  rule ID, resource type/ID, evidence, category, `control_id`, severity, owner,
  confidence, and source references.
- Keep the existing category values for compatibility; derive them from stable
  control IDs.
- Move AWS-specific parsing and remediation into an AWS adapter.
- Begin with public ingress, least privilege, exposed secrets, encryption,
  privileged containers, and audit logging.

### Acceptance criteria

- Existing AWS regression fixtures retain category, severity, owner, and safe
  advisory behavior.
- Every supported AWS finding produces a non-empty `control_id`, evidence,
  owner, confidence, and validation step.
- Unknown or ambiguous provider input routes to generic guidance and human
  review; it is not assumed to be AWS.
- No infrastructure mutation capability is introduced.

## Workstream 2 — Finding ingestion

### Scope

- Add normalized input adapters for Checkov and Trivy JSON first.
- Add read-only AWS Security Hub/Inspector, Config, GuardDuty, and ECR finding
  adapters after local scanner adapters are stable.
- Preserve manual text entry as a fallback.

### Acceptance criteria

- A semantically equivalent Checkov, Trivy, and free-text finding map to the
  same AWS `control_id`, severity band, and owner.
- Invalid, oversized, secret-bearing, and malformed payloads are blocked or
  redacted safely.
- Connector credentials are least-privilege, read-only, and never exposed in
  responses or telemetry.
- Ingestion failures are observable through aggregate error categories.

## Workstream 3 — Grounded remediation and workflow handoff

### Scope

- Add provider/control/source/version metadata to knowledge documents.
- Retrieve by control first, then provider; return citations, validation, and
  rollback guidance.
- Create GitHub PR comments and draft GitHub issues first; add Jira/ServiceNow
  only after the common workflow contract is stable.

### Acceptance criteria

- A high/critical recommendation includes risk, evidence, owner, remediation,
  validation, rollback/dependency warning, and source citation.
- Retrieval quality meets the agreed benchmark Recall@K and Precision@K target.
- Ticket/PR integrations create drafts or comments only; no changes are applied
  to source code or cloud infrastructure without human approval.
- Duplicate findings are linked or grouped rather than creating duplicate work.

## Workstream 4 — Human review, governance, and observability

### Scope

- Replace the review boolean with states: `not_required`, `pending`,
  `approved`, `rejected`, and `escalated`.
- Add reviewer reason, correction, and disposition feedback.
- Add SSO/RBAC, account or tenant isolation, immutable audit events, and
  privacy-safe telemetry export.

### Acceptance criteria

- High/critical and low-confidence findings always enter `pending` review.
- Only authorized roles can view findings for a tenant/account or change review
  state.
- Audit events capture actor, action, timestamp, finding ID, and outcome, but
  exclude sensitive finding payloads and secrets.
- Dashboards expose error rate, latency, low-confidence rate, review/override
  rate, retrieval no-result rate, and output-safety blocks.

## Workstream 5 — Evaluation and continuous improvement

### Scope

- Maintain expert-labeled AWS regression, adversarial, malformed, ambiguous,
  and cross-source parity benchmark sets.
- Score classification, severity, owner routing, retrieval, remediation quality,
  safety, and confidence calibration.
- Use accepted/rejected human-review outcomes as curated evaluation candidates,
  not automatic training truth.

### Acceptance criteria

- Each AI behavior change reports affected-scope coverage of at least 90%.
- Control classification, severity, and ownership meet agreed release thresholds
  against held-out benchmark cases.
- Unsafe advice, secret leakage, and prompt leakage have a release threshold of
  zero confirmed cases.
- Confidence buckets are reviewed for calibration before model/rule changes ship.

## Workstream 6 — Multi-cloud expansion

### Scope

- Add Azure and GCP as adapters to the canonical model after AWS quality gates
  are stable.
- Start Azure with Entra ID/RBAC, NSGs, Blob Storage, Key Vault, AKS, and
  Activity Logs.
- Start GCP with Cloud IAM, VPC firewall rules, Cloud Storage, Secret Manager,
  GKE, and Cloud Audit Logs.

### Acceptance criteria

- Equivalent AWS, Azure, and GCP findings map to the same canonical control
  unless a documented provider difference applies.
- Provider-specific remediation is validated against cited provider knowledge;
  unsupported cases return generic guidance plus human review.
- Azure and GCP adapters are independently feature-flagged and can be disabled
  without affecting AWS behavior.
- Cross-cloud parity, safety, and affected-scope coverage gates pass before
  enabling a provider by default.

## Delivery sequence

1. Canonical finding model, control IDs, AWS adapter, and AWS regression suite.
2. Checkov/Trivy adapters and grounded AWS RAG metadata.
3. GitHub workflow handoff and structured human review.
4. Governance, telemetry export, and benchmark-driven release process.
5. Azure adapter, then GCP adapter, each behind feature flags.

## Definition of done for an increment

- Scope, owner, risks, and rollback are documented.
- Compatibility, unit, integration, safety, and failure-path tests pass.
- Required coverage and benchmark evidence are attached to the change.
- No secrets or sensitive payloads are added to logs, fixtures, or telemetry.
- Human-review and automation boundaries remain intact.
