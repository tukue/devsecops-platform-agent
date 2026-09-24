# Evolvable DevSecOps Workflow Product: Task Backlog

## Execution rules

- Complete tasks in dependency order unless a task is explicitly marked parallel.
- Preserve current manual AWS analysis until the replacement path passes
  regression tests.
- Treat integrations as read-only and advisory-only.
- Require human review for high/critical, low-confidence, or policy-sensitive
  recommendations.

## Milestone 1 — AWS foundation

### Improvement 1 — Define the canonical finding contract

- Create typed fields for provider, account, region, environment, scanner,
  rule ID, resource type/ID, evidence, category, control ID, severity, owner,
  confidence, and source references.
- Define validation and redaction rules for each field.
- Add serialization/versioning support.

**Depends on:** none  
**Done when:** valid AWS findings normalize successfully; malformed or
secret-bearing fields are rejected/redacted; contract tests pass.

### Improvement 2 — Define AWS control taxonomy

- Add stable controls for IAM, public ingress, public storage, secrets,
  encryption, privileged containers, and logging.
- Map current broad categories to controls without removing existing category
  values.
- Document severity and ownership rules per control.

**Depends on:** Improvement 1  
**Done when:** each supported AWS finding emits one documented `control_id`,
severity, and owner.

### Improvement 3 — Create the AWS provider adapter

- Move AWS service keywords, native finding parsing, and remediation overlays
  out of shared classifier logic.
- Implement adapter selection from explicit provider metadata.
- Provide generic fallback for unknown providers.

**Depends on:** Improvements 1 and 2  
**Done when:** existing AWS behavior remains compatible; unknown providers are
not silently classified as AWS; adapter unit tests pass.

### Improvement 4 — Build AWS regression fixtures

- Capture representative current AWS findings and expected category, control,
  severity, owner, review requirement, and response safety outcome.
- Include IAM, network, data, secrets, container, and logging controls.
- Add low-confidence and malformed cases.

**Depends on:** Improvements 1 and 2  
**Done when:** fixtures run in CI; AWS behavior changes require explicit fixture
updates and review.

## Milestone 2 — Finding ingestion

### Improvement 5 — Implement Checkov JSON adapter

- Parse Checkov JSON findings into the canonical contract.
- Preserve rule ID, file/location, framework, resource, and check result.
- Redact values that can contain secrets.

**Depends on:** Improvements 1 and 3  
**Done when:** equivalent Checkov and free-text AWS findings resolve to the same
control, severity band, and owner.

### Improvement 6 — Implement Trivy JSON adapter

- Parse IaC, container, and secret findings into the canonical contract.
- Normalize image, package, CVE, resource, and severity information.
- Distinguish vulnerability findings from configuration findings.

**Depends on:** Improvements 1 and 3  
**Done when:** Trivy inputs are validated, safely redacted, and routed through
the same assessment response contract.

### Improvement 7 — Add AWS security-service adapters

- Add read-only adapters for Security Hub/Inspector first.
- Add Config, GuardDuty, and ECR adapters after Security Hub parity is proven.
- Map native ARN, account, region, product, generator/rule ID, and evidence.

**Depends on:** Improvements 1 through 6  
**Done when:** adapter tests use recorded sanitized fixtures; connector failure
is observable; no write API permissions are required.

### Improvement 8 — Preserve manual input fallback

- Keep the current Gradio text path and map it through the generic/AWS adapter.
- Add a provider selector only when provider inference is ambiguous.

**Depends on:** Improvements 1 and 3  
**Done when:** current sample inputs and user workflow still work unchanged.

## Milestone 3 — Grounded remediation

### Improvement 9 — Version and enrich knowledge documents

- Add provider, control ID, source URL, version/effective date, owner,
  validation, dependency, and rollback metadata.
- Define schema validation for knowledge documents.

**Depends on:** Improvement 2  
**Done when:** invalid documents fail validation; every supported AWS control has
at least one versioned knowledge source.

### Improvement 10 — Add provider/control-aware retrieval

- Filter candidates by canonical control before ranking.
- Boost matching provider and resource type.
- Return source IDs and relevance with the response.

**Depends on:** Improvements 1, 2, and 9  
**Done when:** retrieval benchmark meets approved Recall@K and Precision@K
targets; no-result behavior returns safe generic guidance.

### Improvement 11 — Implement structured remediation response

- Return risk, evidence, owner, remediation actions, validation, rollback,
  source citations, confidence, and review state.
- Retain current response fields for compatibility.

**Depends on:** Improvements 1, 9, and 10  
**Done when:** high/critical AWS responses contain all required sections and pass
output safety checks.

## Milestone 4 — Workflow and human review

### Improvement 12 — Add GitHub PR comment integration

- Create a read-only event receiver for supported CI finding payloads.
- Post idempotent, structured PR comments; avoid duplicate comments.
- Link source, owner, severity, and review state.

**Depends on:** Improvement 5 or 6, and Improvement 11  
**Done when:** a test PR finding produces one safe advisory comment; the agent
cannot push commits, merge PRs, or change infrastructure.

### Improvement 13 — Add draft issue/ticket handoff

- Define a provider-neutral ticket payload.
- Create draft GitHub issues first; add Jira/ServiceNow adapters later.
- Group duplicate findings by control/resource/environment.

**Depends on:** Improvements 11 and 12  
**Done when:** high/critical findings create deduplicated drafts with evidence,
owner, remediation, validation, and source references.

### Improvement 14 — Implement human-review state machine

- Replace boolean review flag with `not_required`, `pending`, `approved`,
  `rejected`, and `escalated`.
- Store reviewer identity, timestamp, reason, and corrected outcome.

**Depends on:** Improvement 11  
**Done when:** high/critical and low-confidence findings enter `pending`; only
authorized reviewers can transition state.

## Milestone 5 — Governance, observability, and evaluation

### Improvement 15 — Add identity, tenancy, and audit model

- Add SSO/OIDC authentication and role-based access control.
- Isolate findings by tenant/account/project.
- Create immutable, redacted audit events.

**Depends on:** Improvements 12 through 14  
**Done when:** authorization and tenant-boundary tests pass; audit records never
include raw secrets, prompts, or sensitive finding content.

### Improvement 16 — Export privacy-safe telemetry

- Replace process-local-only monitoring with OpenTelemetry-compatible metrics
  and traces.
- Track error, latency, no-result retrieval, low-confidence, review/override,
  and safety-block rates.
- Configure alert thresholds and runbook links.

**Depends on:** Improvements 1 and 11  
**Done when:** dashboards and alerts use aggregate data only; telemetry tests
confirm sensitive payloads are excluded.

### Improvement 17 — Build expert evaluation harness

- Create labeled AWS regression, cross-source parity, adversarial, malformed,
  benign, and ambiguous evaluation datasets.
- Calculate control macro F1, severity agreement, owner accuracy, Recall@K,
  Precision@K, safe-and-correct rate, and confidence calibration.
- Add reviewer adjudication workflow for disputed labels.

**Depends on:** Improvements 4, 10, 11, and 14  
**Done when:** a reproducible report is generated for releases and agent changes
meet the agreed thresholds and 90% affected-scope coverage.

## Milestone 6 — Multi-cloud expansion

### Improvement 18 — Add Azure adapter and benchmark set

- Support Entra ID/RBAC, NSGs, Blob Storage, Key Vault, AKS, and Activity Logs.
- Add Azure remediation overlays and parity fixtures against AWS controls.
- Guard rollout with `ENABLE_AZURE_ADAPTER`.

**Depends on:** Improvements 1 through 4, 9 through 11, and 17  
**Done when:** equivalent AWS/Azure findings share `control_id`; Azure can be
disabled independently; parity and safety tests pass.

### Improvement 19 — Add GCP adapter and benchmark set

- Support Cloud IAM, VPC firewall rules, Cloud Storage, Secret Manager, GKE,
  and Cloud Audit Logs.
- Add GCP remediation overlays and AWS/Azure/GCP parity fixtures.
- Guard rollout with `ENABLE_GCP_ADAPTER`.

**Depends on:** Improvements 1 through 4, 9 through 11, and 17  
**Done when:** equivalent three-cloud findings share `control_id`; GCP can be
disabled independently; parity and safety tests pass.

### Improvement 20 — Run multi-cloud production readiness review

- Review adapter coverage, evaluation results, authorization, telemetry,
  rollback flags, knowledge-source freshness, and incident runbooks.
- Approve or defer provider default enablement.

**Depends on:** Improvements 15 through 19  
**Done when:** all provider release gates are signed off and the fallback to
generic advisory guidance has been tested.

## Parallel work

- Improvement 4 can run alongside Improvement 3 after Improvements 1 and 2 are agreed.
- Improvements 5 and 6 can run in parallel.
- Improvement 9 can begin after Improvement 2 and run alongside ingestion work.
- Improvement 16 can start once the canonical event taxonomy from Improvement 1 is stable.

## First delivery slice

Deliver Improvements 1, 2, 3, 4, 5, 8, 9, and 11 first. This creates an AWS-focused,
compatible, evaluated workflow path from a Checkov finding to grounded advisory
guidance without cloud write access.
