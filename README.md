---
title: Platform Engineering DevSecOps Advisor
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
python_version: "3.10"
app_file: app.py
fullWidth: true
short_description: AI security triage for Platform Engineering and SRE teams.
---

# Platform Engineering DevSecOps Advisor

A lightweight AI-assisted advisor that helps Platform Engineering and Site Reliability Engineering (SRE) teams turn infrastructure security findings into consistent, actionable remediation guidance.

The application accepts a finding, classifies it across common platform-security domains, assigns a severity, recommends a remediation path, and identifies the responsible platform team. It is advisory only: it does not modify infrastructure, deploy changes, or make access-control decisions.

## Live Deployment

Run the advisor in Hugging Face Spaces: [platform-eng-agent-advisor](https://huggingface.co/spaces/Tukue/platform-eng-agent-advisor).

## Business Need

Modern engineering organizations operate across cloud infrastructure, Kubernetes, CI/CD systems, identity platforms, and data services. This scale creates a continuous stream of security findings, many of which are difficult to prioritize and route correctly.

Without clear context, teams face predictable problems:

- **Slower delivery:** Developers pause work to interpret security alerts or wait for specialist review.
- **Inconsistent remediation:** Similar issues are fixed differently across teams, creating operational and audit risk.
- **Alert fatigue:** High volumes of low-context findings hide the issues that could affect customer data, availability, or revenue.
- **SRE overload:** Reliability teams spend time triaging misconfigurations rather than improving resilience and service health.
- **Security bottlenecks:** Central security teams become the default router for routine platform questions.

This advisor standardizes the first response to infrastructure risk. It gives teams an immediately understandable explanation and a practical next action, helping them resolve issues earlier in the delivery lifecycle.

## How It Helps Platform Engineering

Platform Engineering teams build the paved roads that enable product teams to ship safely. The advisor supports that mission by:

- **Embedding guardrails in workflows:** It can be used alongside pull requests, infrastructure-as-code reviews, CI/CD checks, and platform support tickets.
- **Improving secure defaults:** Recommendations reinforce least privilege, network segmentation, non-root containers, secret rotation, and encryption.
- **Standardizing ownership:** Each finding is routed to a relevant platform domain such as Cloud Platform, Container Platform, Data Platform, or Platform Security.
- **Accelerating self-service:** Developers receive repeatable guidance before escalating routine questions to platform specialists.
- **Supporting platform adoption:** Clear, consistent advice makes paved-road patterns easier for teams to understand and follow.

## How It Helps SRE Teams

SRE teams balance reliability, operational risk, and engineering velocity. The advisor contributes by:

- **Reducing toil:** It provides a standardized initial triage for common configuration and security findings.
- **Protecting service reliability:** It identifies risky patterns—such as publicly exposed services, privileged workloads, and weak identity controls—that can lead to incidents.
- **Supporting risk-based prioritization:** High and critical findings are flagged for human review, allowing experts to focus on material risk.
- **Improving incident readiness:** Its remediation advice can be used to create consistent runbook steps and escalation paths.
- **Strengthening service ownership:** Recommended owners make it easier to route follow-up work to the team best positioned to resolve it.

## Current Capabilities

| Area | Advisor behavior | Example guidance |
| --- | --- | --- |
| IAM | Detects risky permission and authentication patterns. | Apply least privilege, remove wildcard permissions, and require MFA. |
| Network security | Identifies overly broad ingress and segmentation gaps. | Limit ports and CIDRs; add workload segmentation and NetworkPolicies. |
| Container security | Reviews dangerous workload configurations. | Use patched minimal images, run as non-root, drop capabilities, and scan in CI. |
| Secrets management | Detects exposed or hard-coded credentials. | Revoke and rotate the secret, remove it from history, and use a managed store. |
| Data protection | Identifies encryption and access-control gaps. | Encrypt data, restrict access, enable auditing, and protect backups. |

## Decision Model and Safety

The advisor evaluates a submitted finding with two controls:

1. **Severity rules** identify known high-risk indicators, including public exposure, wildcard permissions, root access, privileged containers, and committed secrets.
2. **AI classification** assigns the finding to its most relevant platform-security domain and returns a confidence score.

High- and critical-severity results, and results below the confidence threshold, require human review. Automation is disabled by design. Teams must validate recommendations against their environment, change-management process, and approved security policies before acting.

## Example Workflow

1. An engineer submits: “The production security group allows SSH from `0.0.0.0/0`.”
2. The advisor categorizes the issue as **Network**, marks it **critical**, assigns it to **Cloud Platform**, and recommends restricting ingress to approved, trusted access paths.
3. The assigned team validates the exposure, remediates through infrastructure-as-code, and runs the normal deployment and verification process.
4. The result is recorded in the ticket or change record, including the decision and evidence of remediation.

## Expected Business Outcomes

- Shorter mean time to triage and remediate platform-security findings.
- Fewer production risks caused by insecure infrastructure defaults.
- Lower interruption load on Platform Engineering, SRE, and Security teams.
- More consistent remediation evidence for audits and compliance reviews.
- Better developer experience through clear self-service security guidance.

## Run Locally

### Prerequisites

- Python 3.10 or later
- Internet access for the initial download of the Hugging Face model

### Setup

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python app.py
```

Open the local Gradio address shown in the terminal, normally `http://127.0.0.1:7860`.

## Roadmap

- Add policy-as-code and approved organizational standards as grounded context.
- Integrate with CI/CD, infrastructure-as-code scanners, ticketing, and alert-management tools.
- Include asset criticality, environment, and service ownership in risk prioritization.
- Add test suites and evaluation datasets to measure recommendation accuracy and false positives.
- Create audit-ready records for findings, approvals, exceptions, and remediation outcomes.

## Governance Principles

- Keep infrastructure access read-only by default.
- Do not expose secrets or sensitive customer data to the model.
- Require human approval for production changes and risk exceptions.
- Log recommendations, decisions, and policy sources for traceability.
- Review accuracy, false positives, and security controls before expanding adoption.
