# Assess an AWS Security Hub export

This workflow lets a DevSecOps engineer review exported AWS evidence without
providing cloud credentials to the advisor. It supports the AWS Security Finding
Format (ASFF) returned by `aws securityhub get-findings`, not arbitrary inventory
JSON or the different `get-findings-v2` schema.

## First assessment

1. Start the app using the README's local setup instructions.
2. For a credential-free trial, upload `tests/fixtures/security_hub_export.json`.
3. Expand **Upload scanner export (JSON)** and select **security_hub**.
4. Click **Preview import scope**. Check accounts, regions represented, status
   counts, rejected rows, and continuation warnings before proceeding.
5. Click **Analyze uploaded findings**. The Assessment JSON contains an updated
   `import_summary`, actionable `results`, `assessment_errors`, and
   `excluded_findings`. Recommendations remain advisory; validate production
   changes through your normal infrastructure-as-code and review process.

To export real findings, use an existing AWS CLI profile authorized to call
`securityhub:GetFindings`, with Security Hub enabled in the selected region:

```bash
aws securityhub get-findings \
  --profile startup-readonly \
  --region eu-north-1 \
  --output json \
  --no-cli-pager > securityhub-findings.json
```

Keep the top-level `Findings` object. Do not use `--query 'Findings'`, which
produces an incompatible bare array. AWS CLI pagination retrieves matching
results automatically; do not disable pagination for a complete export. If you
use an aggregation home region, linked regions may also be represented.

References: [AWS CLI get-findings](https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html),
[AWS workflow statuses](https://docs.aws.amazon.com/securityhub/latest/userguide/findings-workflow-status.html),
[AWS compliance statuses](https://docs.aws.amazon.com/securityhub/latest/userguide/controls-overall-status.html).

## Interpreting the import

Each valid, unique finding has one disposition, using the following precedence:

| Disposition | Source condition | Assessment behavior |
| --- | --- | --- |
| Archived | `RecordState=ARCHIVED` | Retained, not classified |
| Suppressed | `Workflow.Status=SUPPRESSED` | Retained, not classified |
| Passed | `Compliance.Status=PASSED` | Retained as source evidence, not classified |
| Resolved | `Workflow.Status=RESOLVED` | Retained, not classified |
| Unknown check | `Compliance.Status=WARNING` or `NOT_AVAILABLE` | Retained as a coverage gap, not classified |
| Actionable | Other supported records, including records without compliance status | Sent for advisory assessment |

These are import dispositions, not a computed account-wide control status.
Missing compliance status never becomes a pass. Review unknown-check records
alongside actionable findings; a check that could not run needs investigation.

The canonical `finding` preserves product ARN, finding ID, account, region, all
resource identities (ID/type/region/partition), AWS severity, workflow,
compliance, record state, and source timestamps. Detailed resource configurations
and arbitrary provider fields are intentionally not copied. AWS severity stays
in `native_severity`; `severity` is the advisor's heuristic assessment and may
differ. Confidence is not an accuracy guarantee.

Duplicates use `(ProductArn, Id)` and keep the first valid occurrence within the
upload. For conflicting snapshots, export the latest source state before import.
Records missing either identity are retained with a warning and are not deduplicated.
Invalid rows are reported by zero-based index without discarding valid siblings.
No findings or identities are persisted across imports for deduplication.

## Limits and coverage

- Maximum upload: 1 MB; maximum Security Hub records: 500. Larger exports must be
  split into JSON objects, each containing its own `Findings` array. Oversized
  uploads are rejected rather than silently truncated.
- A nonempty `NextToken` marks the export as partial. The advisor does not fetch
  remaining pages or contact AWS.
- Existing input validation and rate limits still apply to each actionable
  finding. Inspect `assessment_error_count` and `assessment_errors`; an imported
  record is not necessarily a successfully assessed record. Large batches may
  require smaller uploads spaced according to the existing rate limit.
- The preview shows source accounts and regions, not proof of complete account,
  regional, control, or resource coverage. Disabled controls and unscanned
  resources cannot be discovered from this export.
- An empty export does not establish a secure environment.
- Review and sanitize exports before sharing them. Exported account IDs, resource
  identifiers, and descriptions can be sensitive. Use a controlled local
  deployment for internal findings; do not upload them to the public demo.

This release provides scope preview and structured JSON results. It does not
add live discovery, scan comparison, persistent assessment storage, or a human
readable downloadable report.
