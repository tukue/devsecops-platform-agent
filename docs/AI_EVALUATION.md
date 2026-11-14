# AI behavior evaluation

Pull-request CI runs a deterministic evaluation against
`data/benchmark_sets.json`:

```bash
python scripts/evaluate_agent.py --output agent-evaluation-report.json
```

The command exits non-zero when a release threshold is missed. It evaluates:

- category, severity, stable control, and owner accuracy;
- top-3 retrieval recall and precision;
- blocked-input rate for the labeled safety cases; and
- evaluation coverage (the fraction of declared cases actually evaluated).

Thresholds live beside the benchmark data so the examples and release gates are
reviewed together. CI uploads the JSON report as the `agent-evaluation-report`
artifact, including on failure. The report records case IDs and outcomes, not
finding text.

This CI suite intentionally exercises deterministic rule-classification cases
and does not download model weights. Cases that require the zero-shot model are
not silently substituted with model results; add a separate evaluation job with
pinned model revisions, fixed runtime settings, and its own thresholds before
using such cases as release evidence. Keep evaluation examples expert-labeled,
include positive, ambiguous, malformed, and adversarial inputs, and preserve a
held-out set for release evaluation to reduce benchmark overfitting.

## Increment 1: consequential classification errors

The classification benchmark now declares review expectations and includes 17
cases across IAM, network, secrets, containers and data protection. New cases
are developer-proposed regression labels, not independently expert-adjudicated
or held-out release evidence. Security reviewers must validate labels against
the described context before treating scores as production accuracy claims.
Model-only ambiguity and remediation correctness remain outside this slice.

Two mandatory gates supplement aggregate accuracy:

- `critical_underestimation_zero_tolerance`: every expected-critical case must
  be evaluated and classified critical. A single downgrade fails the release.
- `required_human_review`: every case labeled as requiring review must be
  evaluated and require review under the application's shared review policy.
  A skipped case cannot satisfy either gate. Empty critical/review slices fail
  rather than reporting a vacuous pass.

The version-2 report includes critical case totals, evaluated totals,
underestimation count/rate, and missing-review counts. Classification cases
include expected and actual category, severity, control, owner and review flag,
without raw finding text. CI already executes this command and propagates its
nonzero exit status; no additional workflow is needed.

To inspect the report, run:

```bash
python scripts/evaluate_agent.py --output /tmp/agent-evaluation-report.json
```

Regression tests intentionally downgrade one critical prediction and remove
required review to prove release failure despite otherwise passing accuracy.
Coverage tests derive denominators from the declared benchmark size.

This gate evaluates deterministic classification plus the shared review policy;
it does not assert end-to-end UI, scanner, provider-overlay or GitHub behavior.
Benchmark execution coverage is distinct from affected-code test coverage.
Keep classifier changes separate from expected-label changes, document the
reason for label corrections, and do not weaken labels to hide regressions.
