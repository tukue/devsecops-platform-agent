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
