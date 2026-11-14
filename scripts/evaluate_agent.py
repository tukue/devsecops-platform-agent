"""Run the offline, deterministic release evaluation for the advisor."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ensemble import EnsembleClassifier, determine_category
from src.input_validation import validate_input
from src.retriever import SecurityRetriever
from src.review_policy import requires_human_review


BENCHMARK_PATH = ROOT / "data" / "benchmark_sets.json"


def _accuracy(correct, total):
    return correct / total if total else 0.0


def evaluate(benchmark):
    """Evaluate rule classification, retrieval relevance, and input blocking."""
    thresholds = benchmark["confidence_calibration"]["release_thresholds"]
    classifier = EnsembleClassifier()
    retriever = SecurityRetriever(top_k=3)
    counts = {
        "category_correct": 0, "severity_correct": 0,
        "control_correct": 0, "owner_correct": 0,
        "classification_total": 0, "retrieval_relevant": 0,
        "retrieval_total": 0, "retrieval_expected_total": 0,
        "safety_blocked": 0,
        "safety_total": 0, "evaluated_total": 0, "benchmark_total": 0,
    }
    cases = []
    critical_total = 0
    critical_evaluated = 0
    critical_underestimated = 0
    review_total = 0
    review_evaluated = 0
    review_missing = 0

    for row in benchmark["classification_benchmarks"]:
        counts["benchmark_total"] += 1
        finding = row["finding"]
        expected_critical = row.get("expected_severity") == "critical"
        expected_review = (row.get("expected_severity") in {"high", "critical"}
                           or row.get("expected_human_review_required", False))
        critical_total += expected_critical
        review_total += expected_review
        # Do not load model weights in CI. Model-fallback cases require a separate,
        # pinned model evaluation job and are deliberately not scored by this gate.
        if determine_category(finding) is None:
            cases.append({"id": row["id"], "kind": "classification", "passed": False,
                          "error": "Benchmark case has no deterministic rule match."})
            continue
        result = classifier.classify(finding)
        actual_review = requires_human_review(result)
        critical_evaluated += expected_critical
        critical_underestimated += expected_critical and result["severity"] != "critical"
        review_evaluated += expected_review
        review_missing += expected_review and not actual_review
        counts["evaluated_total"] += 1
        counts["classification_total"] += 1
        fields = {
            "category": result["category"] == row["expected_category"],
            "severity": result["severity"] == row["expected_severity"],
            "control": result["control_id"] == row["expected_control"],
            "owner": result["owner"] == row["expected_owner"],
            "human_review": actual_review == expected_review,
            "critical_not_underestimated": not expected_critical or result["severity"] == "critical",
        }
        counts["category_correct"] += fields["category"]
        counts["severity_correct"] += fields["severity"]
        counts["control_correct"] += fields["control"]
        counts["owner_correct"] += fields["owner"]
        cases.append({"id": row["id"], "kind": "classification", "passed": all(fields.values()),
                      "checks": fields, "method": result["method"],
                      "expected": {
                          "category": row["expected_category"], "severity": row["expected_severity"],
                          "control": row["expected_control"], "owner": row["expected_owner"],
                          "human_review_required": expected_review,
                      },
                      "actual": {
                          "category": result["category"], "severity": result["severity"],
                          "control": result["control_id"], "owner": result["owner"],
                          "human_review_required": actual_review,
                      }})

    for row in benchmark["retrieval_benchmarks"]:
        counts["benchmark_total"] += 1
        results = retriever.retrieve(
            row["query"], top_k=3, control_id=row["control_id"], provider=row["provider"]
        )
        counts["evaluated_total"] += 1
        relevant = sum(item["id"] in row["expected_ids"] for item in results)
        counts["retrieval_relevant"] += relevant
        counts["retrieval_total"] += len(results)
        counts["retrieval_expected_total"] += len(row["expected_ids"])
        cases.append({"id": row["id"], "kind": "retrieval",
                      "passed": relevant == len(row["expected_ids"]),
                      "relevant_results": relevant, "expected_relevant_results": len(row["expected_ids"]),
                      "returned_results": len(results)})

    for row in benchmark["safety_benchmarks"]:
        counts["benchmark_total"] += 1
        accepted, _, _ = validate_input(row["input"], client_id="evaluation-" + row["id"])
        blocked = not accepted
        counts["evaluated_total"] += 1
        counts["safety_total"] += 1
        counts["safety_blocked"] += blocked
        cases.append({"id": row["id"], "kind": "safety", "passed": blocked,
                      "expected_block": row["ban_reason"]})

    metrics = {
        "category_accuracy": _accuracy(counts["category_correct"], counts["classification_total"]),
        "severity_accuracy": _accuracy(counts["severity_correct"], counts["classification_total"]),
        "control_accuracy": _accuracy(counts["control_correct"], counts["classification_total"]),
        "owner_accuracy": _accuracy(counts["owner_correct"], counts["classification_total"]),
        "retrieval_recall_at_3": _accuracy(counts["retrieval_relevant"], counts["retrieval_expected_total"]),
        "retrieval_precision_at_3": _accuracy(counts["retrieval_relevant"], counts["retrieval_total"]),
        "safety_block_rate": _accuracy(counts["safety_blocked"], counts["safety_total"]),
        "evaluation_coverage": _accuracy(counts["evaluated_total"], counts["benchmark_total"]),
    }
    metrics.update({
        "critical_cases_total": critical_total,
        "critical_cases_evaluated": critical_evaluated,
        "critical_underestimation_count": critical_underestimated,
        "critical_underestimation_rate": _accuracy(critical_underestimated, critical_evaluated),
        "required_review_cases_total": review_total,
        "required_review_cases_evaluated": review_evaluated,
        "missing_required_review_count": review_missing,
    })
    threshold_keys = {
        "category_accuracy": "category_accuracy",
        "severity_accuracy": "severity_accuracy",
        "control_accuracy": "control_accuracy",
        "owner_accuracy": "owner_accuracy",
        "retrieval_recall_at_3": "retrieval_recall_at_3",
        "retrieval_precision_at_3": "retrieval_precision_at_3",
        "evaluation_coverage": "minimum_evaluation_coverage",
    }
    checks = {
        metric: metrics[metric] >= thresholds[threshold]
        for metric, threshold in threshold_keys.items()
    }
    checks["safety_zero_tolerance"] = (
        thresholds["safety_zero_tolerance"] is True
        and counts["safety_blocked"] == counts["safety_total"]
    )
    # These safety invariants cannot be weakened by tuning aggregate thresholds.
    # Require evidence: empty or skipped safety-critical slices cannot pass.
    checks["critical_underestimation_zero_tolerance"] = (
        critical_total > 0 and critical_evaluated == critical_total
        and critical_underestimated == 0
    )
    checks["required_human_review"] = (
        review_total > 0 and review_evaluated == review_total and review_missing == 0
    )
    return {
        "schema_version": 2,
        "benchmark_file": "data/benchmark_sets.json",
        "metrics": metrics,
        "thresholds": thresholds,
        "checks": checks,
        "passed": all(checks.values()),
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional path to write the JSON evaluation report.")
    args = parser.parse_args()
    benchmark = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    report = evaluate(benchmark)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
