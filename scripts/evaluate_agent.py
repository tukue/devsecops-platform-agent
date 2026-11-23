"""Run the offline, deterministic release evaluation for the advisor."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ensemble import EnsembleClassifier, determine_category
from src.controls import resolve_control
from src.findings import canonicalize_finding
from src.ingestion import normalize_payload
from src.input_validation import validate_input
from src.output_filter import filter_output
from src.retriever import SecurityRetriever


BENCHMARK_PATH = ROOT / "data" / "benchmark_sets.json"
SECURITY_HARNESS_PATH = ROOT / "data" / "security_harness_v1.json"


def _accuracy(correct, total):
    return correct / total if total else 0.0


def _safe_case_id(row, kind, passed, **details):
    """Keep reports privacy-safe: include identifiers and outcomes, never inputs."""
    return {"id": row["id"], "kind": kind, "passed": passed, **details}


def evaluate_security_harness(harness):
    """Evaluate adversarial, leakage, output, parity, and review-boundary cases."""
    if harness.get("schema_version") != "1.0":
        raise ValueError("Unsupported security harness schema version.")

    cases = []
    for row in harness["input_adversarial_cases"]:
        accepted, _, _ = validate_input(row["input"], client_id="security-harness-" + row["id"])
        cases.append(_safe_case_id(row, "input_adversarial", not accepted,
                                  expected_block=row["expected_block"]))

    for row in harness["redaction_cases"]:
        canonical = canonicalize_finding(
            row["finding"],
            {"category": "Secrets", "severity": "high", "confidence": 0.8},
            {"id": "secrets.exposure", "owner": "Platform Security"},
            row.get("metadata", {}),
        ).to_dict()
        filtered = filter_output(row["recommendation"])["filtered_text"]
        serialized = json.dumps(canonical, sort_keys=True) + filtered
        passed = all(value not in serialized for value in row["must_redact"])
        cases.append(_safe_case_id(row, "redaction", passed,
                                  redactions_expected=len(row["must_redact"])))

    for row in harness["unsafe_remediation_cases"]:
        filtered = filter_output(row["recommendation"])
        passed = not filtered["safe"] and all(
            value.lower() not in filtered["filtered_text"].lower()
            for value in row["forbidden_phrases"]
        )
        cases.append(_safe_case_id(row, "unsafe_remediation", passed,
                                  expected_block=row["expected_block"]))

    for row in harness["cross_source_parity_cases"]:
        normalized = []
        for source in row["sources"]:
            if source["source"] == "manual":
                normalized.append((source["finding"], source.get("metadata", {})))
            else:
                normalized.extend(normalize_payload(source["source"], source["payload"]))
        outcomes = []
        for finding, metadata in normalized:
            category = determine_category(finding)
            control = resolve_control(finding, category)
            outcomes.append((category, control["id"] if control else "unclassified", control["owner"] if control else None))
        expected = (row["expected_category"], row["expected_control"], row["expected_owner"])
        cases.append(_safe_case_id(row, "cross_source_parity",
                                  bool(outcomes) and all(outcome == expected for outcome in outcomes),
                                  sources_evaluated=len(outcomes)))

    for row in harness["ambiguous_review_cases"]:
        category = determine_category(row["finding"])
        confidence = 0.0 if category is None else 1.0
        requires_review = category is None or confidence < row["minimum_confidence"]
        cases.append(_safe_case_id(row, "ambiguous_review",
                                  requires_review == row["requires_review"],
                                  deterministic_category=category is not None))

    grouped = {}
    for case in cases:
        grouped.setdefault(case["kind"], []).append(case)
    checks = {kind: all(case["passed"] for case in rows) for kind, rows in grouped.items()}
    return {"schema_version": harness["schema_version"], "cases": cases, "checks": checks,
            "passed": all(checks.values()), "total": len(cases)}


def evaluate(benchmark, security_harness=None):
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

    for row in benchmark["classification_benchmarks"]:
        counts["benchmark_total"] += 1
        finding = row["finding"]
        # Do not load model weights in CI. Model-fallback cases require a separate,
        # pinned model evaluation job and are deliberately not scored by this gate.
        if determine_category(finding) is None:
            cases.append({"id": row["id"], "kind": "classification", "passed": False,
                          "error": "Benchmark case has no deterministic rule match."})
            continue
        result = classifier.classify(finding)
        counts["evaluated_total"] += 1
        counts["classification_total"] += 1
        fields = {
            "category": result["category"] == row["expected_category"],
            "severity": result["severity"] == row["expected_severity"],
            "control": result["control_id"] == row["expected_control"],
            "owner": result["owner"] == row["expected_owner"],
        }
        counts["category_correct"] += fields["category"]
        counts["severity_correct"] += fields["severity"]
        counts["control_correct"] += fields["control"]
        counts["owner_correct"] += fields["owner"]
        cases.append({"id": row["id"], "kind": "classification", "passed": all(fields.values()),
                      "checks": fields, "method": result["method"]})

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
    security_harness = security_harness or json.loads(SECURITY_HARNESS_PATH.read_text(encoding="utf-8"))
    harness_report = evaluate_security_harness(security_harness)
    checks["security_harness_zero_tolerance"] = harness_report["passed"]
    return {
        "schema_version": 1,
        "benchmark_file": "data/benchmark_sets.json",
        "metrics": metrics,
        "thresholds": thresholds,
        "checks": checks,
        "security_harness": harness_report,
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
