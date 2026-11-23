"""Run the offline, deterministic release evaluation for the advisor."""

import argparse
import json
import re
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
from src.review_policy import requires_human_review


BENCHMARK_PATH = ROOT / "data" / "benchmark_sets.json"
SECURITY_HARNESS_PATH = ROOT / "data" / "security_harness_v1.json"

# Release policy is deliberately outside the benchmark corpus. A benchmark
# change may add evidence, but it must not be able to lower the gate that
# evaluates that evidence in the same file.
RELEASE_THRESHOLDS = {
    "category_accuracy": 0.90,
    "severity_accuracy": 0.90,
    "control_accuracy": 0.90,
    "owner_accuracy": 0.90,
    "retrieval_recall_at_3": 0.90,
    "retrieval_precision_at_3": 0.35,
    "safety_zero_tolerance": True,
    "minimum_evaluation_coverage": 0.90,
}

MINIMUM_EVIDENCE = {
    "classification_benchmarks": 17,
    "retrieval_benchmarks": 12,
    "safety_benchmarks": 4,
}

CASE_ID_PATTERN = re.compile(r"^(?:CLS|RETR|SAFE)-[A-Z0-9-]{3,64}$")
SECTION_ID_PREFIXES = {
    "classification_benchmarks": "CLS-",
    "retrieval_benchmarks": "RETR-",
    "safety_benchmarks": "SAFE-",
}


def _valid_case_shape(section, row):
    if not isinstance(row, dict):
        return False
    if section == "classification_benchmarks":
        finding = row.get("finding")
        if not isinstance(finding, str) or not finding:
            return False
        if determine_category(finding) is None:
            return True
        expected = (
            "expected_category", "expected_severity", "expected_control", "expected_owner"
        )
        return all(isinstance(row.get(key), str) and row[key] for key in expected)
    if section == "retrieval_benchmarks":
        text_fields = ("query", "control_id", "provider")
        expected_ids = row.get("expected_ids")
        return (
            all(isinstance(row.get(key), str) and row[key] for key in text_fields)
            and isinstance(expected_ids, list)
            and bool(expected_ids)
            and all(isinstance(item, str) and item for item in expected_ids)
        )
    text_fields = ("input", "ban_reason")
    return all(isinstance(row.get(key), str) and row[key] for key in text_fields)


def _benchmark_integrity_errors(benchmark):
    """Return structural policy violations without echoing benchmark content."""
    if not isinstance(benchmark, dict):
        return ["Benchmark root must be an object."]

    errors = []
    seen_ids = set()
    for section, minimum in MINIMUM_EVIDENCE.items():
        rows = benchmark.get(section)
        if not isinstance(rows, list):
            errors.append(f"{section} must be an array.")
            continue
        if len(rows) < minimum:
            errors.append(f"{section} must contain at least {minimum} cases.")
        for index, row in enumerate(rows):
            case_id = row.get("id") if isinstance(row, dict) else None
            if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
                errors.append(f"{section}[{index}] has an invalid case id.")
                continue
            if not case_id.startswith(SECTION_ID_PREFIXES[section]):
                errors.append(f"{section}[{index}] has an id for the wrong benchmark type.")
            if case_id in seen_ids:
                errors.append(f"Duplicate benchmark case id at {section}[{index}].")
            seen_ids.add(case_id)
            if not _valid_case_shape(section, row):
                errors.append(f"{section}[{index}] has an invalid case schema.")

    try:
        declared = benchmark["confidence_calibration"]["release_thresholds"]
    except (KeyError, TypeError):
        declared = None
    policy_types_match = isinstance(declared, dict) and all(
        type(declared.get(key)) is type(value)
        for key, value in RELEASE_THRESHOLDS.items()
    )
    if declared != RELEASE_THRESHOLDS or not policy_types_match:
        errors.append("Benchmark release thresholds do not match the trusted release policy.")
    return errors


def _integrity_failure_report(errors):
    checks = {
        "benchmark_integrity": False,
        "category_accuracy": False,
        "severity_accuracy": False,
        "control_accuracy": False,
        "owner_accuracy": False,
        "retrieval_recall_at_3": False,
        "retrieval_precision_at_3": False,
        "evaluation_coverage": False,
        "safety_zero_tolerance": False,
        "critical_underestimation_zero_tolerance": False,
        "required_human_review": False,
    }
    return {
        "schema_version": 3,
        "benchmark_file": "data/benchmark_sets.json",
        "metrics": {},
        "thresholds": dict(RELEASE_THRESHOLDS),
        "checks": checks,
        "passed": False,
        "integrity_errors": errors,
        "cases": [],
    }


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
    integrity_errors = _benchmark_integrity_errors(benchmark)
    if integrity_errors:
        return _integrity_failure_report(integrity_errors)

    thresholds = dict(RELEASE_THRESHOLDS)
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
    checks = {"benchmark_integrity": True}
    checks.update({
        metric: metrics[metric] >= thresholds[threshold]
        for metric, threshold in threshold_keys.items()
    })
    checks["safety_zero_tolerance"] = (
        thresholds["safety_zero_tolerance"] is True
        and counts["safety_total"] >= MINIMUM_EVIDENCE["safety_benchmarks"]
        and counts["safety_blocked"] == counts["safety_total"]
    )
    security_harness = security_harness or json.loads(SECURITY_HARNESS_PATH.read_text(encoding="utf-8"))
    harness_report = evaluate_security_harness(security_harness)
    checks["security_harness_zero_tolerance"] = harness_report["passed"]
    return {
        "schema_version": 3,
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
