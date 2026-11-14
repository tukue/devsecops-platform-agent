"""Release-gate contract for the deterministic AI evaluation benchmark."""
import copy
import json
from pathlib import Path

import pytest

import scripts.evaluate_agent as evaluator

from scripts.evaluate_agent import evaluate


def load_benchmark():
    benchmark_path = Path(__file__).parents[1] / "data" / "benchmark_sets.json"
    return json.loads(benchmark_path.read_text(encoding="utf-8"))


def test_evaluation_benchmark_passes_all_release_thresholds():
    benchmark = load_benchmark()
    report = evaluate(benchmark)

    assert report["passed"], report
    assert all(report["checks"].values())
    assert report["metrics"]["evaluation_coverage"] >= report["thresholds"]["minimum_evaluation_coverage"]


def test_skipped_model_case_is_counted_as_uncovered():
    benchmark = load_benchmark()
    total = sum(len(benchmark[key]) for key in ("classification_benchmarks", "retrieval_benchmarks", "safety_benchmarks"))
    benchmark["classification_benchmarks"].append({
        "id": "CLS-MODEL-ONLY",
        "finding": "An unusual platform condition needs expert review.",
    })

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == total / (total + 1)
    assert report["metrics"]["evaluation_coverage"] >= report["thresholds"]["minimum_evaluation_coverage"]
    skipped = next(case for case in report["cases"] if case["id"] == "CLS-MODEL-ONLY")
    assert skipped["error"] == "Benchmark case has no deterministic rule match."
    assert report["checks"]["evaluation_coverage"] is True
    assert report["passed"] is True


def test_excessive_skipped_model_cases_fail_coverage_gate():
    benchmark = load_benchmark()
    total = sum(len(benchmark[key]) for key in ("classification_benchmarks", "retrieval_benchmarks", "safety_benchmarks"))
    skipped_count = total // 9 + 1
    benchmark["classification_benchmarks"].extend(
        {"id": f"CLS-MODEL-ONLY-{index}",
         "finding": "An unusual platform condition needs expert review."}
        for index in range(skipped_count)
    )

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == total / (total + skipped_count)
    assert report["checks"]["evaluation_coverage"] is False
    assert report["passed"] is False


def test_disabling_zero_tolerance_fails_closed():
    benchmark = copy.deepcopy(load_benchmark())
    benchmark["confidence_calibration"]["release_thresholds"]["safety_zero_tolerance"] = False

    report = evaluate(benchmark)

    assert report["checks"]["safety_zero_tolerance"] is False
    assert report["passed"] is False


def test_single_critical_downgrade_blocks_release_despite_aggregate_accuracy(monkeypatch):
    original = evaluator.EnsembleClassifier.classify
    target = load_benchmark()["classification_benchmarks"][1]["finding"]

    def downgrade(self, finding):
        result = original(self, finding)
        if finding == target:
            result["severity"] = "high"
        return result

    monkeypatch.setattr(evaluator.EnsembleClassifier, "classify", downgrade)
    report = evaluate(load_benchmark())
    assert report["checks"]["severity_accuracy"] is True
    assert report["checks"]["critical_underestimation_zero_tolerance"] is False
    assert report["metrics"]["critical_underestimation_count"] == 1
    case = next(case for case in report["cases"] if case["id"] == "CLS-002")
    assert case["expected"]["severity"] == "critical"
    assert case["actual"]["severity"] == "high"
    assert case["passed"] is False
    assert report["passed"] is False


def test_missing_required_review_blocks_release(monkeypatch):
    monkeypatch.setattr(evaluator, "requires_human_review", lambda result: False)
    report = evaluate(load_benchmark())
    assert report["checks"]["severity_accuracy"] is True
    assert report["checks"]["required_human_review"] is False
    assert report["metrics"]["missing_required_review_count"] > 0
    assert report["passed"] is False


def test_skipped_critical_case_blocks_release_even_when_coverage_passes():
    benchmark = load_benchmark()
    benchmark["classification_benchmarks"].append({
        "id": "CLS-CRITICAL-UNSUPPORTED", "finding": "Unusual platform condition.",
        "expected_severity": "critical", "expected_human_review_required": True,
    })
    report = evaluate(benchmark)
    assert report["checks"]["evaluation_coverage"] is True
    assert report["checks"]["critical_underestimation_zero_tolerance"] is False
    assert report["checks"]["required_human_review"] is False
    assert report["passed"] is False


def test_empty_classification_slice_cannot_pass_safety_gates():
    benchmark = load_benchmark()
    benchmark["classification_benchmarks"] = []
    report = evaluate(benchmark)
    assert report["checks"]["critical_underestimation_zero_tolerance"] is False
    assert report["checks"]["required_human_review"] is False


@pytest.mark.parametrize("severity,confidence,expected", [
    ("critical", 1.0, True), ("high", 1.0, True),
    ("medium", 1.0, False), ("low", 0.59, True), ("low", 0.60, False),
])
def test_shared_review_policy(severity, confidence, expected):
    assert evaluator.requires_human_review({"severity": severity, "confidence": confidence}) is expected


def test_report_excludes_finding_text():
    benchmark = load_benchmark()
    report = evaluate(benchmark)
    encoded = json.dumps(report)
    assert all(row["finding"] not in encoded for row in benchmark["classification_benchmarks"])


def test_incorrect_review_label_cannot_disable_high_severity_policy(monkeypatch):
    benchmark = load_benchmark()
    for row in benchmark["classification_benchmarks"]:
        row["expected_human_review_required"] = False
    monkeypatch.setattr(evaluator, "requires_human_review", lambda result: False)
    report = evaluate(benchmark)
    assert report["metrics"]["required_review_cases_total"] > 0
    assert report["checks"]["required_human_review"] is False
    assert report["passed"] is False


@pytest.mark.parametrize("fail_review,expected_exit", [(False, 0), (True, 1)])
def test_cli_writes_report_and_returns_release_status(monkeypatch, tmp_path, capsys,
                                                     fail_review, expected_exit):
    output = tmp_path / "reports" / "evaluation.json"
    monkeypatch.setattr("sys.argv", ["evaluate_agent.py", "--output", str(output)])
    if fail_review:
        monkeypatch.setattr(evaluator, "requires_human_review", lambda result: False)
    assert evaluator.main() == expected_exit
    written = json.loads(output.read_text())
    assert written["passed"] is (not fail_review)
    assert json.loads(capsys.readouterr().out) == written
