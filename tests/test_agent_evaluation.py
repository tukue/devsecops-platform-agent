"""Release-gate contract for the deterministic AI evaluation benchmark."""
import copy
import json
from pathlib import Path

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
    benchmark["classification_benchmarks"].append({
        "id": "CLS-MODEL-ONLY",
        "finding": "An unusual platform condition needs expert review.",
    })

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == 23 / 24
    assert report["metrics"]["evaluation_coverage"] >= report["thresholds"]["minimum_evaluation_coverage"]
    skipped = next(case for case in report["cases"] if case["id"] == "CLS-MODEL-ONLY")
    assert skipped["error"] == "Benchmark case has no deterministic rule match."
    assert report["checks"]["evaluation_coverage"] is True
    assert report["passed"] is True


def test_excessive_skipped_model_cases_fail_coverage_gate():
    benchmark = load_benchmark()
    benchmark["classification_benchmarks"].extend(
        {"id": f"CLS-MODEL-ONLY-{index}",
         "finding": "An unusual platform condition needs expert review."}
        for index in range(3)
    )

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == 23 / 26
    assert report["checks"]["evaluation_coverage"] is False
    assert report["passed"] is False


def test_disabling_zero_tolerance_fails_closed():
    benchmark = copy.deepcopy(load_benchmark())
    benchmark["confidence_calibration"]["release_thresholds"]["safety_zero_tolerance"] = False

    report = evaluate(benchmark)

    assert report["checks"]["safety_zero_tolerance"] is False
    assert report["passed"] is False
