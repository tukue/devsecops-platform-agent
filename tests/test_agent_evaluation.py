"""Release-gate contract for the deterministic AI evaluation benchmark."""
import copy
import importlib
import json
import math
import sys
from pathlib import Path

from scripts.evaluate_agent import evaluate


def load_benchmark():
    benchmark_path = Path(__file__).parents[1] / "data" / "benchmark_sets.json"
    return json.loads(benchmark_path.read_text(encoding="utf-8"))


def benchmark_total(benchmark):
    return sum(len(benchmark[key]) for key in (
        "classification_benchmarks", "retrieval_benchmarks", "safety_benchmarks"
    ))


def test_importing_evaluator_preserves_sys_path():
    import scripts.evaluate_agent as evaluator

    original_path = sys.path[:]
    try:
        importlib.reload(evaluator)
        assert sys.path == original_path
    finally:
        sys.path[:] = original_path


def test_evaluation_benchmark_passes_all_release_thresholds():
    benchmark = load_benchmark()
    report = evaluate(benchmark)

    assert report["passed"], report
    assert all(report["checks"].values())
    assert report["metrics"]["evaluation_coverage"] >= report["thresholds"]["minimum_evaluation_coverage"]


def test_skipped_model_case_is_counted_as_uncovered():
    benchmark = load_benchmark()
    base_total = benchmark_total(benchmark)
    benchmark["classification_benchmarks"].append({
        "id": "CLS-MODEL-ONLY",
        "finding": "An unusual platform condition needs expert review.",
    })

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == base_total / (base_total + 1)
    assert report["metrics"]["evaluation_coverage"] >= report["thresholds"]["minimum_evaluation_coverage"]
    skipped = next(case for case in report["cases"] if case["id"] == "CLS-MODEL-ONLY")
    assert skipped["error"] == "Benchmark case has no deterministic rule match."
    assert report["checks"]["evaluation_coverage"] is True
    assert report["passed"] is True


def test_excessive_skipped_model_cases_fail_coverage_gate():
    benchmark = load_benchmark()
    base_total = benchmark_total(benchmark)
    threshold = benchmark["confidence_calibration"]["release_thresholds"]["minimum_evaluation_coverage"]
    skipped_total = math.floor(base_total / threshold - base_total) + 1
    benchmark["classification_benchmarks"].extend(
        {"id": f"CLS-MODEL-ONLY-{index}",
         "finding": "An unusual platform condition needs expert review."}
        for index in range(skipped_total)
    )

    report = evaluate(benchmark)

    assert report["metrics"]["evaluation_coverage"] == base_total / (base_total + skipped_total)
    assert report["checks"]["evaluation_coverage"] is False
    assert report["passed"] is False


def test_disabling_zero_tolerance_fails_closed():
    benchmark = copy.deepcopy(load_benchmark())
    benchmark["confidence_calibration"]["release_thresholds"]["safety_zero_tolerance"] = False

    report = evaluate(benchmark)

    assert report["checks"]["safety_zero_tolerance"] is False
    assert report["passed"] is False
