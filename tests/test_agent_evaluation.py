"""Release-gate contract for the deterministic AI evaluation benchmark."""
import json
from pathlib import Path

from scripts.evaluate_agent import evaluate


def test_evaluation_benchmark_passes_all_release_thresholds():
    benchmark_path = Path(__file__).parents[1] / "data" / "benchmark_sets.json"
    report = evaluate(json.loads(benchmark_path.read_text(encoding="utf-8")))

    assert report["passed"], report
    assert all(report["checks"].values())
    assert report["metrics"]["evaluation_coverage"] == 1.0
