import time
import logging
import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

logger = logging.getLogger("devsecops_advisor")

_metrics_lock = threading.Lock()

_metrics = {
    "requests_total": 0,
    "requests_by_category": defaultdict(int),
    "requests_by_severity": defaultdict(int),
    "requests_by_method": defaultdict(int),
    "validation_blocks": 0,
    "validation_blocks_by_reason": defaultdict(int),
    "output_filter_issues": 0,
    "output_filter_issues_by_type": defaultdict(int),
    "rag_retrievals": 0,
    "rag_retrieval_scores": deque(maxlen=1000),
    "ensemble_disagreements": 0,
    "human_review_required": 0,
    "errors": 0,
    "response_times_ms": deque(maxlen=1000),
    "session_count": 0,
    "findings_per_session": defaultdict(int),
}

_trace_id_counter = 0
_trace_lock = threading.Lock()


def _get_trace_id():
    global _trace_id_counter
    with _trace_lock:
        _trace_id_counter += 1
        return f"trace-{_trace_id_counter}-{int(time.time() * 1000)}"


class PerformanceTimer:
    def __init__(self, operation_name, trace_id=None):
        self.operation_name = operation_name
        self.trace_id = trace_id
        self.start_time = None
        self.elapsed_ms = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            elapsed = (time.perf_counter() - self.start_time) * 1000
            self.elapsed_ms = round(elapsed, 2)

            log_data = {
                "operation": self.operation_name,
                "elapsed_ms": self.elapsed_ms,
                "status": "error" if exc_type else "success",
            }
            if self.trace_id:
                log_data["trace_id"] = self.trace_id

            if exc_type:
                log_data["error"] = str(exc_val)
                logger.error("Operation failed: %s", json.dumps(log_data))
            else:
                logger.info("Operation completed: %s", json.dumps(log_data))

            with _metrics_lock:
                _metrics["response_times_ms"].append(self.elapsed_ms)

        return False


def record_request(category, severity, method, trace_id=None):
    with _metrics_lock:
        _metrics["requests_total"] += 1
        _metrics["requests_by_category"][category] += 1
        _metrics["requests_by_severity"][severity] += 1
        _metrics["requests_by_method"][method] += 1

    logger.info("Request recorded: category=%s severity=%s method=%s trace=%s",
                category, severity, method, trace_id)


def record_validation_block(reason):
    with _metrics_lock:
        _metrics["validation_blocks"] += 1
        _metrics["validation_blocks_by_reason"][reason] += 1

    logger.warning("Validation blocked: reason=%s", reason)


def record_output_filter_issue(issue_type):
    with _metrics_lock:
        _metrics["output_filter_issues"] += 1
        _metrics["output_filter_issues_by_type"][issue_type] += 1

    logger.warning("Output filter issue: type=%s", issue_type)


def record_rag_retrieval(score):
    with _metrics_lock:
        _metrics["rag_retrievals"] += 1
        _metrics["rag_retrieval_scores"].append(score)


def record_ensemble_disagreement():
    with _metrics_lock:
        _metrics["ensemble_disagreements"] += 1

    logger.warning("Ensemble disagreement detected")


def record_human_review():
    with _metrics_lock:
        _metrics["human_review_required"] += 1


def record_error(error_type, message):
    with _metrics_lock:
        _metrics["errors"] += 1

    logger.error("Error: type=%s message=%s", error_type, message)


def record_session(session_id):
    with _metrics_lock:
        _metrics["session_count"] += 1


def record_finding_in_session(session_id):
    with _metrics_lock:
        _metrics["findings_per_session"][session_id] += 1


def get_metrics():
    with _metrics_lock:
        scores = list(_metrics["rag_retrieval_scores"])
        times = list(_metrics["response_times_ms"])

        avg_score = round(sum(scores) / len(scores), 4) if scores else 0
        avg_time = round(sum(times) / len(times), 2) if times else 0
        p95_time = round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) >= 20 else avg_time
        p99_time = round(sorted(times)[int(len(times) * 0.99)], 2) if len(times) >= 100 else avg_time

        return {
            "summary": {
                "requests_total": _metrics["requests_total"],
                "validation_blocks_total": _metrics["validation_blocks"],
                "output_filter_issues_total": _metrics["output_filter_issues"],
                "rag_retrievals_total": _metrics["rag_retrievals"],
                "ensemble_disagreements_total": _metrics["ensemble_disagreements"],
                "human_review_required_total": _metrics["human_review_required"],
                "errors_total": _metrics["errors"],
                "sessions_total": _metrics["session_count"],
            },
            "performance": {
                "avg_response_time_ms": avg_time,
                "p95_response_time_ms": p95_time,
                "p99_response_time_ms": p99_time,
                "avg_rag_retrieval_score": avg_score,
            },
            "breakdowns": {
                "by_category": dict(_metrics["requests_by_category"]),
                "by_severity": dict(_metrics["requests_by_severity"]),
                "by_method": dict(_metrics["requests_by_method"]),
                "validation_blocks_by_reason": dict(_metrics["validation_blocks_by_reason"]),
                "output_filter_issues_by_type": dict(_metrics["output_filter_issues_by_type"]),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def get_health_status():
    metrics = get_metrics()
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "request_processing": "ok",
            "validation_layer": "ok",
            "rag_retrieval": "ok",
            "output_filter": "ok",
        },
    }

    error_rate = 0
    if metrics["summary"]["requests_total"] > 0:
        error_rate = metrics["summary"]["errors_total"] / metrics["summary"]["requests_total"]

    if error_rate > 0.1:
        health["status"] = "degraded"
        health["checks"]["request_processing"] = f"high error rate: {error_rate:.1%}"

    avg_time = metrics["performance"]["avg_response_time_ms"]
    if avg_time > 5000:
        health["status"] = "degraded"
        health["checks"]["request_processing"] = f"slow response time: {avg_time}ms"

    block_rate = 0
    if metrics["summary"]["requests_total"] > 0:
        block_rate = (
            metrics["summary"]["validation_blocks_total"]
            / metrics["summary"]["requests_total"]
        )

    if block_rate > 0.5:
        health["status"] = "degraded"
        health["checks"]["validation_layer"] = f"high block rate: {block_rate:.1%}"

    return health


def reset_metrics():
    with _metrics_lock:
        _metrics["requests_total"] = 0
        _metrics["requests_by_category"].clear()
        _metrics["requests_by_severity"].clear()
        _metrics["requests_by_method"].clear()
        _metrics["validation_blocks"] = 0
        _metrics["validation_blocks_by_reason"].clear()
        _metrics["output_filter_issues"] = 0
        _metrics["output_filter_issues_by_type"].clear()
        _metrics["rag_retrievals"] = 0
        _metrics["rag_retrieval_scores"].clear()
        _metrics["ensemble_disagreements"] = 0
        _metrics["human_review_required"] = 0
        _metrics["errors"] = 0
        _metrics["response_times_ms"].clear()
        _metrics["session_count"] = 0
        _metrics["findings_per_session"].clear()

    logger.info("Metrics reset")


def setup_logging(level="INFO", json_format=True):
    handler = logging.StreamHandler()

    if json_format:
        formatter = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","message":"%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    return logger
