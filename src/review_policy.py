"""Shared advisory review policy used by the application and evaluation."""


def requires_human_review(classification):
    return (classification["severity"] in {"high", "critical"}
            or classification["confidence"] < 0.60)
