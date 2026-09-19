from collections import OrderedDict
import time


class ConversationMemory:
    def __init__(self, max_sessions=10, max_history_per_session=20):
        self.max_sessions = max_sessions
        self.max_history_per_session = max_history_per_session
        self.sessions = OrderedDict()

    def _get_or_create_session(self, session_id):
        if session_id not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                self.sessions.popitem(last=False)
            self.sessions[session_id] = {
                "created_at": time.time(),
                "history": [],
                "categories_seen": [],
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "topics": [],
            }
        return self.sessions[session_id]

    def add_interaction(self, session_id, finding, result):
        session = self._get_or_create_session(session_id)

        entry = {
            "finding": finding,
            "category": result.get("category", "Unknown"),
            "severity": result.get("severity", "unknown"),
            "confidence": result.get("confidence", 0),
            "owner": result.get("owner", ""),
            "timestamp": time.time(),
        }
        session["history"].append(entry)

        if len(session["history"]) > self.max_history_per_session:
            session["history"] = session["history"][-self.max_history_per_session:]

        cat = result.get("category", "")
        if cat and cat not in session["categories_seen"]:
            session["categories_seen"].append(cat)

        severity = result.get("severity", "")
        if severity in session["severity_counts"]:
            session["severity_counts"][severity] += 1

        words = finding.lower().split()
        for word in words:
            if len(word) > 4 and word not in session["topics"] and word not in {
                "the", "this", "that", "with", "from", "have", "been", "were", "they"
            }:
                session["topics"].append(word)
                if len(session["topics"]) > 30:
                    session["topics"] = session["topics"][-30:]

    def get_context(self, session_id):
        if session_id not in self.sessions:
            return ""

        session = self.sessions[session_id]
        if not session["history"]:
            return ""

        parts = [f"Previous findings in this session ({len(session['history'])} total):"]

        for entry in session["history"][-5:]:
            parts.append(
                f"  - [{entry['severity'].upper()}] {entry['category']}: "
                f"{entry['finding'][:80]}..."
            )

        cats = ", ".join(session["categories_seen"]) if session["categories_seen"] else "None"
        parts.append(f"\nCategories seen: {cats}")

        severity_summary = ", ".join(
            f"{k}: {v}" for k, v in session["severity_counts"].items() if v > 0
        )
        if severity_summary:
            parts.append(f"Severity distribution: {severity_summary}")

        high_findings = [
            e for e in session["history"]
            if e["severity"] in ("critical", "high")
        ]
        if high_findings:
            parts.append(f"\nHigh-risk findings requiring attention: {len(high_findings)}")
            for hf in high_findings[-3:]:
                parts.append(f"  - {hf['finding'][:60]}...")

        return "\n".join(parts)

    def get_related_history(self, session_id, current_finding):
        if session_id not in self.sessions:
            return ""

        session = self.sessions[session_id]
        if not session["history"]:
            return ""

        current_words = set(current_finding.lower().split())
        related = []

        for entry in reversed(session["history"]):
            entry_words = set(entry["finding"].lower().split())
            overlap = current_words & entry_words
            if len(overlap) >= 2 or entry["category"] in current_finding.lower():
                related.append(entry)
            if len(related) >= 3:
                break

        if not related:
            return ""

        parts = ["Related findings from this session:"]
        for r in related:
            parts.append(f"  - [{r['severity'].upper()}] {r['finding'][:80]}")
        return "\n".join(parts)

    def get_risk_summary(self, session_id):
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]
        counts = session["severity_counts"]

        total = sum(counts.values())
        if total == 0:
            return None

        return {
            "total_findings": total,
            "severity_distribution": counts,
            "categories_covered": session["categories_seen"],
            "risk_level": (
                "critical" if counts["critical"] > 0
                else "high" if counts["high"] > 0
                else "medium" if counts["medium"] > 0
                else "low"
            ),
        }

    def clear_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
