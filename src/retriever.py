import json
import os
import re
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

CATEGORY_SYNONYMS = {
    "iam": ["identity", "access", "permission", "role", "policy", "rbac", "authn", "authz", "mfa", "credential"],
    "network": ["firewall", "security group", "ingress", "egress", "vpc", "subnet", "cidr", "load balancer", "waf", "dns"],
    "container": ["docker", "kubernetes", "k8s", "pod", "image", "helm", "workload", "deployment"],
    "secrets": ["credential", "password", "token", "key", "api key", "secret manager", "vault"],
    "data": ["storage", "database", "encryption", "backup", "pii", "phi", "gdpr", "compliance"],
}

DEFAULT_CONTROL_ID = "unclassified"
DEFAULT_PROVIDER = "generic"
DEFAULT_SOURCE_VERSION = "unspecified"
DEFAULT_VALIDATION = "Review with the owning team."
DEFAULT_ROLLBACK_GUIDANCE = (
    "Validate dependencies and prepare a rollback plan before changes."
)

SOURCE_FIELDS = (
    "id",
    "title",
    "category",
    "relevance",
    "control_id",
    "provider",
    "source_name",
    "source_version",
    "references",
    "validation",
    "rollback_guidance",
)

FINDING_SYNONYMS = {
    "publicly accessible": ["exposed", "open to internet", "world-readable", "public", "0.0.0.0/0"],
    "hardcoded": ["committed", "embedded", "in code", "plaintext", "clear text"],
    "privileged": ["root", "admin", "elevated", "superuser", "cap_add"],
    "unencrypted": ["no encryption", "plaintext", "clear text", "not ssl", "http"],
    "wildcard": ["*", "all permissions", "full access", "unrestricted", "admin access"],
}


def _preprocess(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _expand_query(query):
    expanded = [query]
    query_lower = query.lower()

    for category, synonyms in CATEGORY_SYNONYMS.items():
        if category in query_lower or any(s in query_lower for s in synonyms):
            expanded.extend(synonyms[:3])

    for pattern, synonyms in FINDING_SYNONYMS.items():
        if pattern in query_lower:
            expanded.extend(synonyms[:2])

    words = query_lower.split()
    if len(words) >= 2:
        for i in range(len(words)):
            for j in range(i + 2, min(i + 4, len(words) + 1)):
                ngram = " ".join(words[i:j])
                if ngram not in " ".join(expanded):
                    expanded.append(ngram)

    return " ".join(expanded)


def _load_kb():
    path = os.path.join(DATA_DIR, "security_kb.json")
    with open(path, "r") as f:
        return json.load(f)


def build_source(entry, relevance):
    """Build the shared retrieval source record.

    Every consumer of retrieval results reads this one schema: app.py builds
    citations from `source_name`, `source_version`, and `references`, while the
    grounding metrics read `id`, `source_name`, `source_version`, `references`,
    `control_id`, and `provider`. Optional knowledge-base fields always fall
    back to explicit defaults so no consumer can raise a KeyError.
    """
    return {
        "id": entry["id"],
        "title": entry["title"],
        "category": entry["category"],
        "relevance": relevance,
        "control_id": entry.get("control_id") or DEFAULT_CONTROL_ID,
        "provider": entry.get("provider") or DEFAULT_PROVIDER,
        "source_name": entry.get("source_name") or entry["title"],
        "source_version": entry.get("source_version") or DEFAULT_SOURCE_VERSION,
        "references": list(entry.get("references") or []),
        "validation": entry.get("validation") or DEFAULT_VALIDATION,
        "rollback_guidance": entry.get("rollback_guidance")
        or DEFAULT_ROLLBACK_GUIDANCE,
    }


class SecurityRetriever:
    def __init__(self, top_k=5):
        self.top_k = top_k
        self.kb = _load_kb()
        self.corpus = []
        self.mappings = []

        for entry in self.kb:
            doc = " ".join([
                entry.get("title", ""),
                entry.get("finding", ""),
                entry.get("remediation", ""),
                " ".join(entry.get("keywords", [])),
            ])
            self.corpus.append(_preprocess(doc))
            self.mappings.append(entry)

        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 3),
            sublinear_tf=True,
            min_df=1,
            max_df=0.95,
        )
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

        self._build_keyword_index()

    def _build_keyword_index(self):
        self.keyword_index = {}
        for idx, entry in enumerate(self.kb):
            for kw in entry.get("keywords", []):
                kw_lower = kw.lower()
                if kw_lower not in self.keyword_index:
                    self.keyword_index[kw_lower] = []
                self.keyword_index[kw_lower].append(idx)

    def _keyword_search(self, query):
        query_lower = _preprocess(query)
        words = query_lower.split()
        scores = Counter()

        for word in words:
            for kw, indices in self.keyword_index.items():
                if word in kw or kw in word:
                    for idx in indices:
                        scores[idx] += 1.0

        return dict(scores)

    def _tfidf_search(self, query):
        query_processed = _preprocess(_expand_query(query))
        query_vec = self.vectorizer.transform([query_processed])
        scores = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        return {idx: float(score) for idx, score in enumerate(scores) if score > 0.01}

    def _hybrid_score(self, query, alpha=0.6):
        tfidf_scores = self._tfidf_search(query)
        keyword_scores = self._keyword_search(query)

        all_indices = set(tfidf_scores.keys()) | set(keyword_scores.keys())
        if not all_indices:
            return {}

        max_kw = max(keyword_scores.values()) if keyword_scores else 1
        max_tfidf = max(tfidf_scores.values()) if tfidf_scores else 1

        combined = {}
        for idx in all_indices:
            tfidf_norm = tfidf_scores.get(idx, 0) / max_tfidf if max_tfidf else 0
            kw_norm = keyword_scores.get(idx, 0) / max_kw if max_kw else 0
            combined[idx] = alpha * tfidf_norm + (1 - alpha) * kw_norm

        return combined

    def _rerank(self, query, candidates, top_k=None, control_id=None, provider=None):
        k = top_k or self.top_k
        if not candidates:
            return []

        if control_id:
            control_candidates = [
                (idx, score) for idx, score in candidates
                if self.mappings[idx].get("control_id") == control_id
            ]
            if control_candidates:
                candidates = control_candidates

        if provider:
            compatible_candidates = [
                (idx, score) for idx, score in candidates
                if self.mappings[idx].get("provider", "generic") in (provider, "generic")
            ]
            if compatible_candidates:
                candidates = compatible_candidates

        query_lower = _preprocess(query)
        reranked = []

        for idx, base_score in candidates:
            entry = self.mappings[idx]
            boosted_score = base_score

            control_match = bool(control_id and entry.get("control_id") == control_id)
            entry_provider = entry.get("provider", "generic")
            provider_match = bool(provider and entry_provider == provider)
            provider_compatible = not provider or entry_provider in (provider, "generic")

            if control_match:
                boosted_score *= 2.0
            if provider_match:
                boosted_score *= 1.25
            elif provider and not provider_compatible:
                boosted_score *= 0.5

            if entry["category"].lower() in query_lower:
                boosted_score *= 1.3

            if entry["severity"] in ("critical", "high"):
                boosted_score *= 1.1

            query_words = set(query_lower.split())
            title_words = set(_preprocess(entry["title"]).split())
            overlap = query_words & title_words
            if overlap:
                boosted_score *= (1 + 0.1 * len(overlap))

            reranked.append((idx, boosted_score, control_match, provider_match))

        reranked.sort(key=lambda x: (x[2], x[3], x[1]), reverse=True)
        return [(idx, score) for idx, score, _, _ in reranked[:k]]

    def retrieve(self, query, top_k=None, retrieve_by="hybrid", control_id=None, provider=None):
        k = top_k or self.top_k
        combined = self._hybrid_score(query)
        ranked = sorted(combined.items(), key=lambda x: x[1], reverse=True)
        reranked = self._rerank(
            query, ranked, top_k=k, control_id=control_id, provider=provider
        )

        results = []
        seen = set()
        for idx, score in reranked:
            if idx not in seen:
                entry = self.mappings[idx].copy()
                entry["relevance_score"] = round(float(score), 4)
                results.append(entry)
                seen.add(idx)

        # Control-first reordering for Workstream 4
        if retrieve_by == "control_first" and control_id:
            results.sort(key=lambda x: (x.get("control", ""), x.get("provider", "")))

        return results

    def build_context(self, query, top_k=None, control_id=None, provider=None):
        results = self.retrieve(query, top_k, retrieve_by="control_first", control_id=control_id, provider=provider)
        if not results:
            return "", []

        context_parts = []
        sources = []
        for i, r in enumerate(results, 1):
            source = build_source(r, r["relevance_score"])
            references = source["references"]
            citation = "; ".join(references) if references else "Source reference unavailable"
            context_parts.append(
                f"[{i}] {source['title']} (Category: {source['category']}, Severity: {r['severity']}, "
                f"Control: {source['control_id']}, Provider: {source['provider']})\n"
                f"    Finding: {r['finding']}\n"
                f"    Remediation: {r['remediation']}\n"
                f"    Validation: {source['validation']}\n"
                f"    Rollback/dependencies: {source['rollback_guidance']}\n"
                f"    Citation: {source['source_name']} v{source['source_version']} ({citation})"
            )
            sources.append(source)

        return "\n\n".join(context_parts), sources
