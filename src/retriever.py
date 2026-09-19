import json
import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_kb():
    path = os.path.join(DATA_DIR, "security_kb.json")
    with open(path, "r") as f:
        return json.load(f)


def _preprocess(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


class SecurityRetriever:
    def __init__(self, top_k=3):
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
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

    def retrieve(self, query, top_k=None):
        k = top_k or self.top_k
        query_processed = _preprocess(query)
        query_vec = self.vectorizer.transform([query_processed])
        scores = cosine_similarity(query_vec, self.tfidf_matrix).flatten()

        ranked = sorted(
            enumerate(scores), key=lambda x: x[1], reverse=True
        )[:k]

        results = []
        for idx, score in ranked:
            if score > 0.01:
                entry = self.mappings[idx].copy()
                entry["relevance_score"] = round(float(score), 4)
                results.append(entry)

        return results

    def build_context(self, query, top_k=None):
        results = self.retrieve(query, top_k)
        if not results:
            return ""

        context_parts = []
        for i, r in enumerate(results, 1):
            context_parts.append(
                f"[{i}] {r['title']} (Category: {r['category']}, Severity: {r['severity']})\n"
                f"    Finding: {r['finding']}\n"
                f"    Remediation: {r['remediation']}"
            )

        return "\n\n".join(context_parts)
