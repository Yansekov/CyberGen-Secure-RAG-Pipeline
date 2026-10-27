"""Tiny pure-Python vector store (TF-IDF + cosine). Swap for Chroma/FAISS later - same API."""
import json, math, re
from collections import Counter
from pathlib import Path


def _tok(s):
    return re.findall(r"[a-z0-9]+", s.lower())


class VectorStore:
    def __init__(self, path):
        self.path = Path(path)
        self.items = json.loads(self.path.read_text("utf-8")) if self.path.exists() else []

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.items), encoding="utf-8")

    def add(self, doc_id, filename, chunks):
        self.items = [i for i in self.items if i["doc_id"] != doc_id]   # re-scan replaces, never duplicates
        self.items += [{"doc_id": doc_id, "filename": filename, "text": t} for t in chunks]
        self._save()

    def remove(self, doc_id):
        self.items = [i for i in self.items if i["doc_id"] != doc_id]
        self._save()

    def search(self, query, k=3):
        n = len(self.items)
        toks = [Counter(_tok(i["text"])) for i in self.items]
        df = Counter(w for t in toks for w in t)
        idf = lambda w: math.log((n + 1) / (df[w] + 1)) + 1
        q = Counter(_tok(query))
        qv = {w: c * idf(w) for w, c in q.items()}
        qn = math.sqrt(sum(v * v for v in qv.values())) or 1
        scored = []
        for item, t in zip(self.items, toks):
            dv = {w: c * idf(w) for w, c in t.items()}
            dn = math.sqrt(sum(v * v for v in dv.values())) or 1
            sim = sum(v * dv.get(w, 0) for w, v in qv.items()) / (qn * dn)
            if sim > 0:
                scored.append((sim, item))
        scored.sort(key=lambda x: -x[0])
        return [dict(i, score=round(s, 3)) for s, i in scored[:k]]
