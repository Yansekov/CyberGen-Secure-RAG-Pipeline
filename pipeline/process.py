"""Orchestrates: ingest -> detect -> decide -> sanitize -> (quarantine | vector DB)."""
import json, shutil
from datetime import datetime, timezone
from pathlib import Path

from detection.scanner import scan
from ingestion.loader import chunk, load
from .decision import decide
from .sanitizer import INJ_TYPES, sanitize
from .vectorstore import VectorStore

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REPORTS, QUAR = DATA / "reports", DATA / "quarantine"
NO_LLM = lambda prompt: '{"is_threat": false, "reason": "re-check only", "confidence": 0}'


def stores():
    return VectorStore(DATA / "vectordb_protected.json"), VectorStore(DATA / "vectordb_unprotected.json")


def _save(doc, status, note=""):
    doc["status"] = status
    doc["audit_trail"].append({"stage": "pipeline", "status": status, "note": note,
                               "ts": datetime.now(timezone.utc).isoformat()})
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"{doc['doc_id']}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False), "utf-8")


def ingest(path, llm_call=None):
    protected, naive = stores()
    doc = scan(load(path), llm_call=llm_call)
    naive.add(doc["doc_id"], doc["filename"], chunk(doc["raw_text"]))   # baseline: no protection
    doc["decision"] = decide(doc)
    if doc["decision"] == "SANITIZE":
        clean = sanitize(doc["text"], doc["findings"])
        again = scan({"text": clean}, llm_call=NO_LLM, use_presidio=False)
        if again["risk_score"] >= 70 or any(f["type"] in INJ_TYPES for f in again["findings"]):
            doc["decision"] = "QUARANTINE"      # still dangerous after cleaning
        else:
            doc["sanitized_text"] = clean
    elif doc["decision"] == "ALLOW":
        doc["sanitized_text"] = doc["text"]

    if doc["decision"] == "QUARANTINE":
        QUAR.mkdir(parents=True, exist_ok=True)
        protected.remove(doc["doc_id"])
        shutil.copy(path, QUAR / Path(path).name)
        _save(doc, "quarantined", "awaiting manual review")
    else:
        protected.add(doc["doc_id"], doc["filename"], chunk(doc["sanitized_text"]))
        _save(doc, "indexed", f"{doc['decision']} -> vector DB")
    return doc


def get(doc_id):
    return json.loads((REPORTS / f"{doc_id}.json").read_text("utf-8"))


def list_docs():
    files = sorted(REPORTS.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if REPORTS.exists() else []
    return [json.loads(f.read_text("utf-8")) for f in files]


def approve(doc_id):
    doc = get(doc_id)
    doc["sanitized_text"] = sanitize(doc["text"], doc["findings"])
    stores()[0].add(doc_id, doc["filename"], chunk(doc["sanitized_text"]))
    _save(doc, "approved", "reviewer approved; sanitized version indexed")


def reject(doc_id):
    _save(get(doc_id), "rejected", "reviewer rejected")


def reset():
    shutil.rmtree(DATA, ignore_errors=True)
