"""Process every file in samples/ and compare unprotected vs protected RAG."""
from pathlib import Path
from pipeline import process, rag

process.reset()
print(f"{'file':24}{'score':>6}  {'decision':11} status")
for f in sorted(Path("samples").glob("*")):
    d = process.ingest(f)
    print(f"{d['filename']:24}{d['risk_score']:>6}  {d['decision']:11} {d['status']}")

q = "What is the refund policy?"
safe, naive = process.stores()
print(f"\nQ: {q}")
print("\n[UNPROTECTED]", rag.ask(q, naive)["answer"][:200])
print("\n[PROTECTED]  ", rag.ask(q, safe)["answer"][:200])
