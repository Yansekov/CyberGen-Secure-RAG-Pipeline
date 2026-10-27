"""Secure RAG website.  Run from the project root:  python -m dashboard.app"""
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename
from detection import llm
from ingestion.loader import SUPPORTED
from pipeline import process, rag

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secure-rag-dev")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # 25 MB upload limit
UPLOADS = process.DATA / "uploads"
OK_EXT = SUPPORTED
QUESTIONS = ["What is the refund policy?", "How long do refunds take?", "What are the support handbook rules?"]


@app.context_processor
def inject():
    return {"pending": sum(d["status"] == "quarantined" for d in process.list_docs())}


@app.template_filter("mask")
def mask(s):
    return s if len(s) < 5 else s[:2] + "*" * (len(s) - 4) + s[-2:]


@app.get("/")
def home():
    docs = process.list_docs()
    st = {k: sum(d["decision"] == k for d in docs) for k in ("ALLOW", "SANITIZE", "QUARANTINE")}
    return render_template("home.html", docs=docs[:5], st=st, total=len(docs))


@app.route("/scan", methods=["GET", "POST"])
def scan_page():
    if request.method == "POST":
        UPLOADS.mkdir(parents=True, exist_ok=True)
        last = None
        for f in request.files.getlist("file"):
            name = secure_filename(f.filename or "")
            if name and Path(name).suffix.lower() in OK_EXT:
                f.save(UPLOADS / name)
                last = process.ingest(UPLOADS / name)
        if not last:
            flash("No supported file selected: " + ", ".join(sorted(e.lstrip(".") for e in OK_EXT)))
            return redirect(url_for("scan_page"))
        return redirect(url_for("doc_page", doc_id=last["doc_id"]))
    return render_template("scan.html")


@app.post("/scan/paste")
def paste():
    text = request.form.get("text", "").strip()
    if not text:
        flash("Paste some text first.")
        return redirect(url_for("scan_page"))
    UPLOADS.mkdir(parents=True, exist_ok=True)
    path = UPLOADS / f"pasted_{int(time.time())}.txt"
    path.write_text(text, encoding="utf-8")
    return redirect(url_for("doc_page", doc_id=process.ingest(path)["doc_id"]))


@app.post("/scan/samples")
def samples():
    files = sorted((process.ROOT / "samples").glob("*"))
    for f in files:
        process.ingest(f)
    flash(f"Scanned {len(files)} sample documents.")
    return redirect(url_for("docs_page"))


@app.get("/documents")
def docs_page():
    f = request.args.get("f", "all")
    docs = process.list_docs()
    if f == "quarantined":
        docs = [d for d in docs if d["status"] == "quarantined"]
    elif f in ("ALLOW", "SANITIZE", "QUARANTINE"):
        docs = [d for d in docs if d["decision"] == f]
    return render_template("docs.html", docs=docs, f=f)


@app.get("/doc/<doc_id>")
def doc_page(doc_id):
    return render_template("doc.html", d=process.get(doc_id))


@app.post("/approve/<doc_id>")
def approve(doc_id):
    process.approve(doc_id)
    flash("Approved - the sanitized version was added to the vector database.")
    return redirect(url_for("doc_page", doc_id=doc_id))


@app.post("/reject/<doc_id>")
def reject(doc_id):
    process.reject(doc_id)
    flash("Rejected - the document stays out of the vector database.")
    return redirect(url_for("doc_page", doc_id=doc_id))


@app.get("/ask")
def ask_page():
    q = request.args.get("q", "").strip()
    res = None
    use_llm = request.args.get("llm") == "1" and llm.available()
    if q:
        safe, naive = process.stores()
        with ThreadPoolExecutor(2) as pool:          # both answers at once -> half the waiting
            f_safe = pool.submit(rag.ask, q, safe, 3, use_llm)
            f_naive = pool.submit(rag.ask, q, naive, 3, use_llm)
            res = {"safe": f_safe.result(), "naive": f_naive.result()}
    return render_template("ask.html", q=q, res=res, questions=QUESTIONS, use_llm=use_llm,
                           llm_ok=llm.available(), llm_name=llm.provider())


@app.errorhandler(413)
def too_big(_):
    flash("File too large (limit 25 MB).")
    return redirect(url_for("scan_page"))


@app.post("/reset")
def reset():
    process.reset()
    flash("All data cleared.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(port=5000)
