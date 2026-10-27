"""Retrieval + answering. Uses a real LLM when asked and a key is set; otherwise a simulated assistant."""
import re
import time
from detection import llm
from detection.rules.injection import scan_injection

SYSTEM = ("You are a helpful assistant. Answer the question using ONLY the provided context, "
          "in at most two sentences. If the context does not contain the answer, say so.")
_answers = {}      # repeated questions come back instantly


def _best_sentences(question, text, n=2):
    q = set(re.findall(r"[a-z0-9]+", question.lower()))
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]
    ranked = sorted(sents, key=lambda s: -len(q & set(re.findall(r"[a-z0-9]+", s.lower()))))
    return " ".join(ranked[:n])


def ask(question, store, k=3, use_llm=False):
    t0 = time.time()
    hits = store.search(question, k)
    context = "\n\n".join(h["text"] for h in hits)
    attacks = scan_injection(context, "retrieved context")
    mode = "simulated assistant"
    if use_llm and llm.available():
        key = (question, str(store.path), len(store.items), context)
        if key in _answers:
            answer, mode = _answers[key]
        else:
            try:
                prompt_ctx = "\n\n".join(h["text"][:800] for h in hits[:3])    # keep the prompt small
                answer = llm.complete(f"Context:\n{prompt_ctx}\n\nQuestion: {question}", system=SYSTEM, max_tokens=300)
                mode = f"LLM ({llm.provider()}{' - ' + llm.last_model() if llm.last_model() else ''})"
                _answers[key] = (answer, mode)
            except Exception as exc:
                answer, mode = f"LLM call failed: {exc}", "LLM error"
    elif attacks:
        answer = ("HIJACKED - a naive assistant would obey the injected instruction: '"
                  + attacks[0]["matched"][:80] + "'")
    elif hits:
        answer = _best_sentences(question, hits[0]["text"])
    else:
        answer = "No relevant information found."
    return {"hits": hits, "hijacked": bool(attacks), "answer": answer, "mode": mode,
            "seconds": round(time.time() - t0, 1)}
