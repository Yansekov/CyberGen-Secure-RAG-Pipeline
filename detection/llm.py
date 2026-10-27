"""One place for real-LLM access.

Provider is chosen by which API key is set (first match wins):
  NVIDIA_API_KEY     -> NVIDIA NIM (OpenAI-compatible endpoint)
  ANTHROPIC_API_KEY  -> Anthropic Claude   (default model: claude-haiku-5-5)
  OPENAI_API_KEY     -> OpenAI             (default model: gpt-4o-mini)
Override the model with LLM_MODEL. LLM_TIMEOUT (seconds, default 30) limits each call; no automatic retries.

NVIDIA retires models often, so without LLM_MODEL we ask the API which models exist right now,
skip embedding/safety/rerank models, prefer small fast chat models, and fall back to the next
one if a model is gone (HTTP 404/410). The model that worked is remembered for the session.
"""
import os
import re

NVIDIA_URL = "https://integrate.api.nvidia.com/v1"
_PREFER = ("llama-3.1-8b-instruct", "gpt-oss-20b", "nemotron-3.5-lightning", "gemma-4",
           "deepseek-v4.1-flash", "nemotron-3-super", "nemotron-3-ultra", "llama-3.3-70b")
_EXCLUDE = ("embed", "rerank", "parse", "safety", "guard", "reward", "voice", "clip", "asr", "tts",
            "calibration", "diffusion", "audio", "speech", "topic-control")
_cache = {}


def provider():
    for name, var in (("nvidia", "NVIDIA_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY"), ("openai", "OPENAI_API_KEY")):
        if os.getenv(var):
            return name
    return None


def available():
    return provider() is not None


def last_model():
    return _cache.get("model")


def _nvidia_candidates(client):
    try:
        ids = [m.id for m in client.models.list().data]
    except Exception:
        return ["meta/llama-3.1-8b-instruct"]
    ok = [i for i in ids if not any(x in i.lower() for x in _EXCLUDE)]
    ranked = [i for p in _PREFER for i in ok if p in i.lower()]
    return list(dict.fromkeys(ranked + ok))[:5]


def _nvidia(msgs, max_tokens):
    from openai import OpenAI              # NVIDIA NIM speaks the OpenAI chat-completions API
    client = OpenAI(base_url=os.getenv("NVIDIA_BASE_URL", NVIDIA_URL), api_key=os.environ["NVIDIA_API_KEY"],
                    timeout=float(os.getenv("LLM_TIMEOUT", "30")), max_retries=0)
    forced = os.getenv("LLM_MODEL")
    candidates = [forced] if forced else ([_cache["model"]] if "model" in _cache else _nvidia_candidates(client))
    last = None
    for model in candidates:
        try:
            if "reasoning" in model.lower():     # e.g. nvidia/nemotron-3-nano-omni-30b-a3b-reasoning
                kw = {"temperature": 0.6, "top_p": 0.95, "max_tokens": max(max_tokens, 4096),
                      "extra_body": {"reasoning_budget": int(os.getenv("NVIDIA_REASONING_BUDGET", "1024"))}}
            else:
                kw = {"temperature": 0, "max_tokens": max(max_tokens, 1024)}
            r = client.chat.completions.create(model=model, messages=msgs, **kw)
            text = re.sub(r"<think>.*?</think>", "", r.choices[0].message.content or "", flags=re.S).strip()
            if not text:
                raise RuntimeError("empty reply")
            _cache["model"] = model
            return text
        except Exception as exc:
            last = exc
            _cache.pop("model", None)
            if getattr(exc, "status_code", None) in (401, 403):
                raise RuntimeError("NVIDIA rejected the API key (check NVIDIA_API_KEY)") from exc
    raise RuntimeError(f"NVIDIA call failed (tried: {', '.join(candidates) or 'none'}): {last}. "
                       "Pick a current chat model at build.nvidia.com and set LLM_MODEL.")


def complete(prompt, system=None, max_tokens=400):
    p = provider()
    msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
    if p == "nvidia":
        return _nvidia(msgs, max_tokens)
    if p == "openai":
        from openai import OpenAI
        r = OpenAI(timeout=float(os.getenv("LLM_TIMEOUT", "30")), max_retries=0).chat.completions.create(model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
                                                       messages=msgs, max_tokens=max_tokens, temperature=0)
        return r.choices[0].message.content
    if p == "anthropic":
        import anthropic
        kw = {"system": system} if system else {}
        r = anthropic.Anthropic().messages.create(
            model=os.getenv("LLM_MODEL", "claude-haiku-5-5"), max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}], **kw)
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    raise RuntimeError("No LLM key set (NVIDIA_API_KEY, ANTHROPIC_API_KEY or OPENAI_API_KEY)")
