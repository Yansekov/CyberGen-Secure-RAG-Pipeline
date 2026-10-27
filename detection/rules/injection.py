"""Prompt-injection, role-override and data-exfiltration rules.
Multilingual (English, Hindi/Hinglish, Spanish, French) and obfuscation-aware
(leetspeak, spaced-out letters, ROT13, base64)."""
import base64
import binascii
import codecs
import re
from .common import normalize, make_finding

PATTERNS = [
    # --- prompt injection ---
    ("prompt_injection", r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|guidelines?)"),
    ("prompt_injection", r"disregard\s+(your\s+|all\s+)?(prior|previous|above|earlier)\s+\w+"),
    ("prompt_injection", r"forget\s+(everything|all)\s+(you\s+)?(know|were\s+told|have\s+been\s+told)"),
    ("prompt_injection", r"bypass\s+(your\s+)?(safety|filters?|restrictions?)"),
    ("prompt_injection", r"do\s+anything\s+now|(developer|admin|system)\s+(mode|override)"),
    ("prompt_injection", r"(attention|note\s+to|important\s+(for|to))\s+(the\s+)?(ai|assistant|model|llm|chatbot)"),
    ("prompt_injection", r"<\s*/?\s*system\s*>|\[/?INST\]|<\|im_start\|>"),
    ("prompt_injection", r"ignora\s+(todas\s+)?las\s+instrucciones\s+(anteriores|previas)"),
    ("prompt_injection", r"ignore[zr]?\s+(toutes\s+)?les\s+instructions\s+(pr[eé]c[eé]dentes)"),
    ("prompt_injection", r"(पिछले|पहले\s+के|ऊपर\s+के)\s+(सभी\s+)?(निर्देश|आदेश)[^\n.।]{0,20}(अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)"),
    ("prompt_injection", r"(pichle|purane|sabhi|saare)\s+(sabhi\s+)?(nirdesh|instructions?|aadesh)\s+(ko\s+)?(ignore|ignor|bhool|andekha)"),
    ("prompt_injection", r"ignore\s+(karo|kar\s+do|kijiye)"),
    # --- role override ---
    ("role_override", r"you\s+are\s+now\s+an?\s+\w+"),
    ("role_override", r"act\s+as\s+(if\s+you\s+are\s+|an?\s+)\w+"),
    ("role_override", r"(pretend|behave)\s+(to\s+be|like|that\s+you\s+are)"),
    ("role_override", r"from\s+now\s+on,?\s+(you|act|respond|answer)"),
    # --- data exfiltration ---
    ("data_exfiltration", r"reveal\s+(your\s+)?(system\s+)?(prompt|instructions)"),
    ("data_exfiltration", r"(सिस्टम\s+प्रॉम्प्ट|सिस्टम\s+प्रोम्प्ट)[^\n.।]{0,20}(बताओ|दिखाओ|बताएं|प्रकट)"),
    ("data_exfiltration", r"system\s+prompt\s+(batao|dikhao|bata\s+do)"),
    ("data_exfiltration", r"print\s+(the\s+)?contents?\s+of\s+"),
    ("data_exfiltration", r"exfiltrate|leak\s+(all\s+)?(the\s+)?data"),
    ("data_exfiltration", r"(send|forward|upload|transmit)\b[^.\n]{0,60}\bto\s+https?://\S+"),
    ("data_exfiltration", r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)]*\)"),   # markdown-image data leak
]
_COMPILED = [(t, re.compile(p, re.I)) for t, p in PATTERNS]
_LOOSE = [(t, re.compile(p.replace(r"\s+", r"\s*"), re.I)) for t, p in PATTERNS]  # for de-spaced text

_LEET = str.maketrans("013457@$", "oieastas")
_SPACED = re.compile(r"(?:\b[A-Za-z]\b[\s._\-*]{1,3}){5,}[A-Za-z]\b")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _variants(t):
    out = [("", t, False)]
    if re.search(r"[013457@$]", t):
        out.append(("leetspeak", t.translate(_LEET), False))
    if _SPACED.search(t):
        out.append(("spaced-out letters", _SPACED.sub(lambda m: re.sub(r"[\s._\-*]", "", m.group(0)), t), True))
    out.append(("ROT13", codecs.decode(t, "rot13"), False))
    return out


def _b64_decoded(t):
    for m in _B64.finditer(t):
        tok = m.group(0)
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if dec and sum(c.isprintable() or c in "\n\t" for c in dec) / len(dec) > 0.95:
            yield tok, dec


def _find(text, loose=False):
    for ftype, rx in (_LOOSE if loose else _COMPILED):
        for m in rx.finditer(text):
            yield ftype, m.group(0).strip()


def scan_injection(text, location):
    base = normalize(text)
    findings, seen = [], set()

    def add(ftype, shown, matched, label=""):
        key = (ftype, matched.lower())
        if key in seen:
            return
        seen.add(key)
        tag = f" [{label}]" if label else ""
        extra = {"obfuscation": label} if label else {}
        findings.append(make_finding(ftype, matched, location, "HIGH",
                        f"Found {ftype.replace('_', ' ')} phrase '{shown}'{tag} in {location}", **extra))

    for label, vtext, loose in _variants(base):
        for ftype, m in _find(vtext, loose):
            add(ftype, m, m, label)
    for tok, dec in _b64_decoded(base):
        for ftype, m in _find(normalize(dec)):
            add(ftype, m, tok, "base64")
    return findings
