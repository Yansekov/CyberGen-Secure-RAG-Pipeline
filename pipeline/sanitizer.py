"""Surgical sanitizer: removes the injected phrase (through the end of its sentence), redacts PII, strips bad links.
Legitimate sentences - and legitimate text earlier in the same sentence - are kept."""
import re
from detection.rules.common import normalize

INJ_TYPES = ("prompt_injection", "role_override", "data_exfiltration")
_END = re.compile(r"[.!?\u0964](?=\s|$)|\n")


def sanitize(text, findings):
    text = normalize(text)
    spans = []
    for f in findings:
        needle = f.get("matched")
        if not needle:
            continue
        for m in re.finditer(re.escape(needle), text, re.I):
            if f["type"] in INJ_TYPES:
                e = _END.search(text, m.end())
                end = e.start() if e and e.group() == "\n" else (e.end() if e else len(text))
                spans.append((m.start(), end, "[REMOVED: suspected prompt injection]"))
            elif f["type"] == "pii":
                label = re.sub(r"[^A-Z0-9]+", "_", f.get("pii_type", "PII").upper()).strip("_")
                spans.append((m.start(), m.end(), f"[REDACTED_{label}]"))
            elif f["type"] == "malicious_content" and ("://" in needle or needle.lower().startswith(("javascript:", "data:", "vbscript:"))):
                spans.append((m.start(), m.end(), "[REMOVED_LINK]"))
    out, pos = [], 0
    for s, e, rep in sorted(spans):
        if s < pos:
            continue
        out += [text[pos:s], rep]
        pos = e
    out.append(text[pos:])
    return "".join(out)
