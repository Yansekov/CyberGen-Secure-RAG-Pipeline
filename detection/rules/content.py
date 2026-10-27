"""Rules on file-level signals from Ingestion: warnings, metadata, links."""
import re
from urllib.parse import urlparse
from .common import make_finding
from .injection import scan_injection

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
BAD = {
    "macro": "Contains VBA macros",
    "pdf_javascript": "Contains embedded JavaScript",
    "auto_action": "Has an automatic open/launch action",
    "embedded_file": "Contains an embedded or attached executable file",
}


def scan_content(doc):
    out = []
    for w in doc.get("warnings") or []:
        code, detail = w["code"], w.get("detail", "")
        if code == "no_text":
            out.append(make_finding("unreadable_content", detail, "document", "HIGH",
                       f"No readable text could be extracted ({detail}); content may be hidden in images or the file is corrupt"))
        elif code in BAD:
            out.append(make_finding("malicious_content", detail or code, "document", "HIGH",
                       BAD[code] + (f" ({detail})" if detail else ""), weight=70))
    for i, m in enumerate(doc.get("metadata_text") or [], 1):
        out += scan_injection(m["text"], m.get("location", f"metadata_{i}"))
    for url in doc.get("links") or []:
        p = urlparse(url.strip())
        host = (p.hostname or "").lower()
        if p.scheme in ("javascript", "data", "vbscript"):
            out.append(make_finding("malicious_content", url, "links", "HIGH",
                       f"Dangerous link scheme '{p.scheme}:'", weight=40))
        elif host in SHORTENERS or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            out.append(make_finding("malicious_content", url, "links", "MEDIUM",
                       f"Suspicious link (URL shortener or raw IP): {host}", weight=25))
    return out
