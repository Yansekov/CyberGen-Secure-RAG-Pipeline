"""Stage 1 - Ingestion: text, hidden content, metadata, links and warnings from many file types.

Supported: txt md csv json html docx pptx xlsx pdf eml + images (OCR via Tesseract)."""
import email, hashlib, html, io, os, re, zipfile
from datetime import datetime, timezone
from email import policy
from html.parser import HTMLParser
from pathlib import Path

HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?!\.?\d)|opacity\s*:\s*0(?!\.?\d)"
    r"|(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}"
    r"|color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", re.I)
VOID = {"br", "hr", "img", "meta", "link", "input"}
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|\b(?:javascript|data|vbscript):[^\s<>\"']+", re.I)
WIN_TESS = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
RISKY_ATTACH = {".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".jar", ".docm", ".xlsm", ".msi"}


def _new():
    return {"text": "", "hidden": [], "meta": [], "links": [], "warnings": [], "ocr": None}


def _warn(ex, code, detail=""):
    ex["warnings"].append({"code": code, "detail": detail})


def _wt(xml):
    return html.unescape(" ".join(re.findall(r"<(?:w|a):t[^>]*>(.*?)</(?:w|a):t>", xml, re.S)))


# ---------- OCR ----------
def _ocr(data):
    try:
        import pytesseract
        from PIL import Image
        cmd = os.getenv("TESSERACT_CMD") or (WIN_TESS if os.path.exists(WIN_TESS) else None)
        if cmd:
            pytesseract.pytesseract.tesseract_cmd = cmd
        return pytesseract.image_to_string(Image.open(io.BytesIO(data))).strip(), "ok"
    except Exception:
        return "", "unavailable"


def _ocr_images(ex, blobs):
    out = []
    for b in blobs[:10]:
        text, st = _ocr(b)
        if st == "ok":
            ex["ocr"] = "ok"
        elif ex["ocr"] is None:
            ex["ocr"] = "unavailable"
        if text:
            out.append(text)
    return "\n\n".join(out)


# ---------- HTML ----------
class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible, self.hidden, self.meta, self.links, self.stack = [], [], [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("href"):
            self.links.append(a["href"])
        for k in ("alt", "title"):
            if (a.get(k) or "").strip():
                self.meta.append({"text": a[k], "location": f"{tag} {k} attribute"})
        if tag == "meta" and (a.get("content") or "").strip() and (a.get("name") or "").lower() in ("description", "keywords"):
            self.meta.append({"text": a["content"], "location": "meta tag"})
        if tag in VOID:
            return
        hid = bool(HIDDEN_STYLE.search(a.get("style") or "")) or "hidden" in a or a.get("aria-hidden") == "true"
        self.stack.append((tag, hid))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if not data.strip() or (self.stack and self.stack[-1][0] in ("script", "style")):
            return
        if any(h for _, h in self.stack):
            self.hidden.append({"type": "hidden HTML element", "text": data.strip()})
        else:
            self.visible.append(data.strip())

    def handle_comment(self, data):
        if data.strip():
            self.hidden.append({"type": "HTML comment", "text": data.strip()})


def _html_text(raw, ex):
    p = _HTML()
    p.feed(raw)
    ex["hidden"] += p.hidden
    ex["meta"] += p.meta
    ex["links"] += p.links
    return "\n\n".join(p.visible)


def _htmlh(data):
    ex = _new()
    ex["text"] = _html_text(data.decode("utf-8", "ignore"), ex)
    return ex


# ---------- Office ----------
def _docx(data):
    z, ex = zipfile.ZipFile(io.BytesIO(data)), _new()
    names = z.namelist()
    xml = z.read("word/document.xml").decode("utf-8", "ignore")
    vis = []
    for para in re.findall(r"<w:p[ >].*?</w:p>", xml, re.S):
        v = h = ""
        for run in re.findall(r"<w:r[ >].*?</w:r>", para, re.S):
            t = _wt(run)
            sz = re.search(r'<w:sz w:val="(\d+)"', run)
            if "<w:vanish" in run or re.search(r'<w:color w:val="FFFFFF"', run, re.I) or (sz and int(sz.group(1)) <= 4):
                h += t
            else:
                v += t
        if v.strip():
            vis.append(v)
        if h.strip():
            ex["hidden"].append({"type": "hidden Word text (hidden, white or tiny)", "text": h})
    for n in names:
        if re.match(r"word/(header|footer|footnotes|endnotes)\d*\.xml$", n):
            t = _wt(z.read(n).decode("utf-8", "ignore"))
            if t.strip():
                vis.append(t)
    if "word/comments.xml" in names:
        ex["meta"].append({"text": _wt(z.read("word/comments.xml").decode("utf-8", "ignore")), "location": "Word comments"})
    if "docProps/core.xml" in names:
        core = z.read("docProps/core.xml").decode("utf-8", "ignore")
        for k, v in re.findall(r"<(?:dc|cp):(title|subject|description|keywords)[^>]*>(.*?)</", core, re.S):
            if v.strip():
                ex["meta"].append({"text": html.unescape(v), "location": f"document {k}"})
    if "word/_rels/document.xml.rels" in names:
        ex["links"] += URL_RE.findall(z.read("word/_rels/document.xml.rels").decode("utf-8", "ignore"))
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        _warn(ex, "macro", "vbaProject.bin")
    if any(n.startswith("word/embeddings/") for n in names):
        _warn(ex, "embedded_file", "embedded object")
    ocr = _ocr_images(ex, [z.read(n) for n in names if n.startswith("word/media/")])
    ex["text"] = "\n\n".join(vis + ([ocr] if ocr else []))
    return ex


def _pptx(data):
    z, ex = zipfile.ZipFile(io.BytesIO(data)), _new()
    names = z.namelist()
    slides = sorted((n for n in names if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                    key=lambda s: int(re.search(r"(\d+)\.xml", s).group(1)))
    vis = []
    for n in slides:
        x = z.read(n).decode("utf-8", "ignore")
        v, h = [], []
        for run in re.findall(r"<a:r>.*?</a:r>", x, re.S):
            sz = re.search(r'sz="(\d+)"', run)
            (h if sz and int(sz.group(1)) < 300 else v).append(_wt(run))
        if re.search(r'<p:sld\b[^>]*\bshow="0"', x):
            ex["hidden"].append({"type": "hidden slide", "text": " ".join(v + h)})
        else:
            vis.append("\n".join(v))
            if h:
                ex["hidden"].append({"type": "tiny text on slide", "text": " ".join(h)})
    for n in names:
        if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n):
            ex["meta"].append({"text": _wt(z.read(n).decode("utf-8", "ignore")), "location": "speaker notes"})
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        _warn(ex, "macro", "vbaProject.bin")
    ocr = _ocr_images(ex, [z.read(n) for n in names if n.startswith("ppt/media/")])
    ex["text"] = "\n\n".join(vis + ([ocr] if ocr else []))
    return ex


def _xlsx(data):
    z, ex = zipfile.ZipFile(io.BytesIO(data)), _new()
    names = z.namelist()
    rd = lambda n: z.read(n).decode("utf-8", "ignore")
    ss = []
    if "xl/sharedStrings.xml" in names:
        ss = [html.unescape("".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.S)))
              for si in re.findall(r"<si>.*?</si>", rd("xl/sharedStrings.xml"), re.S)]
    targets = {}
    if "xl/_rels/workbook.xml.rels" in names:
        for tag in re.findall(r"<Relationship\b[^>]*>", rd("xl/_rels/workbook.xml.rels")):
            i, t = re.search(r'Id="([^"]+)"', tag), re.search(r'Target="([^"]+)"', tag)
            if i and t:
                targets[i.group(1)] = "xl/" + t.group(1).lstrip("/").replace("xl/", "")
    vis = []
    for tag in re.findall(r"<sheet\b[^>]*>", rd("xl/workbook.xml")):
        rid = re.search(r'r:id="([^"]+)"', tag)
        path = targets.get(rid.group(1)) if rid else None
        if not path or path not in names:
            continue
        cells = []
        for attrs, inner in re.findall(r"<c\b([^>]*)>(.*?)</c>", rd(path), re.S):
            if 't="s"' in attrs:
                v = re.search(r"<v>(\d+)</v>", inner)
                if v and int(v.group(1)) < len(ss):
                    cells.append(ss[int(v.group(1))])
            elif 'inlineStr' in attrs:
                cells.append(html.unescape("".join(re.findall(r"<t[^>]*>(.*?)</t>", inner, re.S))))
        text = "\n".join(c for c in cells if c.strip())
        name = (re.search(r'name="([^"]*)"', tag) or [None, "sheet"])[1]
        if re.search(r'state="(hidden|veryHidden)"', tag):
            ex["hidden"].append({"type": f"hidden worksheet '{name}'", "text": text})
        else:
            vis.append(text)
    for n in names:
        if re.match(r"xl/comments\d*\.xml$", n):
            ex["meta"].append({"text": _wt(rd(n)) or " ".join(re.findall(r"<t[^>]*>(.*?)</t>", rd(n), re.S)), "location": "cell comments"})
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        _warn(ex, "macro", "vbaProject.bin")
    ex["text"] = "\n\n".join(vis)
    return ex


# ---------- PDF ----------
def _pdf(data):
    from pypdf import PdfReader
    ex = _new()
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            pass
    for pat, code in ((b"/JavaScript", "pdf_javascript"), (b"/JS", "pdf_javascript"), (b"/OpenAction", "auto_action"),
                      (b"/Launch", "auto_action"), (b"/EmbeddedFile", "embedded_file")):
        if pat in data and not any(w["code"] == code for w in ex["warnings"]):
            _warn(ex, code, pat.decode().lstrip("/"))
    for k, v in (reader.metadata or {}).items():
        if isinstance(v, str) and v.strip():
            ex["meta"].append({"text": v, "location": f"PDF metadata {str(k).lstrip('/')}"})
    vis, blobs = [], []
    for page in reader.pages:
        parts, st = [], {"w": False}

        def op(operator, args, cm, tm):
            try:
                if operator == b"rg":
                    st["w"] = all(float(a) > 0.95 for a in args)
                elif operator == b"g":
                    st["w"] = float(args[0]) > 0.95
                elif operator == b"k":
                    st["w"] = all(float(a) < 0.05 for a in args)
            except Exception:
                pass

        def tx(text, cm, tm, fd, fs):
            try:
                size = abs(fs * (tm[3] or 1))
            except Exception:
                size = fs or 10
            if text:
                parts.append((text, st["w"] or size < 2))

        t = page.extract_text(visitor_operand_before=op, visitor_text=tx) or ""
        hid = "".join(p for p, h in parts if h).strip()
        if hid:
            ex["hidden"].append({"type": "hidden PDF text (white or tiny)", "text": hid})
            vis.append("".join(p for p, h in parts if not h))
        else:
            vis.append(t)
        try:
            for annot in page.get("/Annots") or []:
                a = annot.get_object()
                if a.get("/Contents"):
                    ex["meta"].append({"text": str(a["/Contents"]), "location": "PDF annotation"})
                uri = (a.get("/A") or {}).get("/URI")
                if uri:
                    ex["links"].append(str(uri))
        except Exception:
            pass
        try:
            blobs += [img.data for img in page.images]
        except Exception:
            pass
    ocr = _ocr_images(ex, blobs) if blobs else ""
    ex["text"] = "\n\n".join(v for v in vis + [ocr] if v and v.strip())
    return ex


# ---------- Email / images / plain ----------
def _eml(data):
    ex = _new()
    msg = email.message_from_bytes(data, policy=policy.default)
    head = "\n".join(f"{h}: {msg[h]}" for h in ("Subject", "From", "To") if msg[h])
    body = msg.get_body(preferencelist=("plain", "html"))
    content = body.get_content() if body else ""
    if body is not None and body.get_content_type() == "text/html":
        content = _html_text(content, ex)
    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        if os.path.splitext(name)[1] in RISKY_ATTACH:
            _warn(ex, "embedded_file", name)
    ex["text"] = f"{head}\n\n{content}".strip()
    return ex


def _img(data):
    ex = _new()
    ex["text"] = _ocr_images(ex, [data])
    return ex


def _txt(data):
    ex = _new()
    ex["text"] = data.decode("utf-8", "ignore")
    return ex


HANDLERS = {".html": _htmlh, ".htm": _htmlh, ".docx": _docx, ".docm": _docx, ".pptx": _pptx, ".pptm": _pptx,
            ".xlsx": _xlsx, ".xlsm": _xlsx, ".pdf": _pdf, ".eml": _eml}
for _e in (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif", ".webp"):
    HANDLERS[_e] = _img
SUPPORTED = set(HANDLERS) | {".txt", ".md", ".csv", ".json", ".log"}


def chunk(text, size=600):
    """Paragraph-aware chunking -> list of strings."""
    out, cur = [], ""
    for para in re.split(r"\n\s*\n", text):
        para = para.strip()
        if not para:
            continue
        if cur and len(cur) + len(para) > size:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n\n{para}".strip()
    if cur:
        out.append(cur)
    return out


def load(path):
    path = Path(path)
    data = path.read_bytes()
    try:
        ex = HANDLERS.get(path.suffix.lower(), _txt)(data)
    except Exception as exc:
        ex = _new()
        _warn(ex, "no_text", f"could not parse file ({type(exc).__name__})")
    text = ex["text"].strip()
    if len(text) < 5 and not any(w["code"] == "no_text" for w in ex["warnings"]):
        _warn(ex, "no_text", "OCR unavailable - install Tesseract" if ex["ocr"] == "unavailable" else "empty document")
    links = list(dict.fromkeys(ex["links"] + URL_RE.findall(text) + [u for h in ex["hidden"] for u in URL_RE.findall(h["text"])]))
    chunks = chunk(text)
    return {
        "doc_id": hashlib.sha1(data).hexdigest()[:10],
        "filename": path.name,
        "text": text,                                    # visible text only
        "raw_text": "\n\n".join([text] + [h["text"] for h in ex["hidden"]] + [m["text"] for m in ex["meta"]]),
        "chunks": [{"id": f"chunk_{i}", "text": t} for i, t in enumerate(chunks, 1)],
        "hidden_content": ex["hidden"], "metadata_text": ex["meta"], "links": links,
        "warnings": ex["warnings"], "ocr": ex["ocr"],
        "findings": [], "risk_score": None, "reasons": [],
        "decision": None, "sanitized_text": None, "status": "new",
        "audit_trail": [{"stage": "ingestion", "status": "complete", "chunks": len(chunks),
                         "hidden_items": len(ex["hidden"]), "warnings": len(ex["warnings"]),
                         "ts": datetime.now(timezone.utc).isoformat()}],
    }
