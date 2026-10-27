"""Shared helpers for the rule modules."""
import html
import unicodedata
from urllib.parse import unquote

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text):
    """Defeat simple evasion: lookalike chars, zero-width chars, HTML entities, %-encoding."""
    t = unicodedata.normalize("NFKC", text or "").translate(_ZERO_WIDTH)
    t = html.unescape(t)
    return unquote(t) if "%" in t else t


def make_finding(ftype, matched, location, severity, reason, **extra):
    f = {"type": ftype, "matched": matched, "location": location, "severity": severity, "reason": reason}
    f.update(extra)
    return f
