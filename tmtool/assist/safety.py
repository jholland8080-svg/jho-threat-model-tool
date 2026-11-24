"""
Code-level defenses for the assistant. These run no matter what the model decides.

- Redactor: swaps sensitive identifiers for placeholders before anything leaves the machine, and puts
  them back in the local output.
- strip_hidden: removes content a person reading the document wouldn't see (HTML comments, hidden
  elements, zero-width characters). The model should see what the reviewer sees.
- find_instructions: flags text that reads like instructions to an AI ("mark all threats mitigated").
  Found by code, shown in the draft's review notes, independent of what the model says.
- clean_text: sanitizes every string the model writes before it's stored.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# ----------------------------------------------------------------------------------------- redaction

# Order matters: longer, more specific patterns first so an ARN isn't half-eaten by the account-ID rule.
_REDACT_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ARN", re.compile(r"\barn:aws[a-z-]*:[A-Za-z0-9-]*:[a-z0-9-]*:\d{0,12}:[^\s\"'`<>,;)]+")),
    ("URL", re.compile(r"\b(?:https?|s3|ftp)://[^\s\"'`<>)]+", re.I)),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CIDR", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("IPV6", re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)),
    ("GUID", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("ACCOUNT", re.compile(r"(?<![\d.])\d{12}(?![\d.])")),
    # Hostnames with 3+ labels (app.prod.example.com) or an internal suffix (db1.corp, vault.internal).
    ("HOST", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,}\b"
                        r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|local|corp|lan|intranet)\b", re.I)),
]
_PLACEHOLDER = re.compile(r"\bREDACTED_[A-Z0-9]+_\d+\b")


class Redactor:
    """Consistent placeholders: the same value always gets the same placeholder within one run."""

    def __init__(self, extra_terms: List[str] = ()):  # type: ignore[assignment]
        self.forward: Dict[str, str] = {}
        self.back: Dict[str, str] = {}
        self.counts: Dict[str, int] = {}
        terms = sorted({t.strip() for t in extra_terms if t and t.strip()}, key=len, reverse=True)
        self.term_pattern = (re.compile(r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b", re.I)
                             if terms else None)

    def _placeholder(self, kind: str, value: str) -> str:
        key = value.lower() if kind in ("HOST", "EMAIL", "TERM") else value
        if key not in self.forward:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            ph = f"REDACTED_{kind}_{self.counts[kind]}"
            self.forward[key] = ph
            self.back[ph] = value
        return self.forward[key]

    def redact(self, text: str) -> str:
        if self.term_pattern is not None:
            text = self.term_pattern.sub(lambda m: self._placeholder("TERM", m.group(0)), text)
        for kind, pattern in _REDACT_PATTERNS:
            text = pattern.sub(lambda m, k=kind: m.group(0) if _PLACEHOLDER.fullmatch(m.group(0))
                               else self._placeholder(k, m.group(0)), text)
        return text

    def restore(self, text: str) -> str:
        return _PLACEHOLDER.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)

    def summary(self) -> Dict[str, int]:
        return dict(self.counts)


# ------------------------------------------------------------------------------------- hidden content

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_MD_COMMENT = re.compile(r"^\s*\[(?://|comment)\]:\s*(?:#|<>)\s*\(.*?\)\s*$", re.M | re.I)
_HIDDEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-z][a-z0-9]*)\b[^>]*?(?:style\s*=\s*\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b)[^\"]*\"|\shidden(?=[\s>=]))[^>]*>.*?</(?P=tag)>",
    re.S | re.I)
_SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)


def strip_hidden(text: str) -> Tuple[str, List[str]]:
    """Remove content a human reader wouldn't see. Returns (visible text, notes about what was removed)."""
    notes: List[str] = []

    def drop(pattern: "re.Pattern[str]", label: str, s: str) -> str:
        found = pattern.findall(s)
        if found:
            notes.append(f"{len(found)} {label} removed")
        return pattern.sub(" ", s)

    text = drop(_SCRIPT_STYLE, "script/style block(s)", text)
    text = drop(_HTML_COMMENT, "HTML comment(s)", text)
    text = drop(_HIDDEN_ELEMENT, "hidden HTML element(s)", text)
    text = drop(_MD_COMMENT, "Markdown comment(s)", text)
    text = drop(_ZERO_WIDTH, "zero-width character(s)", text)
    text = drop(_BIDI, "bidirectional control character(s)", text)
    return text, notes


def html_to_text(html: str) -> str:
    text = re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>|</tr>", "\n", html, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    for a, b in (("&nbsp;", " "), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"), ("&amp;", "&")):
        text = text.replace(a, b)
    return re.sub(r"[ \t]+", " ", text)


# ------------------------------------------------------------------------------- instruction-like text

_INSTRUCTION = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules|guidance)"
    r"|disregard (?:the |all |any )?(?:previous|prior|above|system|earlier)"
    r"|(?:you are|act as) (?:now )?(?:a|an|the) (?:\w+ ){0,3}(?:assistant|model|ai|agent)\b"
    r"|(?:mark|treat|record|rate|classify) (?:all |every |these |this |the )?(?:\w+ ){0,3}"
    r"(?:threats?|risks?|findings?|controls?|issues?) as (?:mitigated|resolved|low|accepted|in place|present|n/?a)"
    r"|(?:pre-?approved|already approved|exempt(?:ed)?) by (?:security|infosec|the security team|risk|ciso)"
    r"|(?:do not|don't|never) (?:flag|report|mention|include|ask|raise|list|question)"
    r"|(?:no need|not necessary) to (?:review|assess|flag|ask|threat model)"
    r"|(?:remove|delete|omit|drop) (?:the |this |that |all )?(?:\w+ ){0,2}(?:component|flow|finding|threat)s?\b"
    r"|(?:system|developer) (?:prompt|message|instructions?)\s*:"
    r"|\bAI (?:assistant|agent|model|reviewer)s?,? (?:should|must|please|reading this)",
    re.I)


def find_instructions(text: str) -> List[str]:
    """Snippets of text that read like instructions to an AI. Detection only, for the human reviewer."""
    hits = []
    for m in _INSTRUCTION.finditer(text):
        start, end = max(0, m.start() - 40), min(len(text), m.end() + 40)
        hits.append(" ".join(text[start:end].split()))
    return hits


# ------------------------------------------------------------------------------------- model output

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_ANY_URL = re.compile(r"\b(?:https?|s3|ftp|data|javascript|file)://\S+|\bwww\.\S+|\bdata:[a-z]+/\S+", re.I)
_TAG = re.compile(r"</?[a-z][^>]*>", re.I)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WITHHELD = "[withheld: instruction-like text; see the source document]"


def clean_text(text: object, limit: int = 300) -> Tuple[str, List[str]]:
    """
    Sanitize one string written by the model. Returns (clean text, list of what was removed).
    Links and images are removed (a Markdown image in a rendered report is a classic exfiltration channel),
    HTML is stripped, and instruction-like text is withheld entirely.
    """
    s = "" if text is None else str(text)
    removed: List[str] = []
    s, n = _ZERO_WIDTH.subn("", s)
    s, n2 = _BIDI.subn("", s)
    if n or n2:
        removed.append("invisible characters")
    s = _CTRL.sub(" ", s)
    if _MD_IMAGE.search(s):
        removed.append("image")
        s = _MD_IMAGE.sub("[image removed]", s)
    if _MD_LINK.search(s):
        removed.append("link")
        s = _MD_LINK.sub(r"\1", s)
    if _ANY_URL.search(s):
        removed.append("link")
        s = _ANY_URL.sub("[link removed]", s)
    if _TAG.search(s):
        removed.append("HTML")
        s = _TAG.sub("", s)
    if _INSTRUCTION.search(s):
        removed.append("instruction-like text")
        s = WITHHELD
    s = " ".join(s.split())
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s, removed


def strip_links_after_restore(text: str) -> str:
    """Restoring placeholders can bring source URLs back. Keep them as plain text, never as Markdown links."""
    text = _MD_IMAGE.sub("[image removed]", text)
    return _MD_LINK.sub(r"\1", text)


def normalize_for_match(text: str) -> str:
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return " ".join(text.split()).casefold()
