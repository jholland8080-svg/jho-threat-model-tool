"""
Load the documents the assistant reads (design docs, Confluence/HTML exports, diagrams as text).

Everything here is treated as UNTRUSTED: an architecture doc can be written by anyone, and an attacker
(or a hurried team) can plant text meant for the AI. So, in code, before the model sees anything:
  1. Only regular text files of known types, within size limits. No symlinks.
  2. Hidden content is removed (the model sees what a human reviewer sees).
  3. Instruction-like text is detected and recorded for the reviewer.
  4. Sensitive identifiers are redacted.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from .safety import Redactor, find_instructions, html_to_text, strip_hidden

TEXT_TYPES = {".md", ".markdown", ".txt", ".yaml", ".yml", ".mmd", ".json", ".csv", ".html", ".htm"}
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 600_000
MAX_FILES = 25


class SourceError(Exception):
    pass


def _collect(paths: List[str]) -> List[str]:
    files: List[str] = []
    for p in paths:
        if os.path.islink(p):
            raise SourceError(f"{p}: symlinks are not followed")
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for n in sorted(names):
                    full = os.path.join(root, n)
                    if not n.startswith(".") and not os.path.islink(full) and \
                            os.path.splitext(n)[1].lower() in TEXT_TYPES:
                        files.append(full)
        elif os.path.isfile(p):
            if os.path.splitext(p)[1].lower() not in TEXT_TYPES:
                raise SourceError(f"{p}: unsupported file type (text formats only: {', '.join(sorted(TEXT_TYPES))})")
            files.append(p)
        else:
            raise SourceError(f"{p}: not found")
    if not files:
        raise SourceError("No readable source documents found.")
    if len(files) > MAX_FILES:
        raise SourceError(f"Too many source files ({len(files)}; limit {MAX_FILES}). Pass a narrower set.")
    return files


def load_sources(paths: List[str], redactor: Redactor) -> List[Dict[str, Any]]:
    """Returns one dict per document: id, file, title, text (visible + redacted), hidden_notes, instructions."""
    sources: List[Dict[str, Any]] = []
    total = 0
    for i, path in enumerate(_collect(paths), start=1):
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            raise SourceError(f"{path}: {size} bytes is over the {MAX_FILE_BYTES}-byte limit per file")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise SourceError(f"Sources total more than {MAX_TOTAL_BYTES} bytes. Pass fewer or smaller documents.")
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        visible, hidden_notes = strip_hidden(raw)
        if os.path.splitext(path)[1].lower() in (".html", ".htm"):
            visible = html_to_text(visible)
        sid = f"S{i}"
        sources.append({
            "id": sid,
            "file": path,
            "title": redactor.redact(os.path.basename(path)),
            "text": redactor.redact(visible),
            "hidden_notes": hidden_notes,
            # Scan the raw file, hidden parts included: the reviewer should know what hidden text tried to say.
            "instructions": find_instructions(raw),
        })
    return sources
