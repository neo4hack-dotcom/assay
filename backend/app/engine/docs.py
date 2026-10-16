"""Collect documentation: what the repository ships plus what the auditor uploads.

Supported uploads: Markdown, text, HTML, PDF (pypdf) and DOCX (parsed from the
OOXML zip directly — no extra dependency). Text is only ever *read*, and is
passed to the LLM inside <untrusted_docs> delimiters.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .workspace import Workspace

DOC_RX = re.compile(r"(^|/)(readme[^/]*|architecture[^/]*|security[^/]*|design[^/]*|(docs?|documentation|wiki|adr)/[^/]+)\.(md|rst|txt|adoc)$", re.I)


def read_doc_file(path: Path, limit: int = 300_000) -> str:
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(str(path))
            return "\n".join((p.extract_text() or "") for p in reader.pages[:200])[:limit]
        if suffix == ".docx":
            with zipfile.ZipFile(path) as z:
                xml = z.read("word/document.xml").decode("utf-8", "replace")
            xml = re.sub(r"</w:p>", "\n", xml)
            return re.sub(r"<[^>]+>", "", xml)[:limit]
        text = path.read_text("utf-8", errors="replace")
        if suffix in (".html", ".htm"):
            text = re.sub(r"<(script|style)[\s\S]*?</\1>", "", text, flags=re.I)
            text = re.sub(r"<[^>]+>", " ", text)
        return text[:limit]
    except Exception as e:          # a corrupt document must not fail the audit
        return f"[could not read {path.name}: {type(e).__name__}]"


def collect_docs(ws: Workspace, uploaded: list[Path], limit: int = 120_000) -> tuple[str, list[str]]:
    parts, used = [], []
    for rel in sorted((r for r in ws.other_files if DOC_RX.search(r) and "node_modules" not in r), key=lambda r: (r.count("/"), r))[:25]:
        txt = ws.read(rel, 40_000)
        if txt.strip():
            parts.append(f"### {rel}\n{txt}")
            used.append(rel)
    for p in uploaded:
        txt = read_doc_file(p)
        if txt.strip():
            parts.append(f"### (uploaded) {p.name}\n{txt}")
            used.append(f"uploaded:{p.name}")
    return "\n\n".join(parts)[:limit], used
