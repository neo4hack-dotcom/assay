"""REST API — everything under /api."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError

from ..deps import LLM_KEYS, container as c
from ..engine import __version__, catalog
from ..engine.external import availability
from ..engine.llm import LlmClient
from ..engine.models import AuditOptions, AuditResult, SourceSpec
from ..reports.exports import FORMATS, render

router = APIRouter(prefix="/api")
DOC_EXT = {".md", ".txt", ".pdf", ".docx", ".html", ".htm", ".rst", ".adoc"}


def _get(audit_id: str) -> AuditResult:
    a = c.store.get(audit_id)
    if a is None:
        raise HTTPException(404, "audit not found")
    return a


def summary(a: AuditResult) -> dict:
    v = a.verdict
    return {
        "id": a.id, "project": a.project, "created_at": a.created_at, "finished_at": a.finished_at, "status": a.status,
        "progress": a.progress, "stage": a.stage, "error": a.error, "source": a.source.model_dump(),
        "readiness": v.readiness if v else None, "decision": v.decision if v else None, "label": v.label if v else None,
        "sustainability": v.sustainability if v else None, "confidence": v.confidence if v else None,
        "scores": {s.dimension.value: s.score for s in a.scores},
        "counts": {sev: sum(1 for f in a.findings if f.status == "open" and f.severity.value == sev) for sev in ("critical", "high", "medium", "low")},
        "tools": len([t for t in a.server.tools if t.kind == "tool"]), "llm_model": a.llm_model, "commit": a.commit,
        "comparison": a.comparison,
    }


# ------------------------------------------------------------------ health / meta
@router.get("/health")
async def health():
    cfg = c.llm_config()
    return {"ok": True, "app": c.settings.app_name, "version": __version__, "llm_configured": cfg.configured,
            "llm_model": cfg.model, "auth_required": bool(c.settings.auth_token)}


@router.get("/rules")
async def rules():
    from ..engine.custom_rules import load_custom_rules
    load_custom_rules(c.settings.custom_rules_dir or str(c.store.root / "rules"))
    return [r.as_dict() for r in sorted(catalog.RULES.values(), key=lambda r: r.id)]


@router.get("/scanners")
async def scanners():
    return [{"name": k, "available": bool(v), "path": v or ""} for k, v in availability().items()]


# ------------------------------------------------------------------ settings
class LlmSettingsBody(BaseModel):
    base_url: str = ""
    api_key: str | None = None
    model: str = ""
    temperature: float = Field(0.1, ge=0, le=2)
    max_output_tokens: int = Field(1800, ge=128, le=32000)
    context_window: int = Field(16384, ge=2048, le=2_000_000)
    timeout_s: int = Field(180, ge=10, le=1800)
    max_concurrency: int = Field(2, ge=1, le=32)
    json_mode: bool = True
    verify_tls: bool = True
    ca_bundle: str = ""
    auth_header: Literal["bearer", "api-key", "none"] = "bearer"
    api_version: str = ""
    extra_headers: dict[str, str] = Field(default_factory=dict)


class ScannerSettingsBody(BaseModel):
    timeout_s: int = Field(300, ge=30, le=3600)
    semgrep_config: str = "auto"
    default_tools: list[str] = Field(default_factory=lambda: ["bandit", "semgrep", "gitleaks", "pip-audit", "npm-audit", "osv-scanner"])


def _llm_public() -> dict:
    cfg = c.llm_config()
    d = {k: getattr(cfg, k) for k in LLM_KEYS}
    d["api_key"] = ("••••••••" + cfg.api_key[-4:]) if cfg.api_key else ""
    d["api_key_set"] = bool(cfg.api_key)
    return d


@router.get("/settings")
async def get_settings():
    prefs = c.scanner_prefs()
    return {"llm": _llm_public(), "scanners": ScannerSettingsBody(**prefs).model_dump(),
            "server": {"host": c.settings.host, "port": c.settings.port, "data_dir": str(c.store.root),
                       "allowed_roots": [str(r) for r in c.settings.roots], "auth_required": bool(c.settings.auth_token),
                       "policy_file": c.settings.policy_file, "custom_rules_dir": c.settings.custom_rules_dir or str(c.store.root / "rules"),
                       "version": __version__}}


@router.put("/settings/llm")
async def put_llm(body: LlmSettingsBody):
    data = c.store.load_settings()
    cur = data.get("llm", {})
    new = body.model_dump()
    if body.api_key is None or str(body.api_key).startswith("•"):
        new["api_key"] = cur.get("api_key", c.settings.llm_api_key)
    new["base_url"] = new["base_url"].strip().rstrip("/")
    data["llm"] = new
    c.store.save_settings(data)
    return _llm_public()


@router.put("/settings/scanners")
async def put_scanners(body: ScannerSettingsBody):
    data = c.store.load_settings()
    data["scanners"] = body.model_dump()
    c.store.save_settings(data)
    return data["scanners"]


@router.post("/llm/test")
async def llm_test(body: LlmSettingsBody | None = None):
    """Test the given (unsaved) settings, or the saved ones when no body is sent."""
    import asyncio
    cfg = c.llm_config(body.model_dump() if body else None)
    return await asyncio.to_thread(LlmClient(cfg).test_connection)


@router.post("/llm/models")
async def llm_models(body: LlmSettingsBody | None = None):
    import asyncio
    cfg = c.llm_config(body.model_dump() if body else None)
    try:
        return {"models": await asyncio.to_thread(LlmClient(cfg).list_models)}
    except Exception as e:
        raise HTTPException(502, f"Could not list models: {e}") from e


# ------------------------------------------------------------------ file system helper (local path picker)
def _path_allowed(p: Path) -> bool:
    roots = c.settings.roots
    if not roots:
        return True
    return any(p == r or r in p.parents for r in roots)


@router.get("/browse")
async def browse(path: str = ""):
    roots = c.settings.roots
    if not path:
        if roots:
            return {"path": "", "parent": None, "dirs": [{"name": str(r), "path": str(r)} for r in roots]}
        path = str(Path.home())
    p = Path(path).expanduser().resolve()
    if not _path_allowed(p):
        raise HTTPException(403, "This folder is outside ASSAY_ALLOWED_ROOTS.")
    if not p.is_dir():
        raise HTTPException(404, "not a folder")
    dirs = []
    try:
        for e in sorted(p.iterdir(), key=lambda e: e.name.lower()):
            if e.is_dir() and not e.name.startswith(".") and e.name not in ("node_modules", "__pycache__"):
                markers = [m for m in ("package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", ".git") if (e / m).exists()]
                dirs.append({"name": e.name, "path": str(e), "project": bool(markers)})
    except PermissionError:
        pass
    parent = str(p.parent) if p.parent != p and _path_allowed(p.parent) else None
    return {"path": str(p), "parent": parent, "dirs": dirs[:500]}


# ------------------------------------------------------------------ audits
@router.get("/audits")
async def list_audits():
    return [summary(a) for a in c.store.all()]


@router.get("/portfolio")
async def portfolio():
    """Latest completed audit per project — the organisation-wide view."""
    latest: dict[str, AuditResult] = {}
    for a in c.store.all():
        if a.status == "done" and (a.project not in latest or a.created_at > latest[a.project].created_at):
            latest[a.project] = a
    return sorted((summary(a) for a in latest.values()), key=lambda s: (s["readiness"] or 0))


@router.post("/audits")
async def create_audit(payload: str = Form(...), archive: UploadFile | None = File(None), docs: list[UploadFile] | None = File(None)):
    try:
        body = json.loads(payload)
        source = SourceSpec(**body.get("source", {}))
        options = AuditOptions(**body.get("options", {}))
    except (json.JSONDecodeError, ValidationError, TypeError) as e:
        raise HTTPException(400, f"invalid payload: {e}") from e
    project = str(body.get("project") or "").strip()
    if source.kind == "path":
        p = Path(source.location).expanduser().resolve()
        if not p.is_dir():
            raise HTTPException(400, f"Folder not found on the Assay server: {p}")
        if not _path_allowed(p):
            raise HTTPException(403, "This folder is outside ASSAY_ALLOWED_ROOTS.")
        source.location = str(p)
        project = project or p.name
    elif source.kind == "git":
        if not re.match(r"^(https?://|ssh://|git@)", source.location.strip()):
            raise HTTPException(400, "Git URL must start with https://, ssh:// or git@")
        project = project or re.sub(r"\.git$", "", source.location.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1])
    stamp = f"{int(time.time() * 1000)}"
    up_dir = c.store.uploads_dir / stamp
    zip_path = None
    if source.kind == "zip":
        if archive is None or not archive.filename:
            raise HTTPException(400, "A .zip archive is required for this source type.")
        up_dir.mkdir(parents=True, exist_ok=True)
        zip_path = up_dir / "source.zip"
        size = await _save_upload(archive, zip_path, c.settings.max_upload_mb)
        source.location = f"{archive.filename} ({size / 1e6:.1f} MB)"
        project = project or re.sub(r"\.zip$", "", archive.filename, flags=re.I)
    doc_paths: list[Path] = []
    for d in docs or []:
        if not d.filename:
            continue
        ext = Path(d.filename).suffix.lower()
        if ext not in DOC_EXT:
            raise HTTPException(400, f"Unsupported documentation format: {d.filename} (use {', '.join(sorted(DOC_EXT))})")
        up_dir.mkdir(parents=True, exist_ok=True)
        target = up_dir / f"doc_{len(doc_paths)}_{re.sub(r'[^A-Za-z0-9._-]', '_', Path(d.filename).name)}"
        await _save_upload(d, target, 50)
        doc_paths.append(target)
    a = c.create_audit(project, source, options, zip_path, doc_paths)
    return summary(a)


async def _save_upload(f: UploadFile, target: Path, max_mb: int) -> int:
    size = 0
    with open(target, "wb") as out:
        while chunk := await f.read(1 << 20):
            size += len(chunk)
            if size > max_mb * 1_000_000:
                out.close()
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"Upload exceeds {max_mb} MB.")
            out.write(chunk)
    return size


@router.get("/audits/{audit_id}")
async def get_audit(audit_id: str):
    return _get(audit_id)


@router.get("/audits/{audit_id}/status")
async def get_status(audit_id: str):
    a = _get(audit_id)
    return {**summary(a), "logs": [l.model_dump() for l in a.logs[-80:]]}


@router.delete("/audits/{audit_id}")
async def delete_audit(audit_id: str):
    a = _get(audit_id)
    if a.status in ("queued", "running"):
        c.cancel(audit_id)
    c.store.delete(audit_id)
    return {"ok": True}


@router.post("/audits/{audit_id}/cancel")
async def cancel_audit(audit_id: str):
    _get(audit_id)
    c.cancel(audit_id)
    return {"ok": True}


@router.post("/audits/{audit_id}/rerun")
async def rerun(audit_id: str):
    a = _get(audit_id)
    if a.source.kind == "zip":
        raise HTTPException(400, "Uploaded archives are not kept: upload the new version instead.")
    if a.source.kind == "git" and "***@" in a.source.location:
        raise HTTPException(400, "The git URL contained credentials, which are never stored: start a new audit with the URL.")
    b = c.create_audit(a.project, a.source.model_copy(), a.options.model_copy(deep=True))
    return summary(b)


class TriageBody(BaseModel):
    status: Literal["open", "accepted", "false_positive"]
    reason: str = Field("", max_length=2000)
    by: str = Field("", max_length=120)
    remember: bool = True


@router.patch("/audits/{audit_id}/findings/{fingerprint}")
async def triage(audit_id: str, fingerprint: str, body: TriageBody):
    a = _get(audit_id)
    if a.status != "done":
        raise HTTPException(409, "audit not finished")
    hits = [f for f in a.findings if f.fingerprint == fingerprint]
    if not hits:
        raise HTTPException(404, "finding not found")
    if body.status != "open" and len(body.reason.strip()) < 5:
        raise HTTPException(400, "A justification is required to accept a risk or mark a false positive.")
    for f in hits:
        f.status = body.status
        f.status_reason = (body.reason.strip() + (f" — {body.by}" if body.by else "")) if body.status != "open" else ""
    if body.remember:
        c.store.remember_triage(a.project, fingerprint, body.status, body.reason.strip(), body.by)
    c.rescore(a)
    return summary(a)


@router.get("/audits/{audit_id}/report/{fmt}")
async def report(audit_id: str, fmt: str):
    a = _get(audit_id)
    if fmt not in FORMATS:
        raise HTTPException(400, f"format must be one of {', '.join(FORMATS)}")
    if a.status != "done":
        raise HTTPException(409, "audit not finished")
    mime, ext = FORMATS[fmt]
    cache = c.store.reports_dir / a.id / f"report.{ext}"
    if not cache.exists():
        import asyncio
        data = await asyncio.to_thread(render, a, fmt)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", a.project).strip("-") or "mcp"
    stamp = time.strftime("%Y%m%d", time.localtime(a.finished_at or a.created_at))
    return Response(cache.read_bytes(), media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="assay-{safe}-{stamp}.{ext}"'})


@router.get("/audits/{audit_id}/compare/{other_id}")
async def compare_audits(audit_id: str, other_id: str):
    a, b = _get(audit_id), _get(other_id)
    fa = {f.fingerprint: f for f in a.findings if f.status == "open"}
    fb = {f.fingerprint: f for f in b.findings if f.status == "open"}
    pick = lambda fs: [{"rule_id": f.rule_id, "title": f.title, "severity": f.severity.value, "file": f.file, "line": f.line} for f in fs][:200]
    return {"a": summary(a), "b": summary(b), "fixed": pick(fb[k] for k in fb.keys() - fa.keys()),
            "new": pick(fa[k] for k in fa.keys() - fb.keys()), "persisting": len(fa.keys() & fb.keys())}

