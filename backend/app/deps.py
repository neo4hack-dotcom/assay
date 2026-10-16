"""Dependency container + background job runner."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import settings
from .engine.llm import LlmConfig
from .engine.models import AuditOptions, AuditResult, SourceSpec, StageLog
from .engine.pipeline import PipelineSettings, finalize_scores, run_audit
from .engine.policy import load_policy
from .store import Store

LLM_KEYS = ("base_url", "api_key", "model", "temperature", "max_output_tokens", "context_window", "timeout_s", "max_concurrency",
            "json_mode", "verify_tls", "ca_bundle", "auth_header", "api_version", "extra_headers")


class Container:
    def __init__(self):
        self.settings = settings
        self.store = Store(settings.data)
        self.pool = ThreadPoolExecutor(max_workers=max(1, settings.max_parallel_audits), thread_name_prefix="audit")
        self._cancel: set[str] = set()
        self._recover()

    # ------------------------------------------------------------ settings
    def llm_config(self, override: dict | None = None) -> LlmConfig:
        s = self.settings
        base = {"base_url": s.llm_base_url, "api_key": s.llm_api_key, "model": s.llm_model, "context_window": s.llm_context_window,
                "max_output_tokens": s.llm_max_output_tokens, "timeout_s": s.llm_timeout_s, "max_concurrency": s.llm_max_concurrency,
                "verify_tls": s.llm_verify_tls, "ca_bundle": s.llm_ca_bundle}
        saved = self.store.load_settings().get("llm", {})
        base.update({k: v for k, v in saved.items() if k in LLM_KEYS})
        if override:
            for k, v in override.items():
                if k in LLM_KEYS and not (k == "api_key" and (v is None or str(v).startswith("•"))):
                    base[k] = v
        return LlmConfig.from_dict(base)

    def scanner_prefs(self) -> dict:
        return self.store.load_settings().get("scanners", {})

    def pipeline_settings(self) -> PipelineSettings:
        s = self.settings
        prefs = self.scanner_prefs()
        return PipelineSettings(
            work_dir=self.store.work_dir, llm=self.llm_config(), scanner_timeout=int(prefs.get("timeout_s", s.scanner_timeout_s)),
            semgrep_config=prefs.get("semgrep_config", s.semgrep_config), policy_file=s.policy_file,
            custom_rules_dir=s.custom_rules_dir or str(self.store.root / "rules"), max_zip_mb=s.max_upload_mb,
            keep_workspace=s.keep_workspaces)

    def policy(self) -> dict:
        return load_policy(self.settings.policy_file)

    # ------------------------------------------------------------ jobs
    def _recover(self) -> None:
        for a in self.store.all():
            if a.status in ("queued", "running"):
                a.status, a.error = "failed", "Interrupted: the Assay server restarted during the audit."
                a.logs.append(StageLog(ts=time.time(), stage=a.stage, message=a.error, level="error"))
                self.store.save(a)

    def create_audit(self, project: str, source: SourceSpec, options: AuditOptions, zip_path: Path | None = None,
                     docs: list[Path] | None = None) -> AuditResult:
        a = AuditResult(id=uuid.uuid4().hex[:12], project=project.strip() or "unnamed-mcp", created_at=time.time(), source=source, options=options)
        self.store.save(a)
        self.pool.submit(self._run, a.id, zip_path, docs or [])
        return a

    def _run(self, audit_id: str, zip_path: Path | None, docs: list[Path]) -> None:
        a = self.store.get(audit_id)
        if a is None:
            return
        last = [0.0]

        def save(x: AuditResult):
            now = time.time()
            if now - last[0] > 0.4 or x.status in ("done", "failed", "cancelled"):
                last[0] = now
                self.store.save(x)

        prev = self.store.previous_of(a)
        run_audit(a, self.pipeline_settings(), uploaded_zip=zip_path, uploaded_docs=docs, save=save,
                  cancelled=lambda: audit_id in self._cancel, previous=prev)
        if a.status == "done":
            self.apply_remembered_triage(a)
        if zip_path:
            zip_path.unlink(missing_ok=True)
        self._cancel.discard(audit_id)
        self.store.save(a)

    def apply_remembered_triage(self, a: AuditResult) -> None:
        mem = self.store.load_triage().get(a.project, {})
        changed = False
        for f in a.findings:
            d = mem.get(f.fingerprint)
            if d and f.status == "open":
                f.status, f.status_reason = d["status"], f"{d['reason']} (carried over from a previous audit, by {d.get('by') or 'unknown'})"
                changed = True
        if changed:
            self.rescore(a)

    def rescore(self, a: AuditResult) -> None:
        finalize_scores(a, None, self.policy(), llm_used=bool(a.llm_model), docs_count=len(a.docs_used), previous=self.store.previous_of(a))
        self.store.invalidate_reports(a.id)
        self.store.save(a)

    def cancel(self, audit_id: str) -> None:
        self._cancel.add(audit_id)


container = Container()
