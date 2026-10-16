"""Persistence: one JSON file per audit + a settings file, written atomically.

One file per audit keeps writes small and lets several audits progress in
parallel without rewriting a shared document. Summaries are cached in memory.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

from .engine.models import AuditResult


def _atomic_write(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, "utf-8")
    os.replace(tmp, path)


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.audits_dir = root / "audits"
        self.reports_dir = root / "reports"
        self.uploads_dir = root / "uploads"
        self.work_dir = root / "workspaces"
        for d in (self.audits_dir, self.reports_dir, self.uploads_dir, self.work_dir, root / "rules"):
            d.mkdir(parents=True, exist_ok=True)
        self.settings_path = root / "settings.json"
        self._lock = threading.RLock()
        self._cache: dict[str, AuditResult] = {}
        for p in self.audits_dir.glob("*.json"):
            try:
                a = AuditResult.model_validate_json(p.read_text("utf-8"))
                self._cache[a.id] = a
            except Exception:
                continue

    # ------------------------------------------------------------ audits
    def save(self, a: AuditResult) -> None:
        with self._lock:
            self._cache[a.id] = a
            _atomic_write(self.audits_dir / f"{a.id}.json", a.model_dump_json())

    def get(self, audit_id: str) -> AuditResult | None:
        return self._cache.get(audit_id)

    def all(self) -> list[AuditResult]:
        return sorted(self._cache.values(), key=lambda a: -a.created_at)

    def delete(self, audit_id: str) -> None:
        with self._lock:
            self._cache.pop(audit_id, None)
            (self.audits_dir / f"{audit_id}.json").unlink(missing_ok=True)
            shutil.rmtree(self.reports_dir / audit_id, ignore_errors=True)
            shutil.rmtree(self.uploads_dir / audit_id, ignore_errors=True)
            shutil.rmtree(self.work_dir / audit_id, ignore_errors=True)

    def previous_of(self, a: AuditResult) -> AuditResult | None:
        cands = [x for x in self._cache.values() if x.project == a.project and x.id != a.id and x.status == "done" and x.created_at < a.created_at]
        return max(cands, key=lambda x: x.created_at) if cands else None

    def invalidate_reports(self, audit_id: str) -> None:
        shutil.rmtree(self.reports_dir / audit_id, ignore_errors=True)

    # ------------------------------------------------------------ triage memory
    def triage_path(self) -> Path:
        return self.root / "triage.json"

    def load_triage(self) -> dict:
        p = self.triage_path()
        return json.loads(p.read_text("utf-8")) if p.exists() else {}

    def remember_triage(self, project: str, fingerprint: str, status: str, reason: str, by: str) -> None:
        """Decisions survive re-audits: the same finding in the next audit of this project inherits them."""
        with self._lock:
            data = self.load_triage()
            proj = data.setdefault(project, {})
            if status == "open":
                proj.pop(fingerprint, None)
            else:
                proj[fingerprint] = {"status": status, "reason": reason, "by": by}
            _atomic_write(self.triage_path(), json.dumps(data, indent=1))

    # ------------------------------------------------------------ settings
    def load_settings(self) -> dict:
        if self.settings_path.exists():
            try:
                return json.loads(self.settings_path.read_text("utf-8"))
            except json.JSONDecodeError:
                return {}
        return {}

    def save_settings(self, data: dict) -> None:
        with self._lock:
            _atomic_write(self.settings_path, json.dumps(data, indent=1))
