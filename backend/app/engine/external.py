"""Optional best-of-breed scanners, used when they are installed.

Assay's own rules always run. When bandit / semgrep / gitleaks / pip-audit /
npm / osv-scanner / trivy are on the PATH (or in the venv), their results are
normalised into the same Finding model, mapped onto Assay rule ids where the
meaning overlaps (so duplicates corroborate instead of double-counting), and
the report states exactly which scanners ran — an honest coverage statement
matters more than a long list of tools.

None of these is allowed to execute the audited project: no `pip install`, no
`npm install`, no build. Network-dependent scanners (pip-audit, npm audit,
osv-scanner online mode) simply fail and are reported as such in an
air-gapped environment.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .context import Ctx
from .models import ScannerRun, Severity
from .workspace import SKIP_DIRS

BANDIT_MAP = {
    "B602": "SEC-001", "B605": "SEC-001", "B604": "SEC-001", "B609": "SEC-001", "B607": None,
    "B307": "SEC-002", "B102": "SEC-002", "B608": "SEC-003", "B301": "SEC-004", "B302": "SEC-004", "B506": "SEC-004", "B403": None,
    "B501": "SEC-008", "B323": "SEC-008", "B303": "SEC-009", "B324": "SEC-009", "B304": "SEC-009", "B305": "SEC-009",
    "B311": "SEC-010", "B104": "SEC-012", "B201": "SEC-013", "B105": "SEC-007", "B106": "SEC-007", "B107": "SEC-007",
    "B313": "SEC-014", "B314": "SEC-014", "B318": "SEC-014", "B320": "SEC-014", "B405": None, "B408": None,
    "B113": "REL-001", "B110": "REL-002", "B112": "REL-002", "B202": "SEC-020", "B701": "SEC-017", "B702": "SEC-017",
    "B108": None, "B101": None, "B404": None, "B603": None, "B606": None,
}
SEV_MAP = {"CRITICAL": Severity.critical, "HIGH": Severity.high, "ERROR": Severity.high, "MEDIUM": Severity.medium,
           "MODERATE": Severity.medium, "WARNING": Severity.medium, "LOW": Severity.low, "INFO": Severity.info, "UNKNOWN": Severity.medium}
EXCLUDES = ["node_modules", ".venv", "venv", "dist", "build", ".git", "__pycache__", "tests", "test"]


def which(name: str) -> str | None:
    venv_bin = Path(sys.executable).parent
    for cand in (venv_bin / name, venv_bin / f"{name}.exe"):
        if cand.exists():
            return str(cand)
    return shutil.which(name)


def availability() -> dict[str, str | None]:
    return {
        "bandit": which("bandit"), "semgrep": which("semgrep"), "gitleaks": which("gitleaks"),
        "pip-audit": which("pip-audit"), "npm-audit": which("npm"), "osv-scanner": which("osv-scanner"), "trivy": which("trivy"),
    }


def _run(cmd: list[str], cwd: Path | None, timeout: int, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, **(env or {})}, encoding="utf-8", errors="replace")


def _rel(ctx: Ctx, path: str) -> str:
    try:
        return Path(path).resolve().relative_to(ctx.ws.root).as_posix()
    except (ValueError, OSError):
        return path.replace("\\", "/").lstrip("./")


def _vuln(ctx: Ctx, scanner: str, rel: str, message: str, severity: Severity) -> bool:
    """Known-vulnerable dependency: always its own finding (never merged by location)."""
    if _vendored(rel):
        return False
    return ctx.add("SEC-025", file=rel, message=message, severity=severity, confidence="high", source=scanner) is not None


def _vendored(rel: str) -> bool:
    """Third-party / generated code (a .venv or node_modules nested anywhere) is not the audited project."""
    parts = rel.replace("\\", "/").split("/")[:-1]
    return any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts)


def _merge(ctx: Ctx, scanner: str, rule_id: str | None, rel: str, line: int, title: str, message: str,
           severity: Severity, confidence: str = "medium") -> bool:
    """Corroborate an existing finding when the meaning overlaps, else add a new one. Returns True if new."""
    if _vendored(rel):
        return False
    if rule_id:
        for f in ctx.findings:
            if f.rule_id == rule_id and f.file == rel and abs(f.line - line) <= 2:
                if scanner not in f.source:
                    f.source += f"+{scanner}"
                f.confidence = "high"
                return False
    sf = ctx.ws.get(rel)
    f = ctx.add(rule_id or f"EXT-{scanner.upper()}", sf if (sf and line) else None, line if sf else 0,
                file=None if sf else rel, message=message, severity=severity if not rule_id or severity else None,
                confidence=confidence, source=scanner, title=None if rule_id else title)
    if f and not rule_id:
        f.remediation = f.remediation or "See the scanner documentation for this rule and apply the recommended fix."
        f.description = f.description or title
    return f is not None


# --------------------------------------------------------------------------- adapters
def _skip_dirs(root: Path) -> set[str]:
    out = set()
    for dirpath, dirnames, _ in os.walk(root):
        for d in list(dirnames):
            if d in SKIP_DIRS:
                out.add(str(Path(dirpath) / d))
                dirnames.remove(d)          # never descend into vendored trees
    return out


def run_bandit(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    py = ctx.ws.by_language("python")
    if not py:
        return ScannerRun(name="bandit", status="skipped", detail="no Python sources")
    excl = ",".join(sorted(_skip_dirs(ctx.ws.root) | {str(ctx.ws.root / e) for e in EXCLUDES}))
    proc = _run([exe, "-r", str(ctx.ws.root), "-f", "json", "-q", "-x", excl], None, timeout)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ScannerRun(name="bandit", status="error", detail=(proc.stderr or "invalid output")[-300:])
    n = 0
    for r in data.get("results", []):
        tid = r.get("test_id", "")
        if tid in BANDIT_MAP and BANDIT_MAP[tid] is None:
            continue
        rule = BANDIT_MAP.get(tid)
        sev = SEV_MAP.get(r.get("issue_severity", "MEDIUM"), Severity.medium)
        conf = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(r.get("issue_confidence", "MEDIUM"), "medium")
        if _merge(ctx, "bandit", rule, _rel(ctx, r.get("filename", "")), int(r.get("line_number", 0)),
                  f"Bandit {tid}: {r.get('test_name', '')}", r.get("issue_text", ""), sev, conf):
            n += 1
    return ScannerRun(name="bandit", status="ok", findings=n, detail=f"{len(data.get('results', []))} raw results")


def run_semgrep(ctx: Ctx, exe: str, timeout: int, config: str) -> ScannerRun:
    proc = _run([exe, "scan", "--config", config or "auto", "--json", "--quiet", "--metrics=off", "--timeout", "30",
                 *sum([["--exclude", e] for e in EXCLUDES], []), str(ctx.ws.root)], None, timeout,
                env={"SEMGREP_SEND_METRICS": "off"})
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ScannerRun(name="semgrep", status="error", detail=(proc.stderr or "invalid output")[-300:])
    n = 0
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = SEV_MAP.get(str(extra.get("severity", "WARNING")).upper(), Severity.medium)
        cwe = " ".join(extra.get("metadata", {}).get("cwe", []) if isinstance(extra.get("metadata", {}).get("cwe"), list) else [])
        rule = "SEC-001" if "CWE-78" in cwe else "SEC-003" if "CWE-89" in cwe else "SEC-002" if "CWE-95" in cwe else \
            "SEC-005" if "CWE-22" in cwe else "SEC-006" if "CWE-918" in cwe else "SEC-007" if "CWE-798" in cwe else None
        if _merge(ctx, "semgrep", rule, _rel(ctx, r.get("path", "")), int(r.get("start", {}).get("line", 0)),
                  f"Semgrep: {r.get('check_id', '').split('.')[-1]}", extra.get("message", "")[:400], sev, "medium"):
            n += 1
    errs = data.get("errors", [])
    return ScannerRun(name="semgrep", status="ok", findings=n, detail=f"config={config or 'auto'}; {len(errs)} parse errors")


def run_gitleaks(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gl.json"
        has_git = (ctx.ws.root / ".git").exists()
        cmd = [exe, "detect", "--source", str(ctx.ws.root), "--report-format", "json", "--report-path", str(report), "--redact", "--exit-code", "0"]
        if not has_git:
            cmd.append("--no-git")
        proc = _run(cmd, None, timeout)
        if not report.exists():
            return ScannerRun(name="gitleaks", status="error", detail=(proc.stderr or "no report")[-300:])
        data = json.loads(report.read_text("utf-8") or "[]")
    n = 0
    for r in data or []:
        msg = f"{r.get('Description', 'secret')}" + (f" (in git history, commit {r.get('Commit', '')[:8]})" if r.get("Commit") else "")
        if _merge(ctx, "gitleaks", "SEC-007", _rel(ctx, r.get("File", "")), int(r.get("StartLine", 0)), "Secret", msg, Severity.critical, "high"):
            n += 1
    return ScannerRun(name="gitleaks", status="ok", findings=n, detail=("git history scanned" if has_git else "working tree only"))


def run_pip_audit(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    reqs = [r for r in ctx.ws.other_files if re.search(r"(^|/)requirements[\w.-]*\.txt$", r)]
    if not reqs:
        return ScannerRun(name="pip-audit", status="skipped", detail="no requirements*.txt (pip-audit is never run on pyproject/setup.py: that would execute project code)")
    n, details = 0, []
    for rel in reqs[:4]:
        content = ctx.ws.read(rel)
        pinned_all = all(re.search(r"==", l) for l in content.splitlines() if l.strip() and not l.strip().startswith(("#", "-")))
        if not pinned_all:
            details.append(f"{rel}: skipped (not fully pinned)")
            continue
        proc = _run([exe, "-r", str(ctx.ws.root / rel), "--no-deps", "--disable-pip", "-f", "json", "--progress-spinner", "off"], None, timeout)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            details.append(f"{rel}: error {(proc.stderr or '')[-160:]}")
            continue
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                fix = ", ".join(v.get("fix_versions", [])) or "none published"
                if _vuln(ctx, "pip-audit", rel, f"{dep.get('name')} {dep.get('version')}: {v.get('id')} — fixed in {fix}. {v.get('description', '')[:200]}", Severity.high):
                    n += 1
        details.append(f"{rel}: ok")
    return ScannerRun(name="pip-audit", status="ok" if any("ok" in d for d in details) else "skipped", findings=n, detail="; ".join(details))


def run_npm_audit(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    locks = [r for r in ctx.ws.other_files if r.endswith("package-lock.json") and "node_modules" not in r]
    if not locks:
        return ScannerRun(name="npm-audit", status="skipped", detail="no package-lock.json")
    n = 0
    for rel in locks[:3]:
        cwd = (ctx.ws.root / rel).parent
        proc = _run([exe, "audit", "--json", "--package-lock-only", "--ignore-scripts", "--omit=dev"], cwd, timeout)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return ScannerRun(name="npm-audit", status="error", detail=(proc.stderr or "")[-300:])
        if "error" in data:
            return ScannerRun(name="npm-audit", status="error", detail=str(data["error"].get("summary", data["error"]))[:300])
        for name, v in (data.get("vulnerabilities") or {}).items():
            sev = SEV_MAP.get(str(v.get("severity", "moderate")).upper(), Severity.medium)
            via = [x.get("title", "") for x in v.get("via", []) if isinstance(x, dict)][:2]
            fix = v.get("fixAvailable")
            msg = f"{name} {v.get('range', '')}: {'; '.join(via) or 'transitive advisory'}. Fix available: {bool(fix)}."
            if _vuln(ctx, "npm-audit", rel, msg, sev):
                n += 1
    return ScannerRun(name="npm-audit", status="ok", findings=n)


def run_osv(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    proc = _run([exe, "scan", "source", "-r", "--format", "json", str(ctx.ws.root)], None, timeout)
    if proc.returncode not in (0, 1) or not proc.stdout.strip().startswith("{"):
        proc = _run([exe, "--format", "json", "-r", str(ctx.ws.root)], None, timeout)      # v1 CLI
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ScannerRun(name="osv-scanner", status="error", detail=(proc.stderr or "")[-300:])
    n = 0
    for res in data.get("results", []):
        rel = _rel(ctx, res.get("source", {}).get("path", ""))
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            ids = [v.get("id") for v in pkg.get("vulnerabilities", [])]
            if ids and _vuln(ctx, "osv-scanner", rel, f"{p.get('name')} {p.get('version')}: {', '.join(ids[:5])}", Severity.high):
                n += 1
    return ScannerRun(name="osv-scanner", status="ok", findings=n)


def run_trivy(ctx: Ctx, exe: str, timeout: int) -> ScannerRun:
    proc = _run([exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig", str(ctx.ws.root)], None, timeout)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ScannerRun(name="trivy", status="error", detail=(proc.stderr or "")[-300:])
    n = 0
    for res in data.get("Results", []) or []:
        rel = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            if _vuln(ctx, "trivy", rel, f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('VulnerabilityID')} (fixed {v.get('FixedVersion') or 'n/a'})",
                     SEV_MAP.get(v.get("Severity", "MEDIUM"), Severity.medium)):
                n += 1
        for mc in res.get("Misconfigurations", []) or []:
            if _merge(ctx, "trivy", None, rel, int(mc.get("CauseMetadata", {}).get("StartLine", 0) or 0), f"Trivy {mc.get('ID')}: {mc.get('Title')}",
                      mc.get("Message", "")[:300], SEV_MAP.get(mc.get("Severity", "MEDIUM"), Severity.medium), "medium"):
                n += 1
    return ScannerRun(name="trivy", status="ok", findings=n)


ADAPTERS = {
    "bandit": run_bandit, "gitleaks": run_gitleaks, "pip-audit": run_pip_audit,
    "npm-audit": run_npm_audit, "osv-scanner": run_osv, "trivy": run_trivy,
}


def run_external(ctx: Ctx, wanted: list[str], timeout: int, semgrep_config: str, log) -> list[ScannerRun]:
    avail = availability()
    runs: list[ScannerRun] = []
    for name in ["bandit", "semgrep", "gitleaks", "pip-audit", "npm-audit", "osv-scanner", "trivy"]:
        if name not in wanted:
            continue
        exe = avail.get(name)
        if not exe:
            runs.append(ScannerRun(name=name, status="unavailable", detail="not installed on this host"))
            continue
        t0 = time.time()
        log(f"Running {name}…")
        try:
            run = run_semgrep(ctx, exe, timeout, semgrep_config) if name == "semgrep" else ADAPTERS[name](ctx, exe, timeout)
        except subprocess.TimeoutExpired:
            run = ScannerRun(name=name, status="error", detail=f"timed out after {timeout}s")
        except Exception as e:      # a broken scanner must never break the audit
            run = ScannerRun(name=name, status="error", detail=f"{type(e).__name__}: {e}"[:300])
        run.duration_s = round(time.time() - t0, 1)
        runs.append(run)
    return runs
