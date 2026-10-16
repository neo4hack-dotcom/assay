"""The audit pipeline: ingest → discover → detect → corroborate → review → score.

Used identically by the web API (in a worker thread) and by the CLI.
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path
from typing import Callable

from . import __version__
from .context import Ctx
from .custom_rules import run_custom_rules
from .docs import collect_docs
from .external import run_external
from .llm import LlmClient, LlmConfig, LlmError
from .llm_review import architecture_review, executive_summary, numbers_consistent, run_tool_reviews, run_triage
from .mcp_discovery import discover
from .models import AuditResult, StageLog
from .policy import load_policy
from .project_checks import run_project_checks
from .python_ast import analyze_python
from .regex_rules import analyze_lines
from .scoring import action_plan, apply_context, compare, dimension_scores, rules_narrative, verdict
from .workspace import IngestError, git_clone, mask_url, safe_extract_zip, scan_tree, unwrap_single_dir


class Cancelled(Exception):
    pass


class PipelineSettings:
    def __init__(self, *, work_dir: Path, llm: LlmConfig, scanner_timeout: int = 300, semgrep_config: str = "auto",
                 policy_file: str = "", custom_rules_dir: str = "", max_zip_mb: int = 500, max_zip_files: int = 50_000,
                 keep_workspace: bool = False):
        self.work_dir = work_dir
        self.llm = llm
        self.scanner_timeout = scanner_timeout
        self.semgrep_config = semgrep_config
        self.policy_file = policy_file
        self.custom_rules_dir = custom_rules_dir
        self.max_zip_mb = max_zip_mb
        self.max_zip_files = max_zip_files
        self.keep_workspace = keep_workspace


def run_audit(audit: AuditResult, ps: PipelineSettings, *, uploaded_zip: Path | None = None, uploaded_docs: list[Path] | None = None,
              save: Callable[[AuditResult], None] = lambda a: None, cancelled: Callable[[], bool] = lambda: False,
              previous: AuditResult | None = None) -> AuditResult:
    def log(msg: str, level: str = "info"):
        audit.logs.append(StageLog(ts=time.time(), stage=audit.stage, message=msg, level=level))
        save(audit)

    def stage(name: str, progress: int):
        if cancelled():
            raise Cancelled()
        audit.stage, audit.progress = name, progress
        log(name)

    audit.status = "running"
    audit.tool_version = __version__
    policy = load_policy(ps.policy_file)
    tmp: Path | None = None
    try:
        # ------------------------------------------------------------ ingest
        stage("Preparing source", 3)
        src = audit.source
        if src.kind == "path":
            root = Path(src.location).expanduser().resolve()
            if not root.is_dir():
                raise IngestError(f"Folder not found or not a directory: {root}")
        elif src.kind == "zip":
            if not uploaded_zip:
                raise IngestError("Uploaded archive is missing.")
            tmp = ps.work_dir / audit.id
            safe_extract_zip(uploaded_zip, tmp, ps.max_zip_mb * 1_000_000, ps.max_zip_files)
            root = unwrap_single_dir(tmp)
        else:
            tmp = ps.work_dir / audit.id
            log(f"Cloning {mask_url(src.location)}" + (f" ({src.ref})" if src.ref else ""))
            git_clone(src.location, tmp, src.ref, timeout=ps.scanner_timeout)
            src.location = mask_url(src.location)
            root = tmp
        if src.subdir:
            sub = (root / src.subdir).resolve()
            if root not in sub.parents and sub != root or not sub.is_dir():
                raise IngestError(f"Sub-folder not found inside the source: {src.subdir}")
            root = sub

        stage("Inventorying files", 8)
        ws = scan_tree(root)
        audit.commit = ws.commit
        log(f"{len(ws.files)} source/config files analysed, {ws.skipped} skipped (generated, minified, too large or symlinks).")
        if not ws.files:
            raise IngestError("No analysable source files found (check the folder / sub-folder).")
        ctx = Ctx(ws=ws, options=audit.options)

        stage("Discovering the MCP surface", 14)
        discover(ctx)
        s = ctx.server
        log(f"MCP: {'detected' if s.detected else 'NOT detected'}; SDK {', '.join(s.sdks) or '—'}; transports {', '.join(s.transports) or '—'}; "
            f"{len([t for t in s.tools if t.kind == 'tool'])} tools, {len([t for t in s.tools if t.kind != 'tool'])} resources/prompts; "
            f"auth {'yes' if s.auth.detected else 'no'}.")

        stage("Running security & code rules", 24)
        analyze_python(ctx)
        analyze_lines(ctx)
        run_custom_rules(ctx, ps.custom_rules_dir)
        stage("Running project, dependency & sustainability checks", 34)
        run_project_checks(ctx, policy)
        ctx.finalize()
        propagate_tool_risk(ctx)
        log(f"{len(ctx.findings)} findings from built-in rules.")

        if audit.options.external_tools:
            stage("Running external scanners", 42)
            audit.scanners = run_external(ctx, audit.options.external_tools, ps.scanner_timeout, ps.semgrep_config, log)
            for r in audit.scanners:
                log(f"{r.name}: {r.status}" + (f" — {r.findings} new finding(s)" if r.status == "ok" else f" — {r.detail}" if r.detail else ""),
                    "warning" if r.status == "error" else "info")

        stage("Collecting documentation", 50)
        docs_text, audit.docs_used = collect_docs(ws, uploaded_docs or [])
        log(f"{len(audit.docs_used)} documentation source(s) found.")

        apply_context(ctx.findings, audit.options.context, ctx.server)

        # ------------------------------------------------------------ LLM
        llm_used = False
        if audit.options.use_llm:
            if not ps.llm.configured:
                log("LLM review requested but no LLM is configured — continuing with static analysis only.", "warning")
            else:
                llm = LlmClient(ps.llm)
                audit.llm_model = ps.llm.model
                try:
                    stage(f"LLM review of tools ({ps.llm.model})", 55)
                    n = run_tool_reviews(llm, ctx, audit.options.depth, log)
                    log(f"{n} tool(s) reviewed by the LLM.")
                    stage("LLM triage of high-severity findings", 70)
                    n2 = run_triage(llm, ctx, audit.options.depth, log)
                    log(f"{n2} finding(s) triaged by the LLM.")
                    llm_used = n + n2 > 0
                except LlmError as e:
                    log(f"LLM unavailable: {e}. Continuing with static results.", "error")

        # ------------------------------------------------------------ score
        stage("Scoring", 82)
        finalize_scores(audit, ctx, policy, llm_used, docs_count=len(audit.docs_used), previous=previous)

        if llm_used:
            try:
                stage("LLM architecture & sustainability assessment", 86)
                arch = architecture_review(llm, ctx, docs_text, audit.scores, audit.verdict)
                if arch:
                    n = audit.narrative
                    for k in ("architecture", "security", "scalability", "performance", "sustainability"):
                        if isinstance(arch.get(k), str) and arch[k].strip():
                            setattr(n, k, arch[k].strip())
                    for k in ("strengths", "key_risks", "conditions"):
                        if isinstance(arch.get(k), list) and arch[k]:
                            setattr(n, k, [str(x) for x in arch[k]][:10])
                    gaps = arch.get("documentation_gaps")
                    if isinstance(gaps, list) and gaps:
                        n.architecture += "\n\nDocumentation gaps: " + "; ".join(str(g) for g in gaps[:6])
                stage("LLM executive summary", 93)
                summ = executive_summary(llm, audit.project, audit.verdict, audit.scores, audit.actions, audit.narrative, audit.options.context)
                allowed = {audit.verdict.readiness, audit.verdict.sustainability, audit.verdict.raw_weighted,
                           *(s.score for s in audit.scores), 35, 55, 60, 65, 70, 80, 45, 100}
                if summ and numbers_consistent(summ, allowed) and not re.search(r"\b(at least|minimum of|threshold of)\s+\d+\s?%", summ, re.I):
                    audit.narrative.executive_summary = summ
                elif summ:
                    log("LLM executive summary quoted figures the engine did not compute — kept the rules-based summary.", "warning")
                audit.narrative.generated_by = ps.llm.model
                log(f"LLM usage: {llm.calls} calls, {llm.tokens_in:,} prompt / {llm.tokens_out:,} completion tokens.")
            except LlmError as e:
                log(f"LLM narrative failed: {e}. Using the rules-based narrative.", "warning")

        audit.status, audit.progress, audit.stage = "done", 100, "Completed"
        audit.finished_at = time.time()
        log(f"Readiness {audit.verdict.readiness}% — {audit.verdict.label}.")
    except Cancelled:
        audit.status, audit.stage = "cancelled", "Cancelled"
        audit.finished_at = time.time()
        log("Audit cancelled.", "warning")
    except IngestError as e:
        audit.status, audit.error = "failed", str(e)
        audit.finished_at = time.time()
        log(str(e), "error")
    except Exception as e:      # surface any unexpected engine error on the audit instead of killing the worker
        import traceback
        audit.status, audit.error = "failed", f"{type(e).__name__}: {e}"
        audit.finished_at = time.time()
        log(traceback.format_exc()[-1500:], "error")
    finally:
        if tmp and tmp.exists() and not ps.keep_workspace:
            shutil.rmtree(tmp, ignore_errors=True)
        save(audit)
    return audit


def propagate_tool_risk(ctx: Ctx) -> None:
    """A tool is at least as risky as the worst confident security finding inside its handler."""
    from .models import Dimension, Severity
    for t in ctx.server.tools:
        worst = [f.severity for f in ctx.findings if f.tool == t.name and f.dimension == Dimension.security
                 and f.confidence != "low" and f.severity.rank <= Severity.high.rank]
        if worst:
            w = min(worst, key=lambda s: s.rank)
            if w.rank < t.risk.rank:
                t.risk = w
                t.risk_reasons.append("security finding in handler")


def finalize_scores(audit: AuditResult, ctx: Ctx | None, policy: dict, llm_used: bool, docs_count: int,
                    previous: AuditResult | None = None) -> None:
    """(Re)compute scores, verdict, actions and narrative. Also used after a human triages findings."""
    if ctx is not None:
        audit.server, audit.metrics, audit.findings = ctx.server, ctx.metrics, ctx.findings
    audit.findings.sort(key=lambda f: (f.status != "open", f.severity.rank, f.dimension.value, f.file, f.line))
    audit.scores = dimension_scores(audit.findings, policy)
    scanners_ok = sum(1 for s in audit.scanners if s.status == "ok")
    audit.verdict = verdict(audit.findings, audit.scores, audit.server, audit.metrics, audit.options.context, policy,
                            llm_used, scanners_ok, docs_count)
    audit.actions = action_plan(audit.findings)
    keep_llm = audit.narrative.generated_by not in ("", "rules") and ctx is None
    rn = rules_narrative(audit.project, audit.verdict, audit.scores, audit.findings, audit.server, audit.metrics, audit.actions, audit.options.context)
    if keep_llm:
        # human triage changed the numbers: refresh the factual summary, keep the LLM's qualitative sections
        audit.narrative.executive_summary = rn.executive_summary
        audit.narrative.conditions = rn.conditions
        audit.narrative.generated_by = audit.narrative.generated_by + " + rules (re-scored after triage)"
    else:
        audit.narrative = rn
    if previous is not None and previous.findings:
        audit.comparison = {"previous_id": previous.id, "previous_readiness": previous.verdict.readiness if previous.verdict else None,
                            "previous_date": previous.created_at, **compare(previous.findings, audit.findings)}
