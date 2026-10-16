"""Assay command line.

    assay serve                         start the web UI (http://127.0.0.1:3101)
    assay scan PATH|GIT_URL|ZIP [opts]  audit one MCP server and write reports
    assay scan-all FOLDER [opts]        audit every MCP project in a folder + portfolio summary
    assay test-llm                      check the configured OpenAI-compatible endpoint
    assay rules                         list the rule catalogue

`scan` exits with code 2 when readiness is below --fail-under (CI gating).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path


def _configure_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles
    except (AttributeError, ValueError):
        pass


def _llm_overrides(args) -> dict:
    o = {}
    for k in ("base_url", "api_key", "model"):
        v = getattr(args, f"llm_{k}", None)
        if v:
            o[k] = v
    if getattr(args, "llm_context", None):
        o["context_window"] = args.llm_context
    if getattr(args, "llm_insecure", False):
        o["verify_tls"] = False
    return o


def _options(args):
    from .engine.models import AuditContext, AuditOptions
    tools = [] if args.no_scanners else [t.strip() for t in args.scanners.split(",") if t.strip()]
    return AuditOptions(use_llm=not args.no_llm, depth=args.depth, include_tests=args.include_tests, external_tools=tools,
                        context=AuditContext(deployment=args.deployment, exposure=args.exposure, data_sensitivity=args.sensitivity,
                                             expected_concurrency=args.concurrency))


def _source(target: str, ref: str, subdir: str):
    from .engine.models import SourceSpec
    if target.startswith(("http://", "https://", "ssh://", "git@")):
        return SourceSpec(kind="git", location=target, ref=ref, subdir=subdir), None
    p = Path(target).expanduser().resolve()
    if p.is_file() and p.suffix.lower() == ".zip":
        return SourceSpec(kind="zip", location=p.name, subdir=subdir), p
    if p.is_dir():
        return SourceSpec(kind="path", location=str(p), subdir=subdir), None
    sys.exit(f"error: {target} is not a folder, a .zip or a git URL")


def _bar(v: int, width: int = 24) -> str:
    n = round(width * v / 100)
    return "█" * n + "░" * (width - n)


def run_one(target: str, args, out: Path, project: str = "", quiet: bool = False):
    from .deps import container as c
    from .engine.models import AuditResult
    from .engine.pipeline import run_audit
    from .reports.exports import FORMATS, render

    src, zip_path = _source(target, args.ref, args.subdir)
    name = project or args.name or (Path(src.location).name if src.kind == "path" else Path(target).stem if src.kind == "zip"
                                    else target.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
    a = AuditResult(id=uuid.uuid4().hex[:12], project=name, created_at=time.time(), source=src, options=_options(args))
    ps = c.pipeline_settings()
    ps.llm = c.llm_config(_llm_overrides(args))
    docs = [Path(d).expanduser().resolve() for d in (args.docs or [])]
    last = [""]

    def save(x):
        if not quiet and x.stage != last[0]:
            last[0] = x.stage
            print(f"  [{x.progress:>3}%] {x.stage}", flush=True)

    prev = c.store.previous_of(a)
    run_audit(a, ps, uploaded_zip=zip_path, uploaded_docs=docs, save=save, previous=prev)
    for l in a.logs:
        if l.level != "info" and not quiet:
            print(f"  ! {l.message.splitlines()[-1][:300]}")
    if a.status != "done":
        print(f"✗ {name}: {a.status} — {a.error}")
        return a
    c.apply_remembered_triage(a)
    c.store.save(a)               # visible in the web UI too
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(a.finished_at))
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name)
    written = []
    for fmt in [f.strip() for f in args.formats.split(",") if f.strip()]:
        if fmt not in FORMATS:
            print(f"  ! unknown format {fmt}")
            continue
        path = out / f"assay-{safe}-{stamp}.{FORMATS[fmt][1]}"
        path.write_bytes(render(a, fmt))
        written.append(path)
    v = a.verdict
    if not quiet:
        print()
        print(f"  {name}: {v.label.upper()}  readiness {v.readiness}%  sustainability {v.sustainability}%  confidence {v.confidence}")
        for s in a.scores:
            print(f"    {s.label:<34} {_bar(s.score)} {s.score:>3}")
        cnt = {k: sum(1 for f in a.findings if f.status == 'open' and f.severity.value == k) for k in ("critical", "high", "medium", "low")}
        print(f"    open findings: {cnt['critical']} critical, {cnt['high']} high, {cnt['medium']} medium, {cnt['low']} low")
        for g in v.gates:
            print(f"    gate: {g}")
        for p in written:
            print(f"  → {p}")
    return a


def cmd_scan(args) -> int:
    a = run_one(args.target, args, Path(args.out))
    if a.status != "done":
        return 1
    if args.fail_under is not None and a.verdict.readiness < args.fail_under:
        print(f"readiness {a.verdict.readiness}% < --fail-under {args.fail_under}")
        return 2
    return 0


MARKERS = ("package.json", "pyproject.toml", "requirements.txt", "setup.py", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts")


def cmd_scan_all(args) -> int:
    root = Path(args.folder).expanduser().resolve()
    def is_project(d: Path) -> bool:
        # marker at the root or one level down (backend/, server/, src/…): typical of app + MCP monorepos
        return any((d / m).exists() for m in MARKERS) or any((sub / m).exists() for sub in d.iterdir()
                                                            if sub.is_dir() and not sub.name.startswith(".") and sub.name not in ("node_modules", ".venv")
                                                            for m in MARKERS)
    projects = sorted(d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".") and d.name not in ("node_modules",) and is_project(d))
    if not projects:
        print("No project folders found (looked for package.json, pyproject.toml, requirements.txt, go.mod, pom.xml…).")
        return 1
    out = Path(args.out)
    rows = []
    for i, d in enumerate(projects, 1):
        print(f"[{i}/{len(projects)}] {d.name}")
        a = run_one(str(d), args, out / d.name, project=d.name, quiet=True)
        if a.status == "done":
            v = a.verdict
            rows.append({"project": d.name, "decision": v.label, "readiness": v.readiness, "sustainability": v.sustainability,
                         "confidence": v.confidence, "mcp_detected": a.server.detected, "tools": len([t for t in a.server.tools if t.kind == "tool"]),
                         **{s.dimension.value: s.score for s in a.scores},
                         "critical": sum(1 for f in a.findings if f.status == "open" and f.severity.value == "critical"),
                         "high": sum(1 for f in a.findings if f.status == "open" and f.severity.value == "high"),
                         "top_actions": [x.title for x in a.actions[:3]]})
            print(f"      {v.label:<34} {v.readiness:>3}%")
        else:
            rows.append({"project": d.name, "decision": f"FAILED: {a.error}", "readiness": None})
    rows.sort(key=lambda r: (r.get("readiness") is None, r.get("readiness") or 0))
    out.mkdir(parents=True, exist_ok=True)
    (out / "portfolio.json").write_text(json.dumps(rows, indent=1), "utf-8")
    md = ["# MCP portfolio — production readiness", "", f"*{time.strftime('%d %B %Y')} · {len(rows)} project(s)*", "",
          "| Project | Decision | Readiness | Sustainability | Security | Scalability | Critical | High | Top actions |",
          "|---|---|---:|---:|---:|---:|---:|---:|---|"]
    for r in rows:
        md.append(f"| {r['project']} | {r['decision']} | {r.get('readiness', '—')}% | {r.get('sustainability', '—')}% | {r.get('security', '—')} | "
                  f"{r.get('scalability', '—')} | {r.get('critical', '—')} | {r.get('high', '—')} | {'; '.join(r.get('top_actions', []))} |")
    (out / "portfolio.md").write_text("\n".join(md), "utf-8")
    print(f"\nPortfolio summary → {out / 'portfolio.md'}")
    return 0


def cmd_test_llm(args) -> int:
    from .deps import container as c
    from .engine.llm import LlmClient
    cfg = c.llm_config(_llm_overrides(args))
    print(f"Endpoint {cfg.base_url or '(not set)'} · model {cfg.model or '(not set)'}")
    rep = LlmClient(cfg).test_connection()
    for s in rep["steps"]:
        print(f"  {'✓' if s['ok'] else '✗'} {s['name']}: {s['detail']}" + (f" ({s['ms']} ms)" if s.get("ms") else ""))
    if rep.get("tokens_per_s"):
        print(f"  throughput ≈ {rep['tokens_per_s']} tokens/s")
    if rep.get("models"):
        print("  models: " + ", ".join(rep["models"][:20]))
    return 0 if rep["ok"] else 1


def cmd_rules(args) -> int:
    from .engine import catalog
    for r in sorted(catalog.RULES.values(), key=lambda r: r.id):
        print(f"{r.id:<8} {r.severity.value:<8} {r.dimension.value:<15} {r.title}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    from .config import settings
    host = args.host or settings.host
    port = args.port or settings.port
    if host not in ("127.0.0.1", "localhost", "::1") and not settings.auth_token:
        print("WARNING: listening on a network interface without ASSAY_AUTH_TOKEN — anyone on the network can use Assay.")
    print(f"Assay UI → http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}")
    if args.open:
        import threading
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    uvicorn.run("app.main:app", host=host, port=port, log_level="info")
    return 0


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", default="reports", help="output folder (default ./reports)")
    p.add_argument("--formats", default="pdf,pptx,html,json", help="pdf,pptx,html,md,json,sarif")
    p.add_argument("--no-llm", action="store_true", help="static analysis only")
    p.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard", help="LLM review depth")
    p.add_argument("--deployment", choices=["shared", "local"], default="shared")
    p.add_argument("--exposure", choices=["internal", "internet"], default="internal")
    p.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")
    p.add_argument("--concurrency", type=int, default=50, help="expected concurrent users/agents")
    p.add_argument("--scanners", default="bandit,semgrep,gitleaks,pip-audit,npm-audit,osv-scanner", help="external scanners to use if installed")
    p.add_argument("--no-scanners", action="store_true")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--docs", nargs="*", help="extra documentation files (md, txt, pdf, docx, html)")
    p.add_argument("--ref", default="", help="git branch/tag")
    p.add_argument("--subdir", default="", help="audit only this sub-folder")
    _llm_args(p)


def _llm_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--llm-base-url", help="e.g. http://llm.corp:8000/v1 (overrides saved settings)")
    p.add_argument("--llm-model")
    p.add_argument("--llm-api-key")
    p.add_argument("--llm-context", type=int, help="context window in tokens")
    p.add_argument("--llm-insecure", action="store_true", help="disable TLS verification (lab only)")


def main(argv: list[str] | None = None) -> int:
    _configure_stdout()
    ap = argparse.ArgumentParser(prog="assay", description="Audit MCP servers for security, scalability, performance and sustainability.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--open", action="store_true", help="open the browser")
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("scan", help="audit one MCP server")
    s.add_argument("target", help="folder, .zip or git URL")
    s.add_argument("--name", default="", help="project name")
    s.add_argument("--fail-under", type=int, help="exit 2 if readiness is below this %")
    _common(s)
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("scan-all", help="audit every project in a folder")
    s.add_argument("folder")
    _common(s)
    s.set_defaults(fn=cmd_scan_all, name="")
    s = sub.add_parser("test-llm", help="test the LLM endpoint")
    _llm_args(s)
    s.set_defaults(fn=cmd_test_llm)
    s = sub.add_parser("rules", help="list rules")
    s.set_defaults(fn=cmd_rules)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
