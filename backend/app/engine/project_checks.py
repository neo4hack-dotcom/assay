"""Project-level checks: MCP surface rules, dependencies, tests/CI/docs, containers,
git history and code metrics. These answer "is the *service* production-grade",
where the line rules answer "is this *line* dangerous".
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import tomllib
from collections import Counter

from .context import Ctx
from .mcp_discovery import EXEC_PARAM, SQL_PARAM, WRITE_NAME
from .models import Severity
from .policy import lower_bound, parse_version

POISON_STRONG = re.compile(
    r"(ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|disregard\s+(all\s+|any\s+)?(previous|prior|other)\s+instructions"
    r"|<\s*/?\s*(important|system|secret|instructions?|hidden)\s*>|do\s+not\s+(tell|mention|inform|reveal|disclose)[^.]{0,40}\b(user|human)"
    r"|without\s+(telling|informing|notifying)\s+the\s+user|(~/\.ssh|id_rsa|\.aws/credentials|/etc/passwd|/etc/shadow|mcp\.json|claude_desktop_config)"
    r"|exfiltrat|send\s+(it|them|this|the\s+(contents?|data|results?|file|conversation))\s+to\s+(http|https|the\s+following|this\s+(url|address|email))"
    r"|before\s+(using|calling)\s+(this|any\s+other)\s+tool[^.]{0,60}\b(read|call|send|pass))", re.I)
POISON_WEAK = re.compile(r"(you\s+must\s+(always\s+)?(first\s+)?(call|use|invoke|pass)|always\s+(call|use)\s+this\s+tool|this\s+tool\s+(replaces|supersedes|overrides)|instead\s+of\s+(the\s+)?\w+\s+tool|as\s+an\s+ai|system\s+prompt)", re.I)
INVISIBLE = re.compile("[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
TOOL_NAME_OK = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
CI_PATTERNS = {
    "GitHub Actions": r"^\.github/workflows/.+\.ya?ml$", "GitLab CI": r"(^|/)\.gitlab-ci\.ya?ml$",
    "Jenkins": r"(^|/)Jenkinsfile$", "Azure Pipelines": r"(^|/)azure-pipelines.*\.ya?ml$",
    "CircleCI": r"^\.circleci/", "Bitbucket": r"bitbucket-pipelines\.yml$", "Drone": r"\.drone\.ya?ml$",
    "Travis": r"\.travis\.yml$", "Tekton/Argo": r"(^|/)(tekton|\.tekton|argo)/.+\.ya?ml$",
}
LOCKFILES = r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|uv\.lock|Pipfile\.lock|pdm\.lock|go\.sum|gradle\.lockfile|packages\.lock\.json|requirements.*\.lock|requirements\.txt\.lock)$"
LINT_CONFIGS = r"(^|/)(ruff\.toml|\.ruff\.toml|\.flake8|mypy\.ini|\.mypy\.ini|pyrightconfig\.json|\.pylintrc|pylintrc|\.eslintrc(\.\w+)?|eslint\.config\.\w+|biome\.jsonc?|\.golangci\.ya?ml|checkstyle\.xml|\.editorconfig|\.pre-commit-config\.yaml|tslint\.json|\.prettierrc(\.\w+)?)$"


def _sev(s: str) -> Severity:
    return Severity(s)


# =========================================================================== MCP surface
def mcp_checks(ctx: Ctx, policy: dict) -> None:
    srv = ctx.server
    th = policy["thresholds"]
    if not srv.detected:
        ctx.add("MCP-016", message="No MCP SDK usage or tool registration was recognised.", confidence="high", source="project")
        return
    remote = [t for t in srv.transports if t in ("streamable-http", "sse")]
    # ---- transports / auth
    if remote and not srv.auth.detected:
        ctx.add("MCP-001", file=_entry_file(ctx), message=f"Transport(s) {', '.join(remote)} exposed and no authentication mechanism was found in code. "
                "If authentication is enforced by an API gateway / service mesh, record it as an accepted risk with evidence.",
                confidence="medium", source="project")
    if "sse" in srv.transports:
        ctx.add("MCP-005", file=_entry_file(ctx), message="HTTP+SSE transport detected.", confidence="high", source="project")
    if remote and "dns_rebinding" not in srv.signals:
        ctx.add("MCP-004", file=_entry_file(ctx), message="No Origin/Host validation or DNS-rebinding protection setting found.",
                confidence="low", source="project")
    if srv.transports == ["stdio"]:
        ctx.add("SCL-001", file=_entry_file(ctx), message="Only stdio is wired: each client runs its own server process.", confidence="high", source="project")
    if remote and srv.stateless_http is not True:
        ctx.add("SCL-002", file=_entry_file(ctx), message="Streamable HTTP runs in stateful session mode (stateless mode not enabled).",
                confidence="medium" if srv.stateless_http is None else "high", source="project")
    if remote and "rate_limit" not in srv.signals:
        ctx.add("SCL-006", message="No rate-limiting/throttling library or middleware found.", confidence="medium", source="project")
    if remote and "health" not in srv.signals:
        ctx.add("SCL-009", message="No health/readiness route found.", confidence="medium", source="project")
    if remote and "graceful_shutdown" not in srv.signals:
        ctx.add("REL-007", message="No lifespan/shutdown handling found.", confidence="low", source="project")

    # ---- SDK version floors
    floors = policy["sdk_minimums"]
    for pkg, spec in srv.sdk_versions.items():
        floor = floors.get(pkg)
        lb = lower_bound(spec)
        if floor and lb and parse_version(lb) < parse_version(floor):
            ctx.add("MCP-014", message=f"`{pkg}` constrained to `{spec}` (minimum recommended {floor}).", confidence="high", source="project")
        elif floor and not lb:
            ctx.add("MCP-014", message=f"`{pkg}` is not version-constrained (`{spec}`); builds may pull any release.", severity=Severity.low,
                    confidence="medium", source="project")

    # ---- tool-level
    names = Counter(t.name for t in srv.tools if t.kind == "tool")
    tools = [t for t in srv.tools if t.kind == "tool"]
    for t in srv.tools:
        _tool_checks(ctx, t, th)
    dup = [n for n, c in names.items() if c > 1]
    if dup:
        ctx.add("MCP-011", message=f"Duplicate tool names: {', '.join(dup[:8])}.", confidence="high", source="project")
    if len(tools) > th["tools_too_many"]:
        ctx.add("MCP-009", message=f"{len(tools)} tools exposed.", severity=Severity.medium, confidence="high", source="project")
    elif len(tools) > th["tools_many"]:
        ctx.add("MCP-009", message=f"{len(tools)} tools exposed.", confidence="high", source="project")

    # ---- observability tied to tools
    if tools:
        logged = 0
        for t in tools:
            sf = ctx.ws.get(t.file)
            body = "\n".join(sf.lines[t.line - 1: t.end_line]) if sf else ""
            if re.search(r"(log(ger)?\.\w+\(|logging\.\w+\(|audit|ctx\.(info|debug|log|warning|error)\(|console\.error|pino|winston|slog\.|zap\.)", body):
                logged += 1
        if "audit_log" not in srv.signals and logged < max(1, len(tools) // 2):
            ctx.add("OBS-002", message=f"{logged}/{len(tools)} tool handlers log their invocation and no audit middleware was found.",
                    confidence="medium", source="project")


def _tool_checks(ctx: Ctx, t, th: dict) -> None:
    """Metadata, poisoning, annotation and input-schema checks for one tool/resource/prompt."""
    text = f"{t.name}\n{t.description}\n" + "\n".join(p.description for p in t.params)
    loc = dict(file=t.file, line=t.line, tool=t.name, source="project")
    snippet = (t.description[:600] + ("…" if len(t.description) > 600 else "")) if t.description else None
    if POISON_STRONG.search(text) or INVISIBLE.search(text):
        why = "invisible Unicode characters" if INVISIBLE.search(text) else f"instruction-like content: “{POISON_STRONG.search(text).group(0)[:80]}”"
        ctx.add("MCP-003", message=f"{t.kind.capitalize()} `{t.name}` metadata contains {why}.", confidence="high", snippet=snippet, **_loc(ctx, loc))
    elif POISON_WEAK.search(text) or BASE64_BLOB.search(text):
        ctx.add("MCP-003", message=f"{t.kind.capitalize()} `{t.name}` metadata contains directive phrasing aimed at the model: “{(POISON_WEAK.search(text) or BASE64_BLOB.search(text)).group(0)[:80]}”.",
                severity=Severity.medium, confidence="medium", snippet=snippet, **_loc(ctx, loc))
    if t.kind != "tool":
        return
    if not TOOL_NAME_OK.match(t.name):
        ctx.add("MCP-011", message=f"Tool name `{t.name}` uses characters outside [A-Za-z0-9_.-] or is too long.", confidence="high", **_loc(ctx, loc))
    if not t.description.strip():
        ctx.add("MCP-007", message=f"Tool `{t.name}` has no description.", confidence="high", **_loc(ctx, loc))
    elif len(t.description.strip()) < th["short_description_chars"]:
        ctx.add("MCP-007", message=f"Tool `{t.name}` description is only {len(t.description.strip())} characters.", confidence="high", **_loc(ctx, loc))
    undocumented = [p.name for p in t.params if not p.description]
    if t.params and len(undocumented) == len(t.params) and len(t.params) >= 2 and t.description:
        ctx.add("MCP-007", message=f"Tool `{t.name}`: none of its parameters are documented ({', '.join(undocumented[:6])}).",
                severity=Severity.info, confidence="medium", **_loc(ctx, loc))
    mutating = bool(set(t.capabilities) & {"exec", "fs_write", "destructive", "send"}) or bool(WRITE_NAME.search(t.name))
    has_ann = any(k in t.annotations for k in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"))
    if t.annotations.get("readOnlyHint") is True and set(t.capabilities) & {"exec", "fs_write", "destructive"}:
        ctx.add("MCP-006", message=f"Tool `{t.name}` declares readOnlyHint=true but its handler {', '.join(sorted(set(t.capabilities) & {'exec', 'fs_write', 'destructive'}))}. Clients will auto-approve and retry it.",
                severity=Severity.high, confidence="medium", **_loc(ctx, loc))
    elif mutating and not has_ann:
        ctx.add("MCP-006", message=f"Tool `{t.name}` ({', '.join(t.capabilities) or 'state-changing name'}) declares no behaviour annotations.",
                confidence="medium", **_loc(ctx, loc))
    elif "destructive" in t.capabilities and t.annotations.get("destructiveHint") is False:
        ctx.add("MCP-006", message=f"Tool `{t.name}` looks destructive but declares destructiveHint=false — confirm this is intended.", severity=Severity.low, confidence="low", **_loc(ctx, loc))
    exec_params = [p.name for p in t.params if EXEC_PARAM.match(p.name) and not p.constrained]
    sql_params = [p.name for p in t.params if SQL_PARAM.match(p.name) and not p.constrained]
    if exec_params and "exec" in t.capabilities:
        ctx.add("MCP-013", message=f"Tool `{t.name}` executes model-supplied `{exec_params[0]}`.", confidence="high", **_loc(ctx, loc))
    elif sql_params and "db" in t.capabilities:
        ctx.add("MCP-013", message=f"Tool `{t.name}` runs model-supplied SQL (`{sql_params[0]}`). Acceptable only with a strict guard: read-only DB role, statement allow-list/parser, row/time limits.",
                severity=Severity.medium, confidence="medium", **_loc(ctx, loc))
    free = [p.name for p in t.params if not p.constrained and p.name not in exec_params + sql_params
            and (p.type in ("untyped", "") or re.search(r"\b(str|string)\b", p.type) is not None)]
    sinks = set(t.capabilities) & {"exec", "fs_write", "fs_read", "network", "db"}
    if free and sinks and (t.risk.rank <= Severity.high.rank):
        ctx.add("MCP-008", message=f"Tool `{t.name}`: free-form string parameter(s) {', '.join(free[:5])} reach {', '.join(sorted(sinks))} without schema constraints.",
                severity=Severity.medium if sinks & {"exec", "fs_write"} else Severity.low, confidence="low", **_loc(ctx, loc))


def _entry_file(ctx: Ctx) -> str:
    return ctx.server.entrypoints[0].split(":")[0] if ctx.server.entrypoints else ""


def _loc(ctx: Ctx, loc: dict) -> dict:
    sf = ctx.ws.get(loc["file"])
    return {"sf": sf, "line": loc["line"], "tool": loc["tool"], "source": loc["source"]} if sf else \
        {"file": loc["file"], "tool": loc["tool"], "source": loc["source"]}


# =========================================================================== dependencies
def dependency_checks(ctx: Ctx, policy: dict) -> None:
    ws, m = ctx.ws, ctx.metrics
    deps: list[tuple[str, str, str]] = []    # (name, spec, file)
    for rel in ws.other_files:
        low = rel.lower().rsplit("/", 1)[-1]
        if "node_modules/" in rel:
            continue
        if re.fullmatch(r"requirements[\w.-]*\.(txt|in)", low):
            for line in ws.read(rel).splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith(("-r", "-c", "--", "-e .")):
                    if line.startswith(("-e git", "-e http")):
                        deps.append((line, "url", rel))
                    continue
                mm = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(.*)", line)
                if mm:
                    deps.append((mm.group(1), mm.group(2).strip() or "unpinned", rel))
        elif low == "pyproject.toml":
            try:
                data = tomllib.loads(ws.read(rel))
            except (tomllib.TOMLDecodeError, ValueError):
                continue
            for d in data.get("project", {}).get("dependencies", []) or []:
                mm = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(.*)", d)
                if mm:
                    deps.append((mm.group(1), mm.group(2).strip() or "unpinned", rel))
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
            for k, v in poetry.items():
                if k.lower() != "python":
                    deps.append((k, v if isinstance(v, str) else json.dumps(v), rel))
            rp = data.get("project", {}).get("requires-python", "") or poetry.get("python", "")
            _runtime_check(ctx, policy, "python", rp, rel)
        elif low == "package.json":
            try:
                data = json.loads(ws.read(rel))
            except (json.JSONDecodeError, ValueError):
                continue
            for sec in ("dependencies", "optionalDependencies"):
                for k, v in (data.get(sec) or {}).items():
                    deps.append((k, str(v), rel))
            scripts = data.get("scripts") or {}
            for hook in ("preinstall", "install", "postinstall", "prepare"):
                if hook in scripts and hook != "prepare":
                    ctx.add("SEC-027", file=rel, message=f"`{hook}` script: {str(scripts[hook])[:120]}", confidence="high", source="project")
                if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", str(scripts.get(hook, ""))):
                    ctx.add("SEC-024", file=rel, message=f"`{hook}` pipes a remote script to a shell.", confidence="high", source="project")
            engines = (data.get("engines") or {}).get("node", "")
            _runtime_check(ctx, policy, "node", engines, rel)
        elif low == "setup.py":
            for mm in re.finditer(r"['\"]([A-Za-z0-9_.\-]+)\s*([<>=~!][^'\"]*)?['\"]", ws.read(rel).split("install_requires", 1)[-1][:3000]):
                if mm.group(1) and not mm.group(1).startswith("."):
                    deps.append((mm.group(1), mm.group(2) or "unpinned", rel))
    m.dependencies = len(deps)
    m.lockfiles = ws.exists(LOCKFILES)
    if deps:
        pinned = sum(1 for _, spec, _ in deps if re.match(r"^(==|===)\s*\d|^\d+\.\d+(\.\d+)?$|^@?\d", spec.strip()) or spec.startswith("=="))
        m.dependencies_pinned_pct = round(100 * pinned / len(deps), 1)
        if not m.lockfiles and m.dependencies_pinned_pct < 80:
            ctx.add("MNT-004", message=f"No lockfile; {m.dependencies_pinned_pct:.0f}% of {len(deps)} direct dependencies are pinned.", confidence="high", source="project")
        elif not m.lockfiles:
            ctx.add("MNT-004", message="Direct dependencies are pinned but transitive ones are not locked (no lockfile).",
                    severity=Severity.low, confidence="high", source="project")
        for name, spec, rel in deps:
            if re.search(r"(git\+|https?://|file:|github:|gitlab:|bitbucket:|\.tgz|\.tar\.gz|link:)", f"{name} {spec}"):
                ctx.add("SEC-026", file=rel, message=f"`{name}` → `{spec[:100]}`", confidence="high", source="project")


def _runtime_check(ctx: Ctx, policy: dict, runtime: str, spec: str, rel: str) -> None:
    if not spec:
        return
    lb = lower_bound(spec)
    floor = policy["runtime_minimums"].get(runtime)
    if lb and floor and parse_version(lb) < parse_version(floor):
        ctx.add("MNT-010", file=rel, message=f"{runtime} `{spec}` allows versions below the supported floor {floor}.",
                confidence="medium", source="project")


# =========================================================================== repo hygiene
def hygiene_checks(ctx: Ctx, policy: dict) -> None:
    ws, m, th = ctx.ws, ctx.metrics, policy["thresholds"]
    prod = [f for f in ws.files if not f.is_test and f.language not in ("config", "dockerfile", "shell", "powershell")]
    tests = [f for f in ws.files if f.is_test and f.language not in ("config", "dockerfile")]
    m.files_total = len(ws.other_files)
    m.files_analyzed = len(ws.files)
    m.files_skipped = ws.skipped
    m.loc_total = sum(f.loc for f in prod)
    by_lang: Counter = Counter()
    for f in prod:
        by_lang[f.language] += f.loc
    m.loc_by_language = dict(by_lang.most_common())
    m.test_files = len(tests)
    m.test_loc = sum(f.loc for f in tests)
    m.test_ratio = round(m.test_loc / m.loc_total, 2) if m.loc_total else 0.0
    if m.loc_total:
        if not tests:
            ctx.add("MNT-001", message=f"0 test files for {m.loc_total:,} lines of production code.", confidence="high", source="project")
        elif m.test_ratio < th["test_ratio_low"]:
            ctx.add("MNT-002", message=f"Test/production code ratio is {m.test_ratio:.2f} ({m.test_loc:,} / {m.loc_total:,} LOC).", confidence="medium", source="project")
    # CI
    systems = [name for name, rx in CI_PATTERNS.items() if ws.exists(rx)]
    m.ci_systems, m.has_ci = systems, bool(systems)
    if not systems:
        ctx.add("MNT-003", message="No CI configuration in the analysed folder (if this is a monorepo sub-folder, CI may live at the repository root).",
                confidence="medium", source="project")
    # docs
    readmes = ws.exists(r"(^|/)readme(\.\w+)?$")
    m.has_readme = any("/" not in r for r in readmes) or bool(readmes)
    m.doc_files = len(ws.exists(r"(^|/)(docs?|documentation|wiki)/.+\.(md|rst|adoc|txt|html|pdf)$")) + len(readmes)
    if not readmes:
        ctx.add("MNT-006", message="No README found.", confidence="high", source="project")
    else:
        root_readme = sorted(readmes, key=len)[0]
        text = ws.read(root_readme)
        if len(text.splitlines()) < 15:
            ctx.add("MNT-006", file=root_readme, message=f"README is minimal ({len(text.splitlines())} lines): purpose, configuration, tools and operations are not documented.",
                    severity=Severity.low, confidence="medium", source="project")
    m.has_license = bool(ws.exists(r"^(license|licence|copying)(\.\w+)?$"))
    m.has_changelog = bool(ws.exists(r"^(changelog|changes|history|releases)(\.\w+)?$"))
    m.has_dockerfile = bool(ws.exists(r"(^|/)(dockerfile|[\w.-]+\.dockerfile|dockerfile\.[\w.-]+)$"))
    has_k8s = bool(ws.exists(r"(^|/)(helm|charts|k8s|kubernetes|deploy|manifests)/")) or bool(ws.exists(r"(^|/)(docker-)?compose\.ya?ml$"))
    if not m.has_dockerfile and not has_k8s and ctx.options.context.deployment == "shared":
        ctx.add("SCL-010", message="No container or deployment manifest found.", confidence="medium", source="project")
    # lint / types
    lint = ws.exists(LINT_CONFIGS)
    pyproject = ws.read("pyproject.toml") if "pyproject.toml" in ws.other_files else ""
    if re.search(r"\[tool\.(ruff|mypy|pylint|black|pyright|flake8|isort)", pyproject):
        lint.append("pyproject.toml")
    pkg = ws.read("package.json") if "package.json" in ws.other_files else ""
    if '"eslint' in pkg or '"@biomejs' in pkg:
        lint.append("package.json")
    if not lint and prod:
        ctx.add("MNT-007", message="No lint/format/type-check configuration found.", confidence="medium", source="project")
    tsconfigs = ws.exists(r"(^|/)tsconfig(\.\w+)?\.json$")
    if tsconfigs and by_lang.get("typescript"):
        if not any(re.search(r'"strict"\s*:\s*true', ws.read(t)) for t in tsconfigs):
            ctx.add("MNT-007", file=tsconfigs[0], message="TypeScript `strict` mode is not enabled.", severity=Severity.low, confidence="high", source="project")
    # large files + TODOs
    todo = 0
    for f in prod:
        if f.loc > th["large_file_loc"]:
            ctx.add("MNT-012", file=f.rel, message=f"{f.loc:,} lines of code.", confidence="high", source="project")
        todo += len(re.findall(r"\b(TODO|FIXME|HACK|XXX)\b", f.text))
    m.todo_count = todo
    if m.loc_total and todo / max(m.loc_total / 1000, 1) > th["todo_per_kloc"]:
        ctx.add("MNT-011", message=f"{todo} TODO/FIXME/HACK markers ({todo / max(m.loc_total / 1000, 1):.1f} per kLOC).", confidence="high", source="project")
    # committed secrets files
    for rel in ws.other_files:
        name = rel.rsplit("/", 1)[-1].lower()
        if re.fullmatch(r"\.env(\.[\w-]+)?", name) and not re.search(r"(example|sample|template|dist|defaults?|tpl)", name):
            content = ws.read(rel, 50_000)
            secretish = re.findall(r"(?im)^\s*[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY|PWD)[A-Z0-9_]*\s*=\s*\S{4,}", content)
            ctx.add("SEC-021", file=rel, message=f"Environment file committed{' with ' + str(len(secretish)) + ' credential-like value(s)' if secretish else ''}.",
                    severity=Severity.high if secretish else Severity.low, confidence="high", source="project")
        elif re.search(r"\.(pem|key|p12|pfx|jks|keystore|ppk)$|^id_(rsa|dsa|ecdsa|ed25519)$|^(credentials|service[-_]?account.*)\.json$", name) \
                and not re.search(r"(public|\.pub$|example|sample|test)", name):
            ctx.add("SEC-021", file=rel, message="Key/credential file committed.", severity=Severity.critical, confidence="medium", source="project")


# =========================================================================== containers
def docker_checks(ctx: Ctx, policy: dict) -> None:
    for sf in ctx.ws.by_language("dockerfile"):
        froms, user_set, last_user = [], False, ""
        for i, line in enumerate(sf.lines, 1):
            s = line.strip()
            up = s.upper()
            if up.startswith("FROM "):
                img = s.split()[1]
                froms.append((i, img))
                if img.lower() != "scratch" and ("@sha256" not in img) and (":" not in img.split("/")[-1] or img.endswith(":latest")):
                    ctx.add("SEC-023", sf, i, message=f"Base image `{img}` is not pinned to a version.", confidence="high", source="project")
                mm = re.match(r"(?:.*/)?(python|node):(\d+)(?:\.(\d+))?", img)
                if mm:
                    floor = policy["runtime_minimums"]["python" if mm.group(1) == "python" else "node"]
                    ver = f"{mm.group(2)}.{mm.group(3) or 0}" if mm.group(1) == "python" else mm.group(2)
                    if parse_version(ver) < parse_version(floor):
                        ctx.add("MNT-010", sf, i, message=f"Base image `{img}` uses an end-of-life runtime (floor {floor}).", confidence="high", source="project")
            if up.startswith("USER "):
                user_set = True
                last_user = s.split()[1]
            if re.match(r"^(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)\w*(\s*=\s*|\s+)\S+", s, re.I):
                ctx.add("SEC-007", sf, i, message="Secret baked into the image via ENV/ARG (visible in image history).", severity=Severity.high, confidence="medium", source="project")
            if up.startswith("ADD ") and re.search(r"https?://", s):
                ctx.add("SEC-024", sf, i, message="ADD fetches a remote URL without checksum verification.", severity=Severity.medium, confidence="high", source="project")
        if froms and (not user_set or last_user in ("root", "0", "0:0")):
            ctx.add("SEC-022", sf, froms[-1][0], message="No non-root USER in the final stage.", confidence="high", source="project")


# =========================================================================== observability / resilience
def observability_checks(ctx: Ctx) -> None:
    srv, m = ctx.server, ctx.metrics
    if not m.loc_total:
        return
    if "logging" not in srv.signals:
        ctx.add("OBS-001", message="No logging framework configured.", confidence="medium", source="project")
    elif "structured_logging" not in srv.signals and ctx.options.context.deployment == "shared":
        ctx.add("OBS-001", message="Logging is configured but not structured (JSON): log correlation in a central platform will be weak.",
                severity=Severity.low, confidence="medium", source="project")
    if "metrics_tracing" not in srv.signals:
        ctx.add("OBS-003", message="No OpenTelemetry/Prometheus/StatsD instrumentation found.", confidence="medium", source="project")
    network = any(("network" in t.capabilities) for t in srv.tools) or re.search(r"(requests\.|httpx|aiohttp|fetch\(|axios)", ctx.project_text("python", "typescript", "javascript")) is not None
    if network and "retry" not in srv.signals:
        ctx.add("REL-003", message="Network calls found but no retry/backoff mechanism.", confidence="medium", source="project")


# =========================================================================== complexity & typing
def complexity_metrics(ctx: Ctx, policy: dict) -> None:
    th, m = policy["thresholds"], ctx.metrics
    try:
        import lizard   # pure Python, supports py/js/ts/go/java/c#/kotlin
    except ImportError:
        return
    ccns, hotspots = [], []
    for sf in ctx.ws.files:
        if sf.is_test or sf.language not in ("python", "typescript", "javascript", "go", "java", "kotlin", "csharp", "rust", "ruby", "php"):
            continue
        try:
            info = lizard.analyze_file.analyze_source_code(sf.rel, sf.text)
        except Exception:      # lizard can choke on exotic syntax; metrics are best-effort
            continue
        for fn in info.function_list:
            ccns.append(fn.cyclomatic_complexity)
            if fn.cyclomatic_complexity > th["complexity_medium"]:
                hotspots.append({"file": sf.rel, "function": fn.name, "line": fn.start_line, "ccn": fn.cyclomatic_complexity, "nloc": fn.nloc})
    m.functions = len(ccns)
    m.avg_complexity = round(sum(ccns) / len(ccns), 2) if ccns else 0.0
    m.max_complexity = max(ccns) if ccns else 0
    hotspots.sort(key=lambda h: -h["ccn"])
    m.complex_functions = len(hotspots)
    m.hotspots = hotspots[:15]
    for h in hotspots[:10]:
        sev = Severity.high if h["ccn"] > th["complexity_high"] * 1.6 else Severity.medium if h["ccn"] > th["complexity_high"] else Severity.low
        sf = ctx.ws.get(h["file"])
        ctx.add("MNT-005", sf, h["line"], message=f"`{h['function']}` has cyclomatic complexity {h['ccn']} ({h['nloc']} NLOC).",
                severity=sev, confidence="high", source="project", tool="")
    # Python annotation coverage
    import ast
    total = typed = 0
    for sf in ctx.ws.by_language("python"):
        if sf.is_test:
            continue
        try:
            tree = ast.parse(sf.text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total += 1
                if node.returns is not None or any(a.annotation is not None for a in node.args.args if a.arg not in ("self", "cls")):
                    typed += 1
    if total:
        m.typed_functions_pct = round(100 * typed / total, 1)


# =========================================================================== git
def git_metrics(ctx: Ctx, policy: dict) -> None:
    root = ctx.ws.root
    if not shutil.which("git"):
        return
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=15)
        if top.returncode != 0:
            return
        out = subprocess.run(["git", "-C", str(root), "log", "--no-merges", "-n", "3000", "--format=%aN%x09%at", "--", "."],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return
    rows = [l.split("\t") for l in out.stdout.splitlines() if "\t" in l]
    if not rows:
        return
    authors = Counter(r[0] for r in rows)
    last_ts = max(int(r[1]) for r in rows)
    first_ts = min(int(r[1]) for r in rows)
    now = time.time()
    recent = sum(1 for r in rows if now - int(r[1]) < 90 * 86400)
    top_author, top_count = authors.most_common(1)[0]
    share = top_count / len(rows)
    ctx.metrics.git = {
        "commits": len(rows), "contributors": len(authors), "top_contributor_share": round(share, 2),
        "last_commit_days": int((now - last_ts) / 86400), "first_commit_days": int((now - first_ts) / 86400),
        "commits_last_90d": recent, "shallow": (root / ".git" / "shallow").exists(),
    }
    th = policy["thresholds"]
    if len(rows) >= 10 and (len(authors) == 1 or share >= th["bus_factor_share"]):
        ctx.add("MNT-008", message=f"{share:.0%} of {len(rows)} commits by a single contributor ({len(authors)} contributor(s) in total).",
                confidence="medium", source="project")
    if (now - last_ts) / 86400 > th["stale_days"]:
        ctx.add("MNT-009", message=f"Last commit {int((now - last_ts) / 86400)} days ago.", confidence="high", source="project")


def run_project_checks(ctx: Ctx, policy: dict) -> None:
    hygiene_checks(ctx, policy)
    mcp_checks(ctx, policy)
    dependency_checks(ctx, policy)
    docker_checks(ctx, policy)
    observability_checks(ctx)
    complexity_metrics(ctx, policy)
    git_metrics(ctx, policy)
