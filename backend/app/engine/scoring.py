"""From findings to a decision.

The scoring is deliberately transparent and reproducible — the report's
methodology appendix restates it — because a production go/no-go that nobody
can explain will not be trusted:

1. Severity is first adjusted to the declared deployment context.
2. Each open finding costs   weight(severity) x confidence factor,
   with diminishing returns for repeated occurrences of the same rule.
3. Dimension score = 100 x exp(-penalty / decay).
4. Readiness = weighted mean of dimension scores, then *capped by gates*
   (an open critical caps it at 35 % whatever the rest looks like).
5. LLM verdicts can lower a finding's weight, never lift a gate: only a human
   marking a finding false-positive / accepted does. Audited code is untrusted
   and may try to talk the reviewer model out of a finding.
"""
from __future__ import annotations

import math
from collections import defaultdict

from . import catalog
from .models import (ActionItem, AuditContext, Dimension, DimensionScore, DIMENSION_LABELS, Finding, McpServerInfo,
                     Metrics, Narrative, Severity, Verdict)

CONF_FACTOR = {"high": 1.0, "medium": 0.8, "low": 0.5}
GRADES = [(90, "A"), (80, "B"), (65, "C"), (45, "D"), (0, "E")]


# --------------------------------------------------------------------------- context
def apply_context(findings: list[Finding], ctxt: AuditContext, server: McpServerInfo) -> None:
    remote = any(t in ("streamable-http", "sse") for t in server.transports)
    for f in findings:
        before = f.severity
        note = ""
        r = f.rule_id
        if ctxt.deployment == "local":
            if r in ("SCL-001", "SCL-002", "SCL-006", "SCL-009", "SCL-010", "REL-007", "OBS-003", "SCL-003", "SCL-008"):
                f.severity, note = Severity.info, "Acceptable for a local single-user deployment."
            elif r == "MCP-001":
                f.severity, note = Severity.high, "Local deployment: still reachable by local processes and, via DNS rebinding, by web pages."
        else:
            if r == "SCL-001":
                f.severity, note = Severity.high, "Shared multi-user deployment declared: a stdio-only server cannot be operated as a shared service."
            if r in ("SCL-006", "SCL-004") and ctxt.expected_concurrency >= 200 and f.severity.rank > Severity.high.rank:
                f.severity, note = f.severity.bump(1), f"{ctxt.expected_concurrency} expected concurrent users/agents."
        if ctxt.exposure == "internet":
            if r == "MCP-001":
                f.severity, note = Severity.critical, "Internet-exposed endpoint."
            elif r in ("SEC-012", "SEC-011", "MCP-004", "SEC-006", "SCL-006", "MCP-012", "SEC-015", "MCP-015"):
                f.severity, note = f.severity.bump(1), "Internet exposure raises the likelihood."
        if ctxt.data_sensitivity == "high" and r in ("SEC-007", "SEC-016", "SEC-018", "OBS-002", "SEC-021", "MCP-010", "SEC-019", "MCP-002"):
            f.severity, note = f.severity.bump(1), "High data sensitivity declared."
        elif ctxt.data_sensitivity == "low" and r in ("SEC-016", "SEC-018", "OBS-002"):
            f.severity, note = f.severity.bump(-1), "Low data sensitivity declared."
        if r == "SEC-012" and server.auth.detected:
            f.severity, note = Severity.low, "Authentication is present on the server."
        if r == "SEC-012" and not remote:
            f.severity, note = Severity.low, "No remote MCP transport detected."
        if f.severity != before and note:
            f.context_note = (f.context_note + " " if f.context_note else "") + note


# --------------------------------------------------------------------------- scoring
def finding_weight(f: Finding) -> float:
    if f.status != "open":
        return 0.0
    w = catalog.SEVERITY_WEIGHT[f.severity] * CONF_FACTOR.get(f.confidence, 0.8)
    if f.source == "llm":
        w *= 0.6           # an uncorroborated model opinion: real signal, weaker evidence than a rule hit
    if f.llm and f.llm.verdict == "false_positive":
        w *= 0.25
    elif f.llm and f.llm.verdict == "true_positive":
        w = catalog.SEVERITY_WEIGHT[f.severity]
    return w


def dimension_scores(findings: list[Finding], policy: dict) -> list[DimensionScore]:
    weights = policy["dimension_weights"]
    decay = float(policy.get("score_decay", 55.0))
    by_dim: dict[Dimension, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    counts: dict[Dimension, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        if f.status != "open":
            continue
        by_dim[f.dimension][f.rule_id].append(finding_weight(f))
        counts[f.dimension][f.severity.value] += 1
    out = []
    for dim in Dimension:
        penalty = 0.0
        for _rule_id, ws in by_dim[dim].items():
            ws.sort(reverse=True)
            base = ws[0] if ws else 0
            rule_pen = sum(w / (1 + 0.6 * i) for i, w in enumerate(ws))
            penalty += min(rule_pen, base * 2.5) if base else 0
        score = round(100 * math.exp(-penalty / decay))
        out.append(DimensionScore(dimension=dim, label=DIMENSION_LABELS[dim], score=score, weight=weights[dim.value],
                                  grade=next(g for t, g in GRADES if score >= t), counts=dict(counts[dim])))
    return out


def _blocking(f: Finding) -> bool:
    return f.status == "open" and f.confidence != "low"


def verdict(findings: list[Finding], scores: list[DimensionScore], server: McpServerInfo, metrics: Metrics,
            ctxt: AuditContext, policy: dict, llm_used: bool, scanners_ok: int, docs: int) -> Verdict:
    raw = sum(s.score * s.weight for s in scores) / sum(s.weight for s in scores)
    readiness = raw
    gates: list[str] = []
    crit = [f for f in findings if f.severity == Severity.critical and _blocking(f)]
    sec_high = [f for f in findings if f.severity == Severity.high and f.dimension == Dimension.security and _blocking(f)]
    any_high = [f for f in findings if f.severity == Severity.high and _blocking(f)]

    def cap(limit: float, why: str):
        nonlocal readiness
        if readiness > limit:
            readiness = limit
            gates.append(f"Capped at {int(limit)}%: {why}")

    if crit:
        rules = sorted({f.rule_id for f in crit})
        cap(35, f"{len(crit)} open critical finding(s) ({', '.join(rules[:5])}).")
    if len(sec_high) >= 3:
        cap(55, f"{len(sec_high)} open high-severity security findings.")
    elif sec_high:
        cap(70, f"{len(sec_high)} open high-severity security finding(s) must be fixed or formally accepted.")
    if len(any_high) >= 6:
        cap(60, f"{len(any_high)} open high-severity findings across dimensions.")
    if any(f.rule_id == "MNT-001" and f.status == "open" for f in findings):
        cap(70, "no automated tests: changes cannot be validated safely.")
    if ctxt.deployment == "shared" and server.transports == ["stdio"]:
        cap(60, "shared deployment requested but the server only supports stdio.")
    readiness = round(readiness)
    bands = policy["decision_bands"]
    if readiness >= bands["go"]:
        decision, label = "GO", "Go"
    elif readiness >= bands["conditions"]:
        decision, label = "GO_WITH_CONDITIONS", "Go with conditions"
    elif readiness >= bands["not_ready"]:
        decision, label = "NOT_READY", "Not ready — remediation required"
    else:
        decision, label = "NO_GO", "No-go"

    reasons, points = [], 0
    if server.detected:
        points += 2
    else:
        reasons.append("No MCP server pattern recognised: MCP-specific checks did not apply.")
    if server.tools:
        points += 1
    if llm_used:
        points += 2
    else:
        reasons.append("LLM semantic review not performed (static analysis only).")
    if scanners_ok:
        points += 1
    else:
        reasons.append("No external scanner (bandit/semgrep/gitleaks/…) was available to corroborate results.")
    if docs:
        points += 1
    else:
        reasons.append("No documentation provided: architecture intent could not be checked.")
    if metrics.files_analyzed < 3:
        reasons.append("Very few source files analysed.")
        points -= 2
    confidence = "high" if points >= 6 else "medium" if points >= 3 else "low"
    return Verdict(readiness=readiness, decision=decision, label=label, confidence=confidence, confidence_reasons=reasons,
                   gates=gates, raw_weighted=round(raw), sustainability=sustainability(scores, metrics, findings))


def sustainability(scores: list[DimensionScore], m: Metrics, findings: list[Finding]) -> int:
    """Long-term maintainability outlook: maintainability score blended with hard repository facts."""
    mnt = next(s.score for s in scores if s.dimension == Dimension.maintainability)
    pts, total = 0.0, 0.0

    def chk(ok: bool, w: float):
        nonlocal pts, total
        total += w
        pts += w if ok else 0

    chk(m.test_files > 0, 18)
    chk(m.test_ratio >= 0.3, 10)
    chk(m.has_ci, 14)
    chk(bool(m.lockfiles) or (m.dependencies_pinned_pct or 0) >= 90, 10)
    chk(m.has_readme, 8)
    chk(m.doc_files > 1, 5)
    chk(not any(f.rule_id == "MNT-007" and f.severity != Severity.low for f in findings), 8)
    chk(m.avg_complexity and m.avg_complexity <= 6 or not m.functions, 10)
    git = m.git or {}
    chk(not git or git.get("contributors", 1) > 1, 9)
    chk(not git or git.get("last_commit_days", 0) <= 180, 4)
    chk(m.typed_functions_pct is None or m.typed_functions_pct >= 60, 4)
    facts = 100 * pts / total if total else 50
    return round(0.55 * mnt + 0.45 * facts)


# --------------------------------------------------------------------------- action plan
HORIZON = {"P0": "Before production (blocker)", "P1": "Within 30 days", "P2": "Within 90 days", "P3": "Backlog / continuous improvement"}


def action_plan(findings: list[Finding]) -> list[ActionItem]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.status == "open" and f.severity != Severity.info:
            groups[f.rule_id].append(f)
    items = []
    for rule_id, fs in groups.items():
        fs.sort(key=lambda f: f.severity.rank)
        top = fs[0]
        sev = top.severity
        if sev == Severity.critical or (sev == Severity.high and top.dimension == Dimension.security):
            prio = "P0"
        elif sev == Severity.high or (sev == Severity.medium and top.dimension == Dimension.security):
            prio = "P1"
        elif sev == Severity.medium:
            prio = "P2"
        else:
            prio = "P3"
        if all(f.llm and f.llm.verdict == "false_positive" for f in fs):
            prio = "P3" if prio != "P0" else "P1"
        elif all(f.confidence == "low" for f in fs) and prio in ("P0", "P1"):
            prio = "P1" if prio == "P0" else "P2"      # unconfirmed signal: verify before treating as a blocker
        locs = []
        for f in fs[:8]:
            locs.append(f"{f.file}:{f.line}" if f.line else (f.file or (f.tool and f"tool {f.tool}") or "project"))
        items.append(ActionItem(priority=prio, title=top.title, rule_id=rule_id, dimension=top.dimension, severity=sev,
                                occurrences=len(fs), effort=top.effort, remediation=top.remediation, locations=locs, horizon=HORIZON[prio]))
    items.sort(key=lambda a: (a.priority, a.severity.rank, -a.occurrences))
    return items


# --------------------------------------------------------------------------- deterministic narrative
def rules_narrative(project: str, v: Verdict, scores: list[DimensionScore], findings: list[Finding], server: McpServerInfo,
                    metrics: Metrics, actions: list[ActionItem], ctxt: AuditContext) -> Narrative:
    open_f = [f for f in findings if f.status == "open"]
    sev_count = defaultdict(int)
    for f in open_f:
        sev_count[f.severity.value] += 1
    best = max(scores, key=lambda s: s.score)
    worst = min(scores, key=lambda s: s.score)
    tools = [t for t in server.tools if t.kind == "tool"]
    high_risk_tools = [t.name for t in tools if t.risk.rank <= Severity.high.rank]
    transports = ", ".join(server.transports) or "unknown"
    sdk = ", ".join(server.sdks) or "no recognised MCP SDK"
    p0 = [a for a in actions if a.priority == "P0"]
    p1 = [a for a in actions if a.priority == "P1"]
    exec_summary = (
        f"{project} was assessed for production use as a {'shared, multi-user' if ctxt.deployment == 'shared' else 'local, single-user'} MCP service "
        f"({'internet-facing' if ctxt.exposure == 'internet' else 'internal network'}, {ctxt.data_sensitivity} data sensitivity, ~{ctxt.expected_concurrency} concurrent users/agents). "
        f"The overall production-readiness score is {v.readiness}% — decision: {v.label.upper()} (confidence {v.confidence}). "
        f"The long-term sustainability outlook is {v.sustainability}%.\n\n"
        f"The server is built with {sdk}, exposes {len(tools)} tool(s) over {transports}"
        f"{', with authentication detected' if server.auth.detected else ', with no authentication detected'}. "
        f"{len(open_f)} open findings were raised: {sev_count['critical']} critical, {sev_count['high']} high, {sev_count['medium']} medium, {sev_count['low']} low. "
        f"Strongest area: {best.label} ({best.score}/100). Weakest area: {worst.label} ({worst.score}/100).\n\n"
    )
    if p0:
        exec_summary += (f"{len(p0)} blocker(s) must be resolved before go-live, notably: " + "; ".join(a.title for a in p0[:4]) + ". ")
    elif p1:
        exec_summary += (f"No blocker was found; {len(p1)} item(s) should be addressed within 30 days: " + "; ".join(a.title for a in p1[:4]) + ". ")
    else:
        exec_summary += "No blocker or high-priority item was found. "

    strengths = []
    if server.auth.detected:
        strengths.append(f"Authentication present ({', '.join(server.auth.mechanisms[:3])}).")
    if server.stateless_http:
        strengths.append("Stateless Streamable HTTP: horizontally scalable without sticky sessions.")
    ann = [t for t in tools if any(k in t.annotations for k in ("readOnlyHint", "destructiveHint"))]
    if tools and len(ann) >= 0.8 * len(tools):
        strengths.append(f"Behaviour annotations declared on {len(ann)}/{len(tools)} tools.")
    described = [t for t in tools if len(t.description) >= 40]
    if tools and len(described) >= 0.8 * len(tools):
        strengths.append("Tool descriptions are informative for agents.")
    for sig, label in (("rate_limit", "Rate limiting in place."), ("retry", "Retry/backoff for downstream calls."),
                       ("metrics_tracing", "Metrics/tracing instrumentation present."), ("structured_logging", "Structured logging."),
                       ("audit_log", "Audit trail / tool-call middleware present."), ("pooling", "Connection pooling."),
                       ("input_validation", "Schema-based input validation."), ("health", "Health endpoint exposed."),
                       ("human_confirmation", "Human confirmation / elicitation for sensitive actions.")):
        if sig in server.signals:
            strengths.append(label)
    if metrics.test_files:
        strengths.append(f"Automated tests present ({metrics.test_files} files, ratio {metrics.test_ratio:.2f}).")
    if metrics.has_ci:
        strengths.append(f"CI pipeline ({', '.join(metrics.ci_systems)}).")
    if metrics.lockfiles:
        strengths.append("Dependencies locked.")
    risks = [f"{a.title} ({a.severity.value}, {a.occurrences}×)" for a in actions[:6]]

    def dim_text(dim: Dimension, extra: str) -> str:
        s = next(x for x in scores if x.dimension == dim)
        fs = [f for f in open_f if f.dimension == dim]
        rules = defaultdict(int)
        for f in fs:
            rules[f.title] += 1
        top = "; ".join(f"{t} ({n}×)" for t, n in sorted(rules.items(), key=lambda kv: -kv[1])[:4])
        return f"Score {s.score}/100 (grade {s.grade}). {extra} " + (f"Main issues: {top}." if top else "No significant issue detected.")

    scal_extra = (f"Transport(s): {transports}; session mode: {'stateless' if server.stateless_http else 'stateful/unknown'}; "
                  f"rate limiting: {'yes' if 'rate_limit' in server.signals else 'no'}; async I/O: {'yes' if 'async_io' in server.signals else 'not detected'}; "
                  f"pooling: {'yes' if 'pooling' in server.signals else 'not detected'}.")
    sec_extra = (f"Authentication: {'detected' if server.auth.detected else 'not detected'}. "
                 f"High-risk tools: {', '.join(high_risk_tools[:8]) or 'none'}.")
    perf_extra = f"{len(tools)} tool(s) loaded into agent context; caching: {'yes' if 'cache' in server.signals else 'not detected'}."
    sus_extra = (f"{metrics.loc_total:,} LOC, avg. complexity {metrics.avg_complexity}, {metrics.complex_functions} complex function(s), "
                 f"tests {metrics.test_files} file(s), CI {'yes' if metrics.has_ci else 'no'}, lockfile {'yes' if metrics.lockfiles else 'no'}"
                 + (f", {metrics.git.get('contributors')} contributor(s)" if metrics.git else "") + ".")
    conditions = [f"[{a.priority}] {a.title} — {first_sentence(a.remediation)}" for a in actions if a.priority in ("P0", "P1")][:8]
    return Narrative(executive_summary=exec_summary.strip(), security=dim_text(Dimension.security, sec_extra),
                     scalability=dim_text(Dimension.scalability, scal_extra), performance=dim_text(Dimension.performance, perf_extra),
                     sustainability=dim_text(Dimension.maintainability, sus_extra),
                     architecture=f"{sdk}; transports {transports}; {len(tools)} tools, {len([t for t in server.tools if t.kind == 'resource'])} resources, "
                                  f"{len([t for t in server.tools if t.kind == 'prompt'])} prompts; entry points: {', '.join(server.entrypoints[:3]) or 'n/a'}.",
                     strengths=strengths[:10], key_risks=risks, conditions=conditions, generated_by="rules")


def first_sentence(text: str, limit: int = 180) -> str:
    import re
    m = re.search(r"^(.+?[.;])(\s+[A-Z(]|$)", text.strip())
    out = m.group(1) if m else text.strip()
    return out if len(out) <= limit else out[: limit - 1].rsplit(" ", 1)[0] + "…"


def compare(prev: list[Finding], cur: list[Finding]) -> dict:
    p = {f.fingerprint for f in prev if f.status == "open"}
    c = {f.fingerprint for f in cur if f.status == "open"}
    return {"fixed": len(p - c), "new": len(c - p), "persisting": len(p & c)}
