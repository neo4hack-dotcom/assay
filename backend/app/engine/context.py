"""The shared analysis context every detector writes findings into."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from . import catalog
from .models import AuditOptions, Finding, McpServerInfo, Metrics, Severity
from .workspace import SourceFile, Workspace

INLINE_SUPPRESS = re.compile(r"(assay\s*:\s*ignore(\[(?P<ids>[\w\-, ]+)\])?|nosec|NOSONAR)", re.I)
MAX_PER_RULE_PER_FILE = 5
SECRET_VALUE = re.compile(r"""(["'`])([^"'`\s]{6,})\1|(?<=[:=])\s*([^\s"'`#,;]{12,})""")


def redact(text: str) -> str:
    """Mask credential-looking values so the audit report never re-leaks a secret."""
    def _mask(m: re.Match) -> str:
        val = m.group(2) or m.group(3) or ""
        if not val:
            return m.group(0)
        masked = val[:4] + "…[REDACTED]"
        return m.group(0).replace(val, masked)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
                  "-----BEGIN PRIVATE KEY----- …[REDACTED]", text)
    text = re.sub(r"(?<=://)([^:/\s@]+):([^@\s/]+)@", r"\1:…[REDACTED]@", text)
    return SECRET_VALUE.sub(_mask, text)


@dataclass
class ToolSpan:
    file: str
    start: int
    end: int
    tool: str


@dataclass
class Ctx:
    ws: Workspace
    options: AuditOptions
    server: McpServerInfo = field(default_factory=McpServerInfo)
    metrics: Metrics = field(default_factory=Metrics)
    findings: list[Finding] = field(default_factory=list)
    spans: dict[str, list[ToolSpan]] = field(default_factory=lambda: defaultdict(list))
    _seen: set = field(default_factory=set)
    _per_file: dict = field(default_factory=lambda: defaultdict(int))
    _overflow: dict = field(default_factory=lambda: defaultdict(int))
    _last: dict = field(default_factory=dict)

    # ------------------------------------------------------------ spans
    def tool_at(self, rel: str, line: int) -> str:
        best = None
        for s in self.spans.get(rel, ()):
            if s.start <= line <= s.end and (best is None or (s.end - s.start) < (best.end - best.start)):
                best = s
        return best.tool if best else ""

    def in_tool(self, rel: str, line: int) -> bool:
        return bool(self.tool_at(rel, line))

    # ------------------------------------------------------------ findings
    def add(self, rule_id: str, sf: SourceFile | None = None, line: int = 0, *, message: str = "",
            severity: Severity | None = None, confidence: str | None = None, snippet: str | None = None,
            source: str = "static", tool: str | None = None, title: str | None = None,
            file: str | None = None, end_line: int = 0) -> Finding | None:
        rule = catalog.RULES.get(rule_id)
        rel = sf.rel if sf else (file or "")
        key = (rule_id, rel, line, message if not line else "")
        if key in self._seen:
            return None
        self._seen.add(key)
        if rel and line:
            self._per_file[(rule_id, rel)] += 1
            if self._per_file[(rule_id, rel)] > MAX_PER_RULE_PER_FILE:
                self._overflow[(rule_id, rel)] += 1
                return None
        if snippet is None and sf and line:
            snippet = sf.snippet(line)
        snippet = snippet or ""
        if rule_id in ("SEC-007", "SEC-021"):
            snippet = redact(snippet)
            message = redact(message)
        sev = severity or (rule.severity if rule else Severity.medium)
        tool_name = tool if tool is not None else (self.tool_at(rel, line) if rel and line else "")
        f = Finding(
            rule_id=rule_id,
            title=title or (rule.title if rule else rule_id),
            severity=sev,
            dimension=rule.dimension if rule else catalog.Dimension.security,
            confidence=confidence or ("high" if tool_name else "medium"),
            message=message, file=rel, line=line, end_line=end_line or line, snippet=snippet,
            tool=tool_name, source=source,
            description=rule.description if rule else "", impact=rule.impact if rule else "",
            remediation=rule.remediation if rule else "", effort=(rule.effort if rule else "M"),
            standards=rule.standards() if rule else catalog.Standards(),
            references=rule.references() if rule else [],
        )
        if sf and line:
            m = INLINE_SUPPRESS.search(sf.line(line))
            if m and (not m.group("ids") or rule_id in m.group("ids")):
                f.status = "suppressed_inline"
                f.status_reason = "Suppressed by an inline comment in the source."
        if sf and sf.is_test and rule_id != "SEC-007":
            f.severity = f.severity.bump(-1)
            f.context_note = "Located in test code."
        elif sf and sf.is_aux and rule_id not in ("SEC-007", "SEC-021"):
            f.severity = f.severity.bump(-1)
            f.confidence = "low"
            f.context_note = "Located in auxiliary code (docs/examples/scripts), not in the server itself."
        f.compute_fingerprint()
        self.findings.append(f)
        self._last[(rule_id, rel)] = f
        return f

    def finalize(self) -> None:
        # one root cause, one finding: drop the weaker duplicate of a more specific rule
        supersede = {"SEC-010": "MCP-012", "MCP-008": "MCP-013", "SEC-016": "SEC-007", "PRF-002": "MCP-010"}
        index = {(f.rule_id, f.file, f.line) for f in self.findings}
        tools_by_rule = {(f.rule_id, f.tool) for f in self.findings if f.tool}
        keep = []
        for f in self.findings:
            strong = supersede.get(f.rule_id)
            if strong and ((strong, f.file, f.line) in index or (f.tool and (strong, f.tool) in tools_by_rule)):
                continue
            keep.append(f)
        # same line flagged by the high-confidence async rule and the low-confidence sync-tool variant
        hi = {(f.file, f.line) for f in keep if f.rule_id == "SCL-004" and f.confidence == "high"}
        self.findings = [f for f in keep if not (f.rule_id == "SCL-004" and f.confidence == "low" and (f.file, f.line) in hi)]
        for (rule_id, rel), extra in self._overflow.items():
            f = self._last.get((rule_id, rel))
            if f:
                f.message = (f.message + " " if f.message else "") + f"(+{extra} similar occurrence(s) in this file.)"

    def project_text(self, *langs: str, include_tests: bool = False) -> str:
        return "\n".join(f.text for f in self.ws.files
                         if (not langs or f.language in langs) and (include_tests or not f.is_test))
