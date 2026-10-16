"""Core data model shared by the engine, the API, the CLI and the report renderers.

Everything an audit produces is one `AuditResult`. It is plain Pydantic so it
serialises to the JSON store, the REST API and every report format without a
second representation drifting out of sync.
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    def bump(self, steps: int) -> "Severity":
        """Move up (positive) or down (negative) the scale, clamped."""
        idx = min(max(self.rank - steps, 0), len(SEVERITY_ORDER) - 1)
        return SEVERITY_ORDER[idx]


SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


class Dimension(str, Enum):
    security = "security"
    scalability = "scalability"
    performance = "performance"
    reliability = "reliability"
    observability = "observability"
    maintainability = "maintainability"


DIMENSION_LABELS = {
    Dimension.security: "Security",
    Dimension.scalability: "Scalability",
    Dimension.performance: "Performance & Token Efficiency",
    Dimension.reliability: "Reliability & Resilience",
    Dimension.observability: "Observability & Auditability",
    Dimension.maintainability: "Maintainability & Sustainability",
}

Confidence = Literal["high", "medium", "low"]
FindingStatus = Literal["open", "accepted", "false_positive", "suppressed_inline"]


class Reference(BaseModel):
    label: str
    url: str = ""


class Standards(BaseModel):
    cwe: list[str] = Field(default_factory=list)
    owasp_mcp: list[str] = Field(default_factory=list)   # OWASP MCP Top 10 (2025)
    owasp_llm: list[str] = Field(default_factory=list)   # OWASP Top 10 for LLM Applications (2025)
    mcp_spec: list[str] = Field(default_factory=list)    # MCP specification sections


class LlmVerdict(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    rationale: str = ""
    model: str = ""


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    dimension: Dimension
    confidence: Confidence = "medium"
    message: str = ""                 # occurrence-specific explanation
    file: str = ""                    # path relative to project root ("" = project level)
    line: int = 0
    end_line: int = 0
    snippet: str = ""
    tool: str = ""                    # MCP tool whose handler contains this occurrence
    source: str = "static"            # static | ast | project | llm | bandit | semgrep | gitleaks | ...
    description: str = ""
    impact: str = ""
    remediation: str = ""
    effort: Literal["S", "M", "L"] = "M"
    standards: Standards = Field(default_factory=Standards)
    references: list[Reference] = Field(default_factory=list)
    status: FindingStatus = "open"
    status_reason: str = ""
    llm: LlmVerdict | None = None
    context_note: str = ""            # why the deployment context changed the severity
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        # Line numbers move on every edit; the rule + file + normalised code does not.
        # This is what lets a re-audit say "fixed / new / still there".
        norm = " ".join(self.snippet.split())[:200]
        raw = f"{self.rule_id}|{self.file}|{norm}|{self.tool}|{self.message if not self.file else ''}"
        self.fingerprint = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]
        return self.fingerprint


class ToolParam(BaseModel):
    name: str
    type: str = ""
    required: bool = True
    constrained: bool = False         # has a schema constraint (enum, pattern, max_length, Literal...)
    description: str = ""


class McpTool(BaseModel):
    name: str
    kind: Literal["tool", "resource", "prompt"] = "tool"
    description: str = ""
    file: str = ""
    line: int = 0
    end_line: int = 0
    params: list[ToolParam] = Field(default_factory=list)
    annotations: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)   # exec, fs_read, fs_write, network, db, secrets, destructive
    risk: Severity = Severity.low
    risk_reasons: list[str] = Field(default_factory=list)
    is_async: bool | None = None
    llm_review: dict[str, Any] | None = None


class AuthInfo(BaseModel):
    detected: bool = False
    mechanisms: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class McpServerInfo(BaseModel):
    detected: bool = False
    names: list[str] = Field(default_factory=list)
    sdks: list[str] = Field(default_factory=list)
    sdk_versions: dict[str, str] = Field(default_factory=dict)
    languages: list[str] = Field(default_factory=list)
    transports: list[str] = Field(default_factory=list)      # stdio | sse | streamable-http
    stateless_http: bool | None = None
    auth: AuthInfo = Field(default_factory=AuthInfo)
    entrypoints: list[str] = Field(default_factory=list)
    tools: list[McpTool] = Field(default_factory=list)
    signals: dict[str, list[str]] = Field(default_factory=dict)   # positive controls found: rate_limit, cache, retry...


class FileStat(BaseModel):
    path: str
    language: str
    loc: int
    is_test: bool = False


class Metrics(BaseModel):
    files_total: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    loc_total: int = 0
    loc_by_language: dict[str, int] = Field(default_factory=dict)
    test_files: int = 0
    test_loc: int = 0
    test_ratio: float = 0.0
    functions: int = 0
    avg_complexity: float = 0.0
    max_complexity: int = 0
    complex_functions: int = 0
    hotspots: list[dict[str, Any]] = Field(default_factory=list)
    typed_functions_pct: float | None = None
    todo_count: int = 0
    dependencies: int = 0
    dependencies_pinned_pct: float | None = None
    lockfiles: list[str] = Field(default_factory=list)
    has_readme: bool = False
    has_ci: bool = False
    ci_systems: list[str] = Field(default_factory=list)
    has_license: bool = False
    has_dockerfile: bool = False
    has_changelog: bool = False
    doc_files: int = 0
    git: dict[str, Any] = Field(default_factory=dict)


class DimensionScore(BaseModel):
    dimension: Dimension
    label: str
    score: int
    weight: float
    grade: str
    counts: dict[str, int] = Field(default_factory=dict)
    summary: str = ""


class Verdict(BaseModel):
    readiness: int                     # 0-100, "production readiness" percentage
    decision: Literal["GO", "GO_WITH_CONDITIONS", "NOT_READY", "NO_GO"]
    label: str
    confidence: Literal["high", "medium", "low"]
    confidence_reasons: list[str] = Field(default_factory=list)
    gates: list[str] = Field(default_factory=list)     # caps applied and why
    sustainability: int = 0            # 0-100, long-term maintainability outlook
    raw_weighted: int = 0


class ActionItem(BaseModel):
    priority: Literal["P0", "P1", "P2", "P3"]
    title: str
    rule_id: str
    dimension: Dimension
    severity: Severity
    occurrences: int
    effort: Literal["S", "M", "L"]
    remediation: str
    locations: list[str] = Field(default_factory=list)
    horizon: str = ""


class Narrative(BaseModel):
    executive_summary: str = ""
    security: str = ""
    scalability: str = ""
    performance: str = ""
    sustainability: str = ""
    architecture: str = ""
    strengths: list[str] = Field(default_factory=list)
    key_risks: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    generated_by: str = "rules"        # "rules" or the LLM model name


class AuditContext(BaseModel):
    """How the MCP is meant to be run. The same code is fine as a local stdio helper
    and a blocker as a shared multi-tenant service, so severity depends on this."""
    deployment: Literal["local", "shared"] = "shared"
    exposure: Literal["internal", "internet"] = "internal"
    data_sensitivity: Literal["low", "medium", "high"] = "medium"
    expected_concurrency: int = 50


class AuditOptions(BaseModel):
    use_llm: bool = True
    depth: Literal["quick", "standard", "deep"] = "standard"
    include_tests: bool = False
    external_tools: list[str] = Field(default_factory=lambda: ["bandit", "semgrep", "gitleaks", "pip-audit", "npm-audit", "osv-scanner"])
    context: AuditContext = Field(default_factory=AuditContext)


class SourceSpec(BaseModel):
    kind: Literal["path", "git", "zip"]
    location: str                      # path, URL (credentials masked once stored) or uploaded zip name
    ref: str = ""                      # git branch/tag
    subdir: str = ""                   # analyse only this sub-folder of the source


class StageLog(BaseModel):
    ts: float
    stage: str
    message: str
    level: Literal["info", "warning", "error"] = "info"


class ScannerRun(BaseModel):
    name: str
    status: Literal["ok", "skipped", "unavailable", "error"]
    detail: str = ""
    findings: int = 0
    duration_s: float = 0.0


class AuditResult(BaseModel):
    id: str
    project: str
    created_at: float
    finished_at: float | None = None
    status: Literal["queued", "running", "done", "failed", "cancelled"] = "queued"
    progress: int = 0
    stage: str = ""
    error: str = ""
    source: SourceSpec
    options: AuditOptions
    tool_version: str = ""
    commit: str = ""
    llm_model: str = ""
    server: McpServerInfo = Field(default_factory=McpServerInfo)
    metrics: Metrics = Field(default_factory=Metrics)
    findings: list[Finding] = Field(default_factory=list)
    scores: list[DimensionScore] = Field(default_factory=list)
    verdict: Verdict | None = None
    actions: list[ActionItem] = Field(default_factory=list)
    narrative: Narrative = Field(default_factory=Narrative)
    scanners: list[ScannerRun] = Field(default_factory=list)
    docs_used: list[str] = Field(default_factory=list)
    logs: list[StageLog] = Field(default_factory=list)
    comparison: dict[str, Any] | None = None
