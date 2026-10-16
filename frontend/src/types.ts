// Mirrors backend/app/engine/models.py (hand-maintained; keep snake_case).
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Dimension = 'security' | 'scalability' | 'performance' | 'reliability' | 'observability' | 'maintainability';
export type Decision = 'GO' | 'GO_WITH_CONDITIONS' | 'NOT_READY' | 'NO_GO';
export type AuditStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
export type FindingStatus = 'open' | 'accepted' | 'false_positive' | 'suppressed_inline';

export interface Standards { cwe: string[]; owasp_mcp: string[]; owasp_llm: string[]; mcp_spec: string[] }
export interface Reference { label: string; url: string }

export interface Finding {
  rule_id: string; title: string; severity: Severity; dimension: Dimension; confidence: 'high' | 'medium' | 'low';
  message: string; file: string; line: number; end_line: number; snippet: string; tool: string; source: string;
  description: string; impact: string; remediation: string; effort: 'S' | 'M' | 'L';
  standards: Standards; references: Reference[]; status: FindingStatus; status_reason: string;
  llm: { verdict: 'true_positive' | 'false_positive' | 'uncertain'; rationale: string; model: string } | null;
  context_note: string; fingerprint: string;
}

export interface ToolParam { name: string; type: string; required: boolean; constrained: boolean; description: string }
export interface McpTool {
  name: string; kind: 'tool' | 'resource' | 'prompt'; description: string; file: string; line: number; end_line: number;
  params: ToolParam[]; annotations: Record<string, boolean | string>; capabilities: string[]; risk: Severity;
  risk_reasons: string[]; is_async: boolean | null;
  llm_review: { risk?: string; summary?: string; description_quality?: string; annotations_correct?: boolean | null; prompt_injection_suspected?: boolean; model?: string } | null;
}

export interface McpServerInfo {
  detected: boolean; names: string[]; sdks: string[]; sdk_versions: Record<string, string>; languages: string[];
  transports: string[]; stateless_http: boolean | null;
  auth: { detected: boolean; mechanisms: string[]; evidence: string[] };
  entrypoints: string[]; tools: McpTool[]; signals: Record<string, string[]>;
}

export interface Metrics {
  files_total: number; files_analyzed: number; files_skipped: number; loc_total: number; loc_by_language: Record<string, number>;
  test_files: number; test_loc: number; test_ratio: number; functions: number; avg_complexity: number; max_complexity: number;
  complex_functions: number; hotspots: { file: string; function: string; line: number; ccn: number; nloc: number }[];
  typed_functions_pct: number | null; todo_count: number; dependencies: number; dependencies_pinned_pct: number | null;
  lockfiles: string[]; has_readme: boolean; has_ci: boolean; ci_systems: string[]; has_license: boolean; has_dockerfile: boolean;
  has_changelog: boolean; doc_files: number; git: Record<string, number | boolean>;
}

export interface DimensionScore { dimension: Dimension; label: string; score: number; weight: number; grade: string; counts: Record<string, number> }
export interface Verdict {
  readiness: number; decision: Decision; label: string; confidence: 'high' | 'medium' | 'low'; confidence_reasons: string[];
  gates: string[]; sustainability: number; raw_weighted: number;
}
export interface ActionItem {
  priority: 'P0' | 'P1' | 'P2' | 'P3'; title: string; rule_id: string; dimension: Dimension; severity: Severity;
  occurrences: number; effort: 'S' | 'M' | 'L'; remediation: string; locations: string[]; horizon: string;
}
export interface Narrative {
  executive_summary: string; security: string; scalability: string; performance: string; sustainability: string;
  architecture: string; strengths: string[]; key_risks: string[]; conditions: string[]; generated_by: string;
}
export interface AuditContext { deployment: 'local' | 'shared'; exposure: 'internal' | 'internet'; data_sensitivity: 'low' | 'medium' | 'high'; expected_concurrency: number }
export interface AuditOptions { use_llm: boolean; depth: 'quick' | 'standard' | 'deep'; include_tests: boolean; external_tools: string[]; context: AuditContext }
export interface SourceSpec { kind: 'path' | 'git' | 'zip'; location: string; ref: string; subdir: string }
export interface StageLog { ts: number; stage: string; message: string; level: 'info' | 'warning' | 'error' }
export interface ScannerRun { name: string; status: 'ok' | 'skipped' | 'unavailable' | 'error'; detail: string; findings: number; duration_s: number }

export interface AuditResult {
  id: string; project: string; created_at: number; finished_at: number | null; status: AuditStatus; progress: number;
  stage: string; error: string; source: SourceSpec; options: AuditOptions; tool_version: string; commit: string; llm_model: string;
  server: McpServerInfo; metrics: Metrics; findings: Finding[]; scores: DimensionScore[]; verdict: Verdict | null;
  actions: ActionItem[]; narrative: Narrative; scanners: ScannerRun[]; docs_used: string[]; logs: StageLog[];
  comparison: { previous_id: string; previous_readiness: number | null; fixed: number; new: number; persisting: number } | null;
}

export interface AuditSummary {
  id: string; project: string; created_at: number; finished_at: number | null; status: AuditStatus; progress: number; stage: string;
  error: string; source: SourceSpec; readiness: number | null; decision: Decision | null; label: string | null;
  sustainability: number | null; confidence: string | null; scores: Partial<Record<Dimension, number>>;
  counts: Record<'critical' | 'high' | 'medium' | 'low', number>; tools: number; llm_model: string; commit: string;
  comparison: AuditResult['comparison'];
}

export interface LlmSettings {
  base_url: string; api_key: string; api_key_set?: boolean; model: string; temperature: number; max_output_tokens: number;
  context_window: number; timeout_s: number; max_concurrency: number; json_mode: boolean; verify_tls: boolean; ca_bundle: string;
  auth_header: 'bearer' | 'api-key' | 'none'; api_version: string; extra_headers: Record<string, string>;
}
export interface ScannerSettings { timeout_s: number; semgrep_config: string; default_tools: string[] }
export interface SettingsResponse {
  llm: LlmSettings; scanners: ScannerSettings;
  server: { host: string; port: number; data_dir: string; allowed_roots: string[]; auth_required: boolean; policy_file: string; custom_rules_dir: string; version: string };
}
export interface LlmTestReport {
  ok: boolean; base_url: string; model: string; models?: string[]; tokens_per_s?: number; latency_ms?: number; json_mode_supported?: boolean;
  steps: { name: string; ok: boolean; detail: string; ms: number | null }[];
}
export interface Rule {
  id: string; title: string; dimension: Dimension; severity: Severity; description: string; impact: string; remediation: string;
  effort: string; standards: Standards; tags: string[]; references: Reference[];
}
export interface Health { ok: boolean; app: string; version: string; llm_configured: boolean; llm_model: string; auth_required: boolean }
export interface BrowseResult { path: string; parent: string | null; dirs: { name: string; path: string; project?: boolean }[] }
export interface ScannerInfo { name: string; available: boolean; path: string }
