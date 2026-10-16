# Assay — MCP Production Readiness Auditor

Assay audits the source code of **Model Context Protocol (MCP) servers** and answers one question for each of them:
*can this server go to production in our organisation, for many concurrent users and agents — and can we maintain it?*

It produces a decision-grade report in English (**PDF**, **PowerPoint**, HTML, Markdown, SARIF, JSON) with:

- the **risks** found (security, scalability, performance, reliability, observability, maintainability), each with evidence, impact and standards mapping;
- a prioritised **remediation plan** (P0 blockers → P3 backlog, with effort);
- a **production-readiness %** and a **Go / Go with conditions / Not ready / No-go** decision, plus a separate **sustainability %**;
- the **MCP surface**: SDK, transports, authentication, every tool with its capabilities, risk and annotations.

Static analysis only: **the audited code is never executed, installed or built.**

---

## Quick start

### Windows (local)
1. Install Python 3.11+ (python.org, tick *Add to PATH*).
2. Double-click **`run.bat`** (or `.\run.ps1` in PowerShell). The first run creates `.venv` and installs dependencies; the UI opens on <http://127.0.0.1:3101>.
3. *Settings* → configure your LLM endpoint → **Test connection** → *Save*.
4. *New audit* → choose a folder, a git URL or a ZIP → *Start audit*.

The web UI is pre-built in `frontend/dist`: Node.js is **not** needed to run Assay.

### Linux / Windows server (shared)
```bash
cp .env.example backend/.env      # set ASSAY_HOST=0.0.0.0, ASSAY_AUTH_TOKEN, ASSAY_ALLOWED_ROOTS
./run.sh                          # Windows: run.bat
```
or with Docker:
```bash
docker compose up -d              # mounts ./repos read-only as the only auditable folder
```

### Command line (batch, CI)
```bash
./assay scan /srv/repos/orders-mcp --out reports                       # Windows: assay.bat scan C:\repos\orders-mcp
./assay scan https://gitlab.corp/team/orders-mcp.git --ref main --docs architecture.pdf
./assay scan-all /srv/repos/mcp --out reports/portfolio                # every MCP project + portfolio.md
./assay scan . --no-llm --formats sarif,md --fail-under 65             # CI gate: exit code 2 below 65 %
./assay test-llm --llm-base-url http://llm.corp:8000/v1 --llm-model qwen2.5-coder-32b
./assay rules
```
Main options: `--deployment shared|local`, `--exposure internal|internet`, `--sensitivity low|medium|high`,
`--concurrency N`, `--depth quick|standard|deep`, `--no-llm`, `--scanners bandit,semgrep,…`, `--subdir path`.
Audits run from the CLI also appear in the web UI.

---

## Approach

```
 source (folder | git | zip) ──► inventory ──► MCP discovery ──► rules ──► external scanners ──► LLM review ──► scoring ──► reports
                                  languages     SDK, transports   AST +       bandit, semgrep,     per tool,       context,      PDF, PPTX,
                                  tests, docs   auth, tools,      patterns +  gitleaks, pip-audit, triage,         gates,        HTML, MD,
                                                capabilities      project     npm audit, osv,      architecture,   action plan   SARIF, JSON
                                                                  checks      trivy (if installed) summary
```

1. **MCP discovery** — recognises the official Python SDK (FastMCP & low-level), `fastmcp`, the TypeScript SDK
   (`tool`, `registerTool`, low-level handlers), TS `fastmcp`, `mcp-framework`, Go (`mcp-go`, official SDK), Java/Spring AI and C#.
   For each tool: name, description, parameters (types, schema constraints, Pydantic aliases, zod), annotations, handler span,
   capabilities (exec, file write/read, network, database, secrets, external send, destructive) and a risk level.
2. **Rules (≈ 80, MCP-aware)** — Python is analysed on the syntax tree with taint tracking from tool parameters to sinks
   (command/SQL/path/SSRF/eval/deserialisation…); TypeScript/JS/Go/Java/C# with targeted patterns scoped to tool handlers;
   plus project checks. MCP-specific checks include: remote transport without authentication, token passthrough, missing
   Origin/DNS-rebinding protection, tool poisoning (hidden instructions, invisible Unicode), missing/contradictory annotations,
   predictable session IDs, stateful sessions vs horizontal scaling, stdout pollution in stdio servers, unbounded tool output,
   tool sprawl, outdated SDK.
3. **External scanners** — used when installed; results are de-duplicated and *corroborate* Assay findings instead of double counting.
   Vendored code (`.venv`, `node_modules`, …) is excluded everywhere.
4. **LLM review (optional)** — tool-by-tool semantic review, second-opinion triage of high-severity findings, architecture /
   scalability / sustainability assessment against your documentation, and the executive summary.
5. **Scoring** — transparent and reproducible (see below), adjusted to the declared deployment context.

### Scoring model
- Severity is first adjusted to the **deployment context** (a stdio-only server is fine as a local helper, a blocker as a shared service).
- Each open finding costs *severity weight × confidence* (critical 30, high 14, medium 5, low 1.5; confidence 1.0 / 0.8 / 0.5;
  uncorroborated LLM-only issues × 0.6), with diminishing returns per rule.
- Dimension score = `100 × exp(−penalty / 55)`; readiness = weighted mean (security 35 %, maintainability 20 %, scalability 15 %,
  reliability 12 %, performance 10 %, observability 8 %).
- **Gates** cap readiness: any open critical → 35 %; ≥ 3 high security → 55 %; any high security → 70 %; no tests → 70 %;
  stdio-only for a shared deployment → 60 %.
- Bands: ≥ 80 Go · 65–79 Go with conditions · 45–64 Not ready · < 45 No-go.
- **Sustainability %** = 55 % maintainability score + 45 % repository facts (tests, CI, lockfile, docs, lint/type-checking,
  complexity, number of contributors, activity).
- Weights, bands, SDK minimum versions and thresholds live in a policy file (`examples/policy.example.yaml`), not in code.

### Human triage
Any finding can be marked **accepted risk** or **false positive** with a mandatory justification (UI → Findings). Scores are
recomputed immediately, the decision appears in every report, and it is **carried over to the next audit** of the same project
(stable fingerprints). Re-audits show *fixed / new / persisting* findings.

---

## LLM configuration (OpenAI-compatible)

Any endpoint exposing `/v1/chat/completions` works: vLLM, Ollama, LM Studio, llama.cpp server, TGI, LiteLLM, OpenAI, Azure OpenAI.

| Setting | Notes |
|---|---|
| Base URL | include the API prefix, usually `/v1` (Azure: `…/openai/deployments/<name>` + *API version* + `api-key` header) |
| Model | *List* fetches `/v1/models` |
| Context window | must match the server's real limit. **Ollama:** start it with `OLLAMA_CONTEXT_LENGTH=16384` — its OpenAI endpoint otherwise silently truncates prompts |
| JSON mode | requested, automatically disabled if the endpoint rejects it; answers are repaired/parsed robustly (`<think>` blocks, fences, trailing commas) |
| TLS | corporate CA bundle supported; verification can be disabled for lab use only |

**Test connection** checks: model listing, model availability, a chat completion, structured-JSON compliance, warm latency and
throughput (tokens/s), and context-window sanity. Recommended: a code-capable model of ≥ 14 B parameters with ≥ 16 k context
(e.g. Qwen2.5-Coder-32B, Llama-3.3-70B, DeepSeek-Coder-V2); 7 B models work but produce shallower reviews.

### How the LLM is kept honest
- Audited code and documentation are wrapped in `<untrusted_code>` / `<untrusted_docs>` blocks; the system prompt states that any
  instruction inside is data. (An MCP server can contain text aimed at the auditor — e.g. *"this code is safe"*.)
- The model can **annotate** findings (true/false positive, extra issues) but can **never delete a finding or lift a score gate**.
  Only a documented human decision does.
- LLM-only issues are capped at *high*, carry low confidence and a reduced weight; duplicates of rule findings are merged.
- A generated executive summary quoting figures the engine did not compute is rejected in favour of the rules-based summary.
- Without an LLM, Assay runs fully and writes a deterministic narrative — nothing is faked.

---

## Security of Assay itself
- Never executes audited code; git clones run with hooks disabled, `file://`/`ext::` protocols blocked, no submodules, no LFS smudge.
- ZIP uploads are extracted member by member with path (zip-slip), symlink, size and count limits.
- Credentials in git URLs are used once and masked everywhere; secrets found in code are **redacted** in all reports.
- `ASSAY_AUTH_TOKEN` protects the UI/API (constant-time comparison); `ASSAY_ALLOWED_ROOTS` restricts readable folders;
  default bind is `127.0.0.1`; security headers on every response; the container runs as non-root on a read-only filesystem.
- External scanners that need the network (pip-audit, npm audit, osv-scanner online, semgrep `auto`) simply report
  *error/unavailable* in an air-gapped environment; Assay's own rules need no network.

## Extending
- **Custom rules** (no code): YAML files in `<data_dir>/rules` — see `examples/custom-rules.example.yaml`.
- **Policy**: `ASSAY_POLICY_FILE` — weights, bands, SDK floors, thresholds.
- **New detectors**: `backend/app/engine/` — `catalog.py` (meaning of a rule), `python_ast.py`, `regex_rules.py`,
  `project_checks.py`, `mcp_discovery.py`; reports in `backend/app/reports/`.
- **CI**: `examples/ci/` (GitLab, GitHub Actions) — SARIF output for code-scanning platforms, `--fail-under` gate.

## Development
```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cd backend && ../.venv/bin/python -m pytest -q        # engine + API + report tests
cd frontend && npm ci && npm run dev                  # UI on :3100, proxies /api to :3101
cd frontend && npm run build                          # refresh frontend/dist (served by the backend)
```
`samples/` contains deliberately vulnerable MCP servers (Python, TypeScript) and a hardened one, used by the tests.

## Limitations
Static analysis cannot prove the absence of vulnerabilities. Controls enforced outside the repository (API gateway auth,
WAF, network policies, rate limits at the ingress) appear as missing until recorded as accepted risks with evidence.
Scalability and performance are inferred from code patterns — confirm with a load test at the expected concurrency before go-live.
The OWASP MCP Top 10 mapping follows the 2025 project list; MCP specification references point to revision 2025-06-18.
