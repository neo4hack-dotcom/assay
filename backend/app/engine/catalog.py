"""The rule catalog: what every check means, why it matters and how to fix it.

Detection lives elsewhere (regex_rules, python_ast, mcp_checks, project_checks);
this file is the single source of truth for the *meaning* of a rule, so the
report, the UI rules browser and the SARIF export all describe a finding the
same way. Organisation-specific rules can be added without code via YAML
(see engine/custom_rules.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Dimension, Reference, Severity, Standards

SPEC = "https://modelcontextprotocol.io/specification/2025-06-18"
SPEC_SEC = f"{SPEC}/basic/security_best_practices"
SPEC_AUTH = f"{SPEC}/basic/authorization"
SPEC_TRANSPORT = f"{SPEC}/basic/transports"
SPEC_TOOLS = f"{SPEC}/server/tools"
OWASP_MCP = "https://owasp.org/www-project-mcp-top-10/"
OWASP_LLM = "https://genai.owasp.org/llm-top-10/"

# OWASP MCP Top 10 (2025)
MCP01 = "MCP01:2025 Token Mismanagement & Secret Exposure"
MCP02 = "MCP02:2025 Privilege Escalation via Scope Creep"
MCP03 = "MCP03:2025 Tool Poisoning"
MCP04 = "MCP04:2025 Software Supply Chain Attacks"
MCP05 = "MCP05:2025 Command Injection & Execution"
MCP06 = "MCP06:2025 Prompt Injection via Contextual Payloads"
MCP07 = "MCP07:2025 Insufficient Authentication & Authorization"
MCP08 = "MCP08:2025 Lack of Audit and Telemetry"
MCP09 = "MCP09:2025 Shadow MCP Servers"
MCP10 = "MCP10:2025 Context Injection & Over-Sharing"
# OWASP Top 10 for LLM Applications (2025)
LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM05 = "LLM05:2025 Improper Output Handling"
LLM06 = "LLM06:2025 Excessive Agency"
LLM10 = "LLM10:2025 Unbounded Consumption"


@dataclass
class Rule:
    id: str
    title: str
    dimension: Dimension
    severity: Severity
    description: str
    impact: str
    remediation: str
    effort: str = "M"
    cwe: list[str] = field(default_factory=list)
    owasp_mcp: list[str] = field(default_factory=list)
    owasp_llm: list[str] = field(default_factory=list)
    mcp_spec: list[str] = field(default_factory=list)
    refs: list[tuple[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def standards(self) -> Standards:
        return Standards(cwe=self.cwe, owasp_mcp=self.owasp_mcp, owasp_llm=self.owasp_llm, mcp_spec=self.mcp_spec)

    def references(self) -> list[Reference]:
        out = [Reference(label=l, url=u) for l, u in self.refs]
        for c in self.cwe:
            num = c.split("-")[-1]
            out.append(Reference(label=c, url=f"https://cwe.mitre.org/data/definitions/{num}.html"))
        return out

    def as_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "dimension": self.dimension.value,
            "severity": self.severity.value, "description": self.description, "impact": self.impact,
            "remediation": self.remediation, "effort": self.effort,
            "standards": self.standards().model_dump(), "tags": self.tags,
            "references": [r.model_dump() for r in self.references()],
        }


S, D = Severity, Dimension
RULES: dict[str, Rule] = {}


def _r(**kw) -> Rule:
    rule = Rule(**kw)
    RULES[rule.id] = rule
    return rule


# ---------------------------------------------------------------- security
_r(id="SEC-001", title="OS command injection", dimension=D.security, severity=S.critical,
   description="A shell or process is spawned with a command built from non-constant data (shell=True, os.system, child_process.exec, sh -c...).",
   impact="Any agent, or any prompt injected into an agent, that reaches this tool can run arbitrary commands with the server's privileges: full host compromise, lateral movement, data exfiltration.",
   remediation="Never pass model-controlled strings to a shell. Use an argument vector without a shell (subprocess.run([...], shell=False) / execFile), validate each argument against a strict allow-list, and run the server under a least-privilege account or sandbox.",
   effort="M", cwe=["CWE-78"], owasp_mcp=[MCP05], owasp_llm=[LLM05, LLM06],
   refs=[("OWASP MCP Top 10", OWASP_MCP)], tags=["injection"])
_r(id="SEC-002", title="Dynamic code evaluation", dimension=D.security, severity=S.critical,
   description="eval/exec/compile, new Function or vm.run* evaluates code that is not a constant.",
   impact="Remote code execution if any part of the evaluated string is influenced by tool arguments, resources or downstream data.",
   remediation="Remove dynamic evaluation. Use a parser for the expected grammar (ast.literal_eval, JSON, a dedicated expression library with a sandboxed AST allow-list).",
   effort="M", cwe=["CWE-95"], owasp_mcp=[MCP05], owasp_llm=[LLM05], tags=["injection"])
_r(id="SEC-003", title="SQL built by string formatting", dimension=D.security, severity=S.high,
   description="A SQL statement passed to execute/query is assembled with f-strings, concatenation, % or .format instead of bind parameters.",
   impact="SQL injection: an agent (or a prompt-injected agent) can read, modify or delete data beyond its intended scope.",
   remediation="Use parameterised queries / bind variables for every value; validate identifiers (table/column names) against an allow-list; connect with a read-only database role where possible.",
   effort="S", cwe=["CWE-89"], owasp_mcp=[MCP05], owasp_llm=[LLM05], tags=["injection"])
_r(id="SEC-004", title="Insecure deserialization", dimension=D.security, severity=S.high,
   description="pickle/marshal/shelve/jsonpickle, yaml.load without a safe loader, or node-serialize is used.",
   impact="Deserialising attacker-influenced data executes arbitrary code.",
   remediation="Use JSON or yaml.safe_load; never unpickle data that crossed a trust boundary.",
   effort="S", cwe=["CWE-502"], owasp_mcp=[MCP05])
_r(id="SEC-005", title="Unrestricted file system path", dimension=D.security, severity=S.high,
   description="A file is opened, written or deleted using a path derived from tool input without canonicalisation and a base-directory check.",
   impact="Path traversal: an agent can read secrets (~/.ssh, .env, /etc), overwrite code or configuration, or delete data outside the intended workspace.",
   remediation="Resolve the path (Path.resolve / fs.realpath), then verify it is inside an allowed root (is_relative_to / startsWith(root + sep)); reject symlinks escaping the root; expose roots explicitly.",
   effort="S", cwe=["CWE-22"], owasp_mcp=[MCP02, MCP10], owasp_llm=[LLM06], tags=["filesystem"])
_r(id="SEC-006", title="Server-side request forgery (SSRF)", dimension=D.security, severity=S.high,
   description="An outbound HTTP request is made to a URL derived from tool input without an allow-list.",
   impact="Agents can be steered to internal endpoints (cloud metadata 169.254.169.254, admin consoles, internal APIs), bypassing network segmentation.",
   remediation="Allow-list destination hosts/schemes, resolve and block private/link-local ranges, disable redirects to non-allowed hosts, and route egress through a proxy.",
   effort="M", cwe=["CWE-918"], owasp_mcp=[MCP02], mcp_spec=["Security Best Practices"], refs=[("MCP Security Best Practices", SPEC_SEC)])
_r(id="SEC-007", title="Hard-coded secret or credential", dimension=D.security, severity=S.critical,
   description="A credential (API key, token, private key, password, connection string) is committed in source.",
   impact="Anyone with read access to the repository (or to the built image) obtains the credential; rotation becomes mandatory once leaked.",
   remediation="Remove the secret, rotate it, and load it at runtime from a secret manager (Vault, Azure Key Vault, AWS Secrets Manager) or environment injected by the platform. Add a pre-commit secret scanner.",
   effort="S", cwe=["CWE-798"], owasp_mcp=[MCP01], owasp_llm=[LLM02], tags=["secrets"])
_r(id="SEC-008", title="TLS certificate verification disabled", dimension=D.security, severity=S.high,
   description="verify=False, rejectUnauthorized:false, NODE_TLS_REJECT_UNAUTHORIZED=0, InsecureSkipVerify or an unverified SSL context.",
   impact="Man-in-the-middle interception of tokens and data between the MCP server and its downstream systems.",
   remediation="Keep verification on; for an internal PKI, point the client at the corporate CA bundle (REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS).",
   effort="S", cwe=["CWE-295"], owasp_mcp=[MCP01])
_r(id="SEC-009", title="Weak cryptographic algorithm", dimension=D.security, severity=S.medium,
   description="MD5, SHA-1, DES/3DES, RC4 or ECB mode is used.",
   impact="Collisions or brute-force break integrity/confidentiality guarantees if used for signatures, tokens or passwords.",
   remediation="Use SHA-256+, HMAC for integrity, AES-GCM for encryption and argon2/bcrypt/scrypt for passwords. If the hash is non-security (cache key), mark it usedforsecurity=False.",
   effort="S", cwe=["CWE-327"])
_r(id="SEC-010", title="Non-cryptographic randomness for secrets", dimension=D.security, severity=S.medium,
   description="random.* / Math.random() is used to generate tokens, session IDs, passwords or nonces.",
   impact="Predictable identifiers enable session hijacking and token guessing.",
   remediation="Use secrets.token_urlsafe / crypto.randomUUID / crypto.randomBytes.",
   effort="S", cwe=["CWE-338"], mcp_spec=["Security Best Practices: Session Hijacking"], refs=[("MCP Security Best Practices", SPEC_SEC)])
_r(id="SEC-011", title="Permissive CORS policy", dimension=D.security, severity=S.medium,
   description="CORS allows any origin ('*'), possibly together with credentials.",
   impact="Any web page visited by a user can drive the MCP endpoint from the browser (cross-site requests, DNS-rebinding style attacks on local servers).",
   remediation="Restrict allowed origins to the known agent/front-end hosts; never combine '*' with credentials.",
   effort="S", cwe=["CWE-942"], owasp_mcp=[MCP07])
_r(id="SEC-012", title="Server binds to all network interfaces", dimension=D.security, severity=S.medium,
   description="The HTTP server listens on 0.0.0.0 / :: .",
   impact="The endpoint is reachable from the whole network; combined with weak or missing auth it is directly exploitable. The MCP specification asks local servers to bind to localhost only.",
   remediation="Bind to 127.0.0.1 for local use; for shared deployments expose it only behind an authenticating gateway / ingress with network policies.",
   effort="S", cwe=["CWE-1327"], mcp_spec=["Transports: Security Warning"], refs=[("MCP Transports", SPEC_TRANSPORT)])
_r(id="SEC-013", title="Debug mode enabled", dimension=D.security, severity=S.medium,
   description="A framework debug flag is turned on in code (debug=True, app.run(debug=True)...).",
   impact="Stack traces, internals and sometimes interactive consoles are exposed to callers.",
   remediation="Drive debug from configuration and keep it off by default in production builds.",
   effort="S", cwe=["CWE-489"])
_r(id="SEC-014", title="XML parsing vulnerable to XXE", dimension=D.security, severity=S.medium,
   description="Standard-library XML parsers process untrusted XML.",
   impact="External entity expansion can read local files, perform SSRF or exhaust memory (billion laughs).",
   remediation="Use defusedxml (Python) or disable DTD/entity resolution on the parser.",
   effort="S", cwe=["CWE-611"])
_r(id="SEC-015", title="JWT signature or claims not verified", dimension=D.security, severity=S.high,
   description="Tokens are decoded without signature verification, accept the 'none' algorithm, or skip audience validation.",
   impact="Forged or replayed tokens grant access; tokens minted for another service are accepted (confused deputy).",
   remediation="Verify signature with a pinned algorithm list, and validate iss, aud (this MCP server's resource identifier) and exp on every request.",
   effort="S", cwe=["CWE-347"], owasp_mcp=[MCP07, MCP01], mcp_spec=["Authorization: Token Audience Binding"], refs=[("MCP Authorization", SPEC_AUTH)])
_r(id="SEC-016", title="Secrets or tokens written to logs", dimension=D.security, severity=S.medium,
   description="A log/print statement includes a variable named like a password, token, secret, API key or authorization header.",
   impact="Credentials leak into log aggregation, tickets and backups where access controls are much weaker.",
   remediation="Never log credentials; add a redaction filter to the logger and log token fingerprints at most.",
   effort="S", cwe=["CWE-532"], owasp_mcp=[MCP01], owasp_llm=[LLM02])
_r(id="SEC-017", title="Server-side template injection", dimension=D.security, severity=S.high,
   description="A template is compiled from a non-constant string (jinja2 Template(var), render_template_string).",
   impact="Template injection commonly escalates to remote code execution.",
   remediation="Load templates from files and pass untrusted values only as context variables; use a SandboxedEnvironment if templates must be dynamic.",
   effort="S", cwe=["CWE-1336"], owasp_mcp=[MCP05])
_r(id="SEC-018", title="Internal error details returned to the caller", dimension=D.security, severity=S.low,
   description="Exception text or tracebacks are returned inside tool results.",
   impact="Leaks stack traces, file paths, SQL and connection details to the model, the conversation transcript and potentially end users.",
   remediation="Return a stable, actionable error message with isError=true; log the full exception server-side with a correlation id.",
   effort="S", cwe=["CWE-209"], owasp_llm=[LLM02])
_r(id="SEC-019", title="Untrusted external content returned to the model verbatim", dimension=D.security, severity=S.medium,
   description="A tool fetches external content (web pages, e-mails, documents, tickets) and returns it raw to the model.",
   impact="Indirect prompt injection: instructions hidden in the fetched content are executed by the agent with all of its other tools.",
   remediation="Strip or neutralise active content, wrap external data in clearly delimited, labelled blocks, cap its size, and keep high-privilege tools behind human confirmation when untrusted content is in context.",
   effort="M", cwe=["CWE-1427"], owasp_mcp=[MCP06], owasp_llm=[LLM01])
_r(id="SEC-020", title="Unsafe archive extraction", dimension=D.security, severity=S.medium,
   description="zipfile/tarfile extractall (or equivalent) without member path validation.",
   impact="Zip-slip: crafted archives write files outside the target directory (overwrite code, cron jobs, keys).",
   remediation="Validate each member path against the destination root (tarfile filter='data' on Python 3.12+).",
   effort="S", cwe=["CWE-22"])
_r(id="SEC-021", title="Committed environment or key file", dimension=D.security, severity=S.high,
   description="A .env, private key, keystore or credentials file is present in the source tree.",
   impact="Credentials distributed with every clone, artefact and container image.",
   remediation="Delete the file from the repository and history, rotate the credentials, and add the pattern to .gitignore/.dockerignore.",
   effort="S", cwe=["CWE-312"], owasp_mcp=[MCP01])
_r(id="SEC-022", title="Container runs as root", dimension=D.security, severity=S.medium,
   description="The Dockerfile never switches to a non-root USER.",
   impact="A compromise of the MCP process (e.g. via injection) yields root inside the container and eases container escape.",
   remediation="Create a dedicated unprivileged user and add USER before the entrypoint; drop capabilities and use a read-only root filesystem.",
   effort="S", cwe=["CWE-250"], owasp_mcp=[MCP02])
_r(id="SEC-023", title="Unpinned or mutable container base image", dimension=D.maintainability, severity=S.low,
   description="FROM uses ':latest' or no tag.",
   impact="Non-reproducible builds; a compromised or breaking upstream image flows straight to production.",
   remediation="Pin to a specific version tag, ideally by digest, and update it through a controlled dependency process.",
   effort="S", cwe=["CWE-1357"], owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="SEC-024", title="Remote script piped to a shell", dimension=D.security, severity=S.high,
   description="curl/wget output is piped into sh/bash in a build or install script.",
   impact="Supply-chain execution of whatever the remote host serves at build time.",
   remediation="Download pinned artefacts, verify checksums/signatures, then execute.",
   effort="S", cwe=["CWE-494"], owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="SEC-025", title="Dependency with a known vulnerability", dimension=D.security, severity=S.high,
   description="A dependency version is affected by a published advisory (reported by an external scanner).",
   impact="Known, often weaponised, vulnerabilities reachable through the MCP server.",
   remediation="Upgrade to a fixed version; if not possible, document compensating controls and track the exception.",
   effort="S", owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="SEC-026", title="Dependency fetched from an unvetted source", dimension=D.security, severity=S.medium,
   description="A dependency is installed from a git URL, tarball URL or local path instead of the approved registry.",
   impact="Bypasses the organisation's artefact repository, vulnerability scanning and provenance controls.",
   remediation="Publish the package to the internal registry (Artifactory/Nexus) and depend on a pinned version.",
   effort="S", owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="SEC-027", title="Install-time lifecycle script", dimension=D.security, severity=S.low,
   description="package.json declares preinstall/install/postinstall scripts.",
   impact="Code runs on every developer workstation and CI agent at install time; a common supply-chain attack vector.",
   remediation="Avoid lifecycle scripts or make them auditable; install with --ignore-scripts in CI where possible.",
   effort="S", owasp_mcp=[MCP04])

# ---------------------------------------------------------------- MCP-specific
_r(id="MCP-001", title="Remote MCP transport without authentication", dimension=D.security, severity=S.critical,
   description="The server exposes an HTTP/SSE transport but no authentication or authorization mechanism was found.",
   impact="Anyone who can reach the endpoint can enumerate and invoke every tool — with the server's own credentials to downstream systems.",
   remediation="Implement OAuth 2.1 resource-server validation as defined by the MCP Authorization specification (or enforce authentication at a gateway): validate bearer tokens, audience-bind them to this server, apply per-tool scopes.",
   effort="L", cwe=["CWE-306"], owasp_mcp=[MCP07], mcp_spec=["Authorization"], refs=[("MCP Authorization", SPEC_AUTH)])
_r(id="MCP-002", title="Token passthrough to downstream services", dimension=D.security, severity=S.high,
   description="The incoming client Authorization header/token is forwarded as-is to downstream APIs.",
   impact="Explicitly forbidden by the MCP specification: breaks audience binding, audit trails and rate limits, and turns the server into a confused deputy.",
   remediation="Validate the token issued for this MCP server, then obtain a separate downstream token (token exchange / on-behalf-of / service credentials) with minimal scopes.",
   effort="M", cwe=["CWE-441"], owasp_mcp=[MCP01, MCP07], mcp_spec=["Security Best Practices: Token Passthrough"], refs=[("MCP Security Best Practices", SPEC_SEC)])
_r(id="MCP-003", title="Tool poisoning: hidden instructions in tool metadata", dimension=D.security, severity=S.critical,
   description="A tool, prompt or resource description contains instruction-like or hidden content (\"ignore previous instructions\", <IMPORTANT> blocks, invisible Unicode, requests to read secrets or not to tell the user).",
   impact="Descriptions are injected into every agent's context: they can silently redirect the agent, exfiltrate data through other tools or shadow trusted tools.",
   remediation="Descriptions must be plain, factual documentation of the tool. Remove imperative instructions aimed at the model, strip invisible characters, and review metadata changes like code (pin and diff tool definitions).",
   effort="S", cwe=["CWE-1427"], owasp_mcp=[MCP03], owasp_llm=[LLM01])
_r(id="MCP-004", title="No Origin / Host validation on HTTP transport (DNS rebinding)", dimension=D.security, severity=S.medium,
   description="A Streamable HTTP / SSE transport is exposed without Origin or Host header validation.",
   impact="The MCP specification requires servers to validate Origin: without it, a malicious web page can reach a locally running server via DNS rebinding.",
   remediation="Enable DNS-rebinding protection (TS SDK: enableDnsRebindingProtection + allowedHosts/allowedOrigins; Python SDK: TransportSecuritySettings) or validate Origin in middleware.",
   effort="S", cwe=["CWE-350"], owasp_mcp=[MCP07], mcp_spec=["Transports: Security Warning"], refs=[("MCP Transports", SPEC_TRANSPORT)])
_r(id="MCP-005", title="Deprecated HTTP+SSE transport", dimension=D.maintainability, severity=S.low,
   description="The legacy HTTP+SSE transport (protocol 2024-11-05) is used.",
   impact="Superseded by Streamable HTTP since the 2025-03-26 revision; clients are dropping it and it complicates load balancing (long-lived connections).",
   remediation="Migrate to the Streamable HTTP transport (keep SSE only as a temporary compatibility endpoint).",
   effort="M", mcp_spec=["Transports"], refs=[("MCP Transports", SPEC_TRANSPORT)])
_r(id="MCP-006", title="State-changing tool without behaviour annotations", dimension=D.security, severity=S.medium,
   description="A tool that writes, deletes, executes or sends does not declare readOnlyHint/destructiveHint/idempotentHint annotations.",
   impact="Clients cannot distinguish it from a harmless read: they will auto-approve, retry or cache it. Human-in-the-loop confirmation recommended by the specification is not triggered.",
   remediation="Declare ToolAnnotations (readOnlyHint=false, destructiveHint, idempotentHint, openWorldHint) for every tool; require explicit confirmation for destructive operations.",
   effort="S", owasp_mcp=[MCP02], owasp_llm=[LLM06], mcp_spec=["Tools: Annotations"], refs=[("MCP Tools", SPEC_TOOLS)])
_r(id="MCP-007", title="Missing or weak tool description", dimension=D.performance, severity=S.low,
   description="A tool has no description or one too short to tell an agent when and how to use it.",
   impact="Agents pick the wrong tool, retry, or hallucinate arguments: more calls, more tokens, more latency, more errors.",
   remediation="Describe purpose, when to use it, argument semantics, return shape and limits in 1–4 sentences; document every parameter.",
   effort="S", mcp_spec=["Tools"], refs=[("MCP Tools", SPEC_TOOLS)])
_r(id="MCP-008", title="Unconstrained input reaches a sensitive operation", dimension=D.security, severity=S.medium,
   description="A free-form string parameter flows into a shell, SQL, file system or network operation without schema constraints (enum, pattern, max length) or validation.",
   impact="The model (or an injected prompt) controls the full value sent to a sensitive sink.",
   remediation="Constrain parameters in the input schema (Literal/Enum, regex pattern, maxLength, ranges) and validate server-side before use.",
   effort="S", cwe=["CWE-20"], owasp_mcp=[MCP05], owasp_llm=[LLM06])
_r(id="MCP-009", title="Too many tools exposed by one server", dimension=D.performance, severity=S.low,
   description="The server exposes a large number of tools.",
   impact="Every tool definition is loaded into the agent context: higher token cost per turn, slower responses and measurably worse tool selection.",
   remediation="Split the server by domain, merge overlapping tools, or expose a smaller default tool set.",
   effort="M", owasp_llm=[LLM10])
_r(id="MCP-010", title="Unbounded tool output", dimension=D.performance, severity=S.medium,
   description="A tool returns a full result set / file / API payload without a limit, pagination or truncation.",
   impact="Context-window overflow, high token cost, slow agents and memory pressure on the server under concurrency.",
   remediation="Enforce a default and maximum page size, return a cursor (MCP pagination) and a 'truncated' flag, and summarise large payloads server-side.",
   effort="S", owasp_llm=[LLM10], mcp_spec=["Utilities: Pagination"])
_r(id="MCP-011", title="Tool name not compliant or duplicated", dimension=D.maintainability, severity=S.low,
   description="A tool name is duplicated or uses characters outside [A-Za-z0-9_.-] / exceeds 128 characters.",
   impact="Clients may reject or silently shadow tools; duplicates make behaviour depend on registration order.",
   remediation="Use unique, stable snake_case names with a domain prefix.",
   effort="S", mcp_spec=["Tools"])
_r(id="MCP-012", title="Predictable session identifier", dimension=D.security, severity=S.high,
   description="The Streamable HTTP session ID generator uses a counter, timestamp or Math.random.",
   impact="Session hijacking: the specification requires secure, non-deterministic session IDs.",
   remediation="Use crypto.randomUUID()/secrets.token_urlsafe and bind sessions to the authenticated principal.",
   effort="S", cwe=["CWE-330"], owasp_mcp=[MCP07], mcp_spec=["Security Best Practices: Session Hijacking"], refs=[("MCP Security Best Practices", SPEC_SEC)])
_r(id="MCP-013", title="Tool grants arbitrary execution capability", dimension=D.security, severity=S.high,
   description="A tool is designed to run arbitrary shell commands, code or raw SQL supplied by the model.",
   impact="Excessive agency: the tool is a general-purpose remote execution primitive for any agent — and any prompt injection reaching that agent.",
   remediation="Replace with narrow, purpose-built tools; if unavoidable, sandbox (container/VM, no network, read-only FS), allow-list commands, require human approval and log every call.",
   effort="L", cwe=["CWE-250"], owasp_mcp=[MCP02, MCP05], owasp_llm=[LLM06])
_r(id="MCP-014", title="Outdated MCP SDK version", dimension=D.security, severity=S.medium,
   description="The MCP SDK version pinned by the project is older than the minimum recommended version.",
   impact="Older SDK releases are affected by published security advisories and lack current protocol features (Streamable HTTP, structured output, auth helpers).",
   remediation="Upgrade the MCP SDK to a current release and re-run the protocol tests.",
   effort="S", owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="MCP-015", title="Token audience not validated", dimension=D.security, severity=S.medium,
   description="Bearer tokens are verified without checking the audience/resource claim.",
   impact="Tokens issued for other services are accepted by this MCP server (token reuse / confused deputy).",
   remediation="Validate the 'aud' claim against this server's canonical resource URI (RFC 8707), as required by the MCP Authorization spec.",
   effort="S", cwe=["CWE-287"], owasp_mcp=[MCP07], mcp_spec=["Authorization: Token Audience Binding"], refs=[("MCP Authorization", SPEC_AUTH)])
_r(id="MCP-016", title="No MCP server detected", dimension=D.maintainability, severity=S.info,
   description="No known MCP SDK usage or tool registration pattern was found in the analysed sources.",
   impact="MCP-specific checks could not be applied; scores rely on generic code checks only.",
   remediation="Check that the right folder was analysed. Custom/unsupported frameworks can be covered with custom rules.",
   effort="S")

# ---------------------------------------------------------------- scalability
_r(id="SCL-001", title="stdio-only transport", dimension=D.scalability, severity=S.medium,
   description="The server only supports the stdio transport.",
   impact="Each client spawns its own server process on its own machine: it cannot be operated as a shared service, centrally secured, monitored or scaled horizontally for many users/agents.",
   remediation="Add the Streamable HTTP transport (stateless mode where possible) behind an authenticating gateway for shared use.",
   effort="M", mcp_spec=["Transports"], refs=[("MCP Transports", SPEC_TRANSPORT)])
_r(id="SCL-002", title="In-memory session state prevents horizontal scaling", dimension=D.scalability, severity=S.medium,
   description="Streamable HTTP sessions/transports are kept in a process-local map (stateful mode).",
   impact="Requests of a session must reach the same replica (sticky sessions); a restart or scale-in drops every session.",
   remediation="Prefer stateless HTTP mode (stateless_http=True / sessionIdGenerator: undefined); if state is required, externalise it (Redis) and configure session affinity explicitly.",
   effort="M", mcp_spec=["Transports: Session Management"])
_r(id="SCL-003", title="Process-local mutable state", dimension=D.scalability, severity=S.low,
   description="A module-level dict/list/set is mutated by request handlers (in-process cache, registry or counters).",
   impact="Inconsistent behaviour across replicas, unbounded memory growth and race conditions under concurrent agents.",
   remediation="Bound caches (TTL/LRU), or move shared state to an external store; guard concurrent mutation.",
   effort="M", cwe=["CWE-362"])
_r(id="SCL-004", title="Blocking call inside async handler", dimension=D.scalability, severity=S.high,
   description="A synchronous network, sleep, subprocess or database call is made inside an async function.",
   impact="The call freezes the event loop: every concurrent request on that worker stalls. Throughput collapses to one request at a time under load.",
   remediation="Use async clients (httpx.AsyncClient, asyncpg, aiofiles, asyncio.sleep, asyncio.create_subprocess_exec) or offload with asyncio.to_thread / run_in_executor.",
   effort="M", cwe=["CWE-400"], owasp_llm=[LLM10])
_r(id="SCL-005", title="Connection or client created per call", dimension=D.scalability, severity=S.medium,
   description="A database connection or HTTP client is created inside a function that runs per request.",
   impact="Connection setup (TCP+TLS+auth) on every tool call: high latency, exhausted database connection slots and ephemeral ports under concurrency.",
   remediation="Create pooled clients once at startup (lifespan) and reuse them; size the pool to the expected concurrency.",
   effort="M")
_r(id="SCL-006", title="No rate limiting or quota", dimension=D.scalability, severity=S.medium,
   description="No rate limiting, throttling or per-client quota mechanism was found for the remote transport.",
   impact="A single runaway agent loop can saturate the server and its downstream systems (denial of wallet/service for everyone else).",
   remediation="Apply per-principal rate limits and concurrency caps (gateway or middleware), and budgets on expensive tools.",
   effort="M", cwe=["CWE-770"], owasp_llm=[LLM10])
_r(id="SCL-007", title="Unbounded concurrent fan-out", dimension=D.scalability, severity=S.low,
   description="asyncio.gather / Promise.all is applied to a dynamically sized collection without a concurrency limit.",
   impact="Bursts of thousands of concurrent downstream calls, exhausting pools and triggering upstream throttling.",
   remediation="Bound concurrency with a semaphore / p-limit and batch large inputs.",
   effort="S", cwe=["CWE-770"])
_r(id="SCL-008", title="Local file system used as state store", dimension=D.scalability, severity=S.low,
   description="Application state (SQLite, JSON, pickle files) is written to the local disk.",
   impact="Replicas do not share state and containers lose it on restart.",
   remediation="Use a managed database/object store for shared state, or document the single-instance constraint.",
   effort="M")
_r(id="SCL-009", title="No health or readiness endpoint", dimension=D.reliability, severity=S.low,
   description="No /health, /healthz or /ready endpoint was found for the HTTP server.",
   impact="Orchestrators cannot detect hung instances or route traffic only to ready replicas.",
   remediation="Expose liveness and readiness endpoints (readiness should check downstream dependencies).",
   effort="S")
_r(id="SCL-010", title="No deployment packaging", dimension=D.scalability, severity=S.low,
   description="No Dockerfile, Helm chart or deployment manifest was found.",
   impact="Deployment is manual and not reproducible; horizontal scaling and rollback are harder to industrialise.",
   remediation="Provide a minimal, non-root container image and deployment manifests with resource limits.",
   effort="M")

# ---------------------------------------------------------------- performance
_r(id="PRF-001", title="Network or database call inside a loop (N+1)", dimension=D.performance, severity=S.medium,
   description="A loop body performs an HTTP request or database query on each iteration.",
   impact="Latency grows linearly with input size; downstream systems receive N small calls instead of one batched call.",
   remediation="Batch the operation (IN clause, bulk endpoint), or parallelise with bounded concurrency.",
   effort="M")
_r(id="PRF-002", title="Full result set or file loaded in memory", dimension=D.performance, severity=S.low,
   description="fetchall(), read() of whole files or similar loads data without bounds.",
   impact="Memory spikes proportional to data size multiplied by concurrent calls; risk of OOM kills.",
   remediation="Stream or page through results (fetchmany, LIMIT/OFFSET or keyset pagination, chunked reads).",
   effort="S", owasp_llm=[LLM10])
_r(id="PRF-003", title="Pretty-printed JSON returned to the model", dimension=D.performance, severity=S.info,
   description="Tool results are serialised with indentation.",
   impact="Indentation and whitespace typically add 15–30 % tokens to every tool result.",
   remediation="Return compact JSON (separators=(',', ':')) or MCP structured content.",
   effort="S", owasp_llm=[LLM10])
_r(id="PRF-004", title="Synchronous sleep in request path", dimension=D.performance, severity=S.low,
   description="time.sleep / Thread.sleep / busy waiting is used in a code path executed per request.",
   impact="Ties up a worker for the whole wait: concurrency capacity drops proportionally.",
   remediation="Use async waits, event notifications or background jobs with progress notifications.",
   effort="S")
_r(id="PRF-005", title="Regular expression compiled inside a loop", dimension=D.performance, severity=S.info,
   description="re.compile / new RegExp is executed inside a loop.",
   impact="Repeated compilation cost on hot paths.",
   remediation="Compile once at module level.",
   effort="S")

# ---------------------------------------------------------------- reliability
_r(id="REL-001", title="Outbound call without timeout", dimension=D.reliability, severity=S.medium,
   description="An HTTP or socket call is made without an explicit timeout (requests, urllib, fetch, axios...).",
   impact="A slow downstream hangs the tool call indefinitely, pinning workers and connections until the server stops responding to everyone.",
   remediation="Set connect/read timeouts on every client (and an overall deadline per tool call); surface timeouts as isError results.",
   effort="S", cwe=["CWE-400"])
_r(id="REL-002", title="Exception silently swallowed", dimension=D.reliability, severity=S.low,
   description="An except/catch block ignores the error (pass, empty block) or catches everything without re-raising or logging.",
   impact="Failures disappear: the agent receives empty or partial data as if it were a success, and operators have nothing to investigate.",
   remediation="Catch specific exceptions, log them with context, and return an explicit error (isError=true) to the client.",
   effort="S", cwe=["CWE-390"])
_r(id="REL-003", title="No retry/backoff strategy for downstream calls", dimension=D.reliability, severity=S.low,
   description="The server calls network services but no retry/backoff library or pattern was found.",
   impact="Transient network or throttling errors bubble up as tool failures and trigger costly agent-level retries.",
   remediation="Retry idempotent calls with exponential backoff and jitter (tenacity, backoff, p-retry), honour Retry-After, add circuit breakers for unstable dependencies.",
   effort="S")
_r(id="REL-004", title="Process exit inside library or handler code", dimension=D.reliability, severity=S.medium,
   description="sys.exit / os._exit / process.exit is called outside the entry point.",
   impact="One bad request terminates the whole server for every connected client.",
   remediation="Raise/return an error instead; only the entry point should decide to exit.",
   effort="S", cwe=["CWE-705"])
_r(id="REL-005", title="stdout written by a stdio server", dimension=D.reliability, severity=S.high,
   description="print()/console.log() writes to stdout in a server using the stdio transport.",
   impact="stdout carries the JSON-RPC stream: any stray output corrupts the protocol and breaks the client connection (intermittently, depending on the code path).",
   remediation="Log to stderr (logging to sys.stderr / console.error) or to a file; never print to stdout in a stdio server.",
   effort="S", mcp_spec=["Transports: stdio"], refs=[("MCP Transports", SPEC_TRANSPORT)])
_r(id="REL-006", title="Untyped tool parameters", dimension=D.reliability, severity=S.low,
   description="Tool handlers accept parameters without type information or schema (Any, dict, untyped).",
   impact="The published inputSchema is permissive: agents send malformed arguments that fail deep inside the handler instead of being rejected with a clear validation error.",
   remediation="Type every parameter (Pydantic/Annotated Field, zod schemas) with descriptions, ranges and enums.",
   effort="S", cwe=["CWE-20"])
_r(id="REL-007", title="No graceful shutdown", dimension=D.reliability, severity=S.info,
   description="The HTTP server has no lifespan/shutdown hook to drain requests and close pools.",
   impact="Rolling deployments drop in-flight tool calls and leak downstream connections.",
   remediation="Use framework lifespan hooks / SIGTERM handlers to stop accepting work, drain, then close clients.",
   effort="S")

# ---------------------------------------------------------------- observability
_r(id="OBS-001", title="No structured logging", dimension=D.observability, severity=S.medium,
   description="The project does not configure a logging framework (only print/console or nothing).",
   impact="Incidents cannot be investigated; no correlation between agent sessions and server behaviour.",
   remediation="Configure structured (JSON) logging with level, timestamp, request/session id and tool name; ship logs to the central platform.",
   effort="S", owasp_mcp=[MCP08])
_r(id="OBS-002", title="No audit trail of tool invocations", dimension=D.observability, severity=S.medium,
   description="Tool handlers do not log who invoked which tool with which (redacted) arguments and outcome.",
   impact="No accountability for agent actions; impossible to answer 'which agent deleted this record?' or to detect abuse.",
   remediation="Emit one audit event per tool call: principal, client, tool, argument digest, result status, duration. Protect the audit log from tampering.",
   effort="M", owasp_mcp=[MCP08])
_r(id="OBS-003", title="No metrics or tracing", dimension=D.observability, severity=S.low,
   description="No metrics (Prometheus/StatsD) or distributed tracing (OpenTelemetry) instrumentation was found.",
   impact="No visibility on latency, error rate or saturation: capacity problems are found by users first.",
   remediation="Instrument with OpenTelemetry (traces + metrics per tool: count, latency, errors) and define SLOs.",
   effort="M", owasp_mcp=[MCP08])

# ---------------------------------------------------------------- maintainability / sustainability
_r(id="MNT-001", title="No automated tests", dimension=D.maintainability, severity=S.high,
   description="No test files were found.",
   impact="Every change is a production experiment; upgrades of the SDK or dependencies cannot be done safely, so the server will rot.",
   remediation="Add unit tests per tool (happy path, validation errors, permission denials) and a protocol-level test using the SDK's in-memory client.",
   effort="L")
_r(id="MNT-002", title="Low test coverage indicator", dimension=D.maintainability, severity=S.medium,
   description="Test code is small relative to production code.",
   impact="Large parts of the behaviour are unverified; regressions are likely as the server evolves.",
   remediation="Raise test coverage on tool handlers and security controls first; track coverage in CI.",
   effort="M")
_r(id="MNT-003", title="No continuous integration pipeline", dimension=D.maintainability, severity=S.medium,
   description="No CI configuration (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines...) was found.",
   impact="Tests, linters and security scans are not enforced; quality depends on individual discipline.",
   remediation="Add a CI pipeline running lint, type-check, tests, dependency and secret scanning on every merge request.",
   effort="M")
_r(id="MNT-004", title="Dependencies not locked", dimension=D.maintainability, severity=S.medium,
   description="No lockfile was found and/or dependency versions are unpinned.",
   impact="Non-reproducible builds: a new transitive release (or a malicious one) changes production behaviour without any code change.",
   remediation="Commit a lockfile (uv.lock / poetry.lock / requirements with hashes / package-lock.json) and update it through reviewed PRs (Renovate/Dependabot).",
   effort="S", owasp_mcp=[MCP04], owasp_llm=[LLM03])
_r(id="MNT-005", title="High cyclomatic complexity", dimension=D.maintainability, severity=S.medium,
   description="A function exceeds the cyclomatic complexity threshold.",
   impact="Hard to test and reason about; defect probability rises sharply with complexity.",
   remediation="Split into smaller functions, use early returns and table-driven logic; cover with tests before refactoring.",
   effort="M")
_r(id="MNT-006", title="Missing README / operating documentation", dimension=D.maintainability, severity=S.medium,
   description="No README or documentation describing purpose, configuration, tools and operation was found.",
   impact="Onboarding, operations and security review depend on the original author (bus factor).",
   remediation="Document purpose, tool catalogue, configuration variables, required permissions, deployment and runbook.",
   effort="S")
_r(id="MNT-007", title="No lint / type-check configuration", dimension=D.maintainability, severity=S.low,
   description="No linter or static type-checker configuration was found (ruff, flake8, mypy, pyright, eslint, strict tsconfig).",
   impact="Style drift and type errors accumulate; refactoring becomes riskier over time.",
   remediation="Adopt ruff + mypy/pyright (Python) or eslint + strict TypeScript and enforce them in CI.",
   effort="S")
_r(id="MNT-008", title="Concentrated knowledge (bus factor)", dimension=D.maintainability, severity=S.medium,
   description="Almost all commits come from a single contributor.",
   impact="Maintenance depends on one person: vacations, departures or reassignments stall security fixes.",
   remediation="Assign a second maintainer, require reviews, and document the design decisions.",
   effort="M")
_r(id="MNT-009", title="Stale repository", dimension=D.maintainability, severity=S.low,
   description="No commit in a long period.",
   impact="Dependencies and SDK drift behind security releases; the protocol evolves faster than the code.",
   remediation="Define an owner and a maintenance cadence (monthly dependency updates).",
   effort="S")
_r(id="MNT-010", title="End-of-life runtime", dimension=D.maintainability, severity=S.medium,
   description="The project targets a Python or Node.js version that no longer receives security updates.",
   impact="Unpatched interpreter vulnerabilities; modern SDKs drop support.",
   remediation="Move to a supported LTS runtime (Python ≥ 3.10, Node.js ≥ 20).",
   effort="M")
_r(id="MNT-011", title="High density of TODO/FIXME markers", dimension=D.maintainability, severity=S.info,
   description="Many TODO/FIXME/HACK/XXX markers were found.",
   impact="Signals unfinished work and known shortcuts.",
   remediation="Triage markers into the backlog and remove or resolve them before production.",
   effort="S")
_r(id="MNT-012", title="Very large source file", dimension=D.maintainability, severity=S.low,
   description="A source file exceeds 1,000 lines of code.",
   impact="Low cohesion, merge conflicts and difficult reviews.",
   remediation="Split by responsibility (tools by domain, transport/config separated from business logic).",
   effort="M")
_r(id="MNT-013", title="Hard-coded environment endpoint", dimension=D.maintainability, severity=S.low,
   description="A hostname, IP address or URL of an environment is hard-coded in source.",
   impact="Promoting between environments requires code changes; risk of production calling test systems (or the reverse).",
   remediation="Read endpoints from configuration/environment with validation at startup.",
   effort="S")

SEVERITY_WEIGHT = {
    Severity.critical: 30.0,
    Severity.high: 14.0,
    Severity.medium: 5.0,
    Severity.low: 1.5,
    Severity.info: 0.0,
}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
