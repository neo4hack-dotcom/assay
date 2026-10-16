"""Find the MCP surface: which SDK, which transports, which auth, which tools.

Python is parsed with the stdlib `ast` (precise). TypeScript/JavaScript, Go,
Java and C# use targeted regexes plus a string/comment-aware bracket matcher to
find each tool's handler span. The spans are what make later findings say
"this SQL injection is reachable from tool `run_query`".
"""
from __future__ import annotations

import ast
import re

from .context import Ctx, ToolSpan
from .models import McpTool, Severity, ToolParam
from .workspace import SourceFile

# --------------------------------------------------------------------------- capabilities
CAP_PATTERNS: dict[str, re.Pattern] = {
    "exec": re.compile(r"\b(subprocess\.|os\.system|os\.popen|os\.exec|os\.spawn|create_subprocess_|child_process|execSync|execFile|spawn\(|spawnSync|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\.Command|Process\.Start|shelljs|execa\(|eval\(|exec\(|new Function\()"),
    "fs_write": re.compile(r"(open\([^)]*['\"][wax]b?\+?['\"]|\.write_text\(|\.write_bytes\(|writeFile|appendFile|createWriteStream|\bunlink|rmtree|os\.remove|os\.rmdir|fs\.rm|\.rmSync|shutil\.(move|copy|rmtree)|os\.rename|\.mkdir\(|os\.makedirs|File\.Delete|os\.Remove|ioutil\.WriteFile|os\.WriteFile)"),
    "fs_read": re.compile(r"(\bopen\(|\.read_text\(|\.read_bytes\(|readFile|createReadStream|os\.listdir|os\.walk|\.iterdir\(|glob\(|scandir|readdir|os\.ReadFile|File\.Read)"),
    "network": re.compile(r"(\brequests\.|httpx\.|aiohttp|urllib\.request|urlopen|\bfetch\(|axios|got\(|http\.request|https\.request|HttpClient|http\.Get|http\.Post|WebClient|RestTemplate|\.get\(\s*url|client\.(get|post|put|patch|delete|request)\()"),
    "db": re.compile(r"(\.execute\(|\.executemany\(|cursor\(|\.query\(|\.fetchall\(|sqlalchemy|session\.(add|delete|commit|query)|knex|prisma\.|\.findMany\(|\.find\(\{|mongo|\.aggregate\(|redis\.|\.QueryContext|\.ExecContext|db\.Query|db\.Exec|jdbcTemplate)"),
    "secrets": re.compile(r"(os\.environ|os\.getenv|process\.env|keyring|vault|SecretClient|secretsmanager)"),
    "send": re.compile(r"(smtplib|send_mail|sendmail|send_email|sendEmail|slack|webhook|twilio|chat\.postMessage|nodemailer|\.publish\()", re.I),
}
DESTRUCTIVE_NAME = re.compile(r"(^|[_\-.])(delete|remove|drop|destroy|purge|kill|truncate|wipe|reset|revoke|terminate|uninstall|erase|cancel)", re.I)
WRITE_NAME = re.compile(r"(^|[_\-.])(create|update|write|set|put|post|send|insert|upload|modify|edit|move|rename|deploy|exec|execute|run|approve|transfer|publish|merge|commit|push|grant|add|patch|save|apply|restart|stop|start)", re.I)
EXEC_PARAM = re.compile(r"^(cmd|command|commands|shell|script|code|expr|expression|program|bash|python|js|javascript|powershell)$", re.I)
SQL_PARAM = re.compile(r"^(sql|query|statement|stmt|sql_query|raw_sql|cypher|sparql|query_string)$", re.I)

PY_SDK_MODULES = ("mcp", "fastmcp")
PY_TOOL_DECOS = {"tool": "tool", "resource": "resource", "prompt": "prompt"}
PY_TRANSPORT_HINTS = {
    "stdio_server": "stdio", "run_stdio_async": "stdio", "StdioServerTransport": "stdio",
    "sse_app": "sse", "SseServerTransport": "sse", "run_sse_async": "sse",
    "streamable_http_app": "streamable-http", "http_app": "streamable-http", "StreamableHTTPSessionManager": "streamable-http",
    "run_streamable_http_async": "streamable-http", "run_http_async": "streamable-http",
}
TRANSPORT_WORDS = {
    "stdio": "stdio", "sse": "sse", "http": "streamable-http", "streamable-http": "streamable-http",
    "streamable_http": "streamable-http", "streamablehttp": "streamable-http", "httpstream": "streamable-http",
}
AUTH_PATTERNS = [
    ("OAuth / bearer token verification", re.compile(r"\b(AuthSettings|TokenVerifier|token_verifier|BearerAuthProvider|JWTVerifier|RemoteAuthProvider|OAuthProvider|OAuthProxy|auth_server_provider|requireBearerAuth|mcpAuthRouter|ProxyOAuthServerProvider|OAuthServerProvider|verifyAccessToken|WithAuthorization|oauth2|OAuth2PasswordBearer|AzureProvider|GoogleProvider|GitHubProvider|WorkOSProvider|Auth0Provider|KeycloakAuthProvider)\b")),
    ("JWT validation", re.compile(r"\b(jwt\.verify|jwt\.decode|jose\.jwt|jwtVerify|PyJWKClient|express-jwt|expressjwt|JwtBearer|AddJwtBearer|ValidateIssuer)\b")),
    ("HTTP bearer / API key check", re.compile(r"(HTTPBearer|APIKeyHeader|x-api-key|X-API-Key|api_key_header|['\"]authorization['\"]\s*\]|headers\.get\(\s*['\"]authorization|req\.headers\.authorization|request\.headers\[['\"]authorization|Authorization['\"]\]\s*!==?|Depends\(\s*verify_|verify_token|check_api_key|authenticate\s*:)", re.I)),
    ("Auth middleware / framework", re.compile(r"\b(passport\.authenticate|AuthenticationMiddleware|@login_required|RequireAuthorization|\[Authorize\]|spring-boot-starter-security|SecurityFilterChain|BasicAuth|basic_auth)\b")),
    ("mTLS", re.compile(r"(ssl_cert_reqs\s*=\s*ssl\.CERT_REQUIRED|requestCert\s*:\s*true|ClientAuth\s*:\s*tls\.RequireAndVerifyClientCert)")),
]
SIGNAL_PATTERNS = {
    "rate_limit": re.compile(r"(slowapi|ratelimit|rate_limit|RateLimit|rateLimit|express-rate-limit|limiter|throttl|Bottleneck|token[_ ]bucket|leaky[_ ]bucket)", re.I),
    "concurrency_limit": re.compile(r"(Semaphore|BoundedSemaphore|p-limit|pLimit|max_concurrency|concurrency_limit|limit_concurrency|CapacityLimiter)"),
    "cache": re.compile(r"(lru_cache|@cache\b|cachetools|TTLCache|aiocache|redis|memcache|node-cache|lru-cache|keyv|@cached)"),
    "retry": re.compile(r"(tenacity|\bbackoff\b|retrying|Retry\(|p-retry|axios-retry|async-retry|retry_on|max_retries|@retry)"),
    "timeouts": re.compile(r"(timeout\s*[=:]|Timeout\(|AbortSignal\.timeout|setTimeout\()"),
    "pooling": re.compile(r"(create_pool|ConnectionPool|SessionPool|pool_size|max_connections|Pool\(|createPool|poolSize|PoolOptions|limits=httpx\.Limits|connection_pool)"),
    "async_io": re.compile(r"(httpx\.AsyncClient|aiohttp|asyncpg|aiomysql|motor|aiofiles|aioredis|redis\.asyncio|oracledb\.connect_async|create_async_engine)"),
    "logging": re.compile(r"(import logging|logging\.getLogger|structlog|loguru|winston|pino|bunyan|log4js|log4j|slf4j|zap\.|logrus|slog\.|ILogger|Serilog)"),
    "structured_logging": re.compile(r"(structlog|python-json-logger|jsonlogger|JSONFormatter|pino|winston\.format\.json|zap\.NewProduction|slog\.NewJSONHandler|Serilog|ecs_logging|json_formatter)", re.I),
    "metrics_tracing": re.compile(r"(opentelemetry|prometheus|prom-client|statsd|datadog|ddtrace|newrelic|elastic-apm|micrometer|@opentelemetry|otel)", re.I),
    "audit_log": re.compile(r"(audit|AuditLog|audit_log|on_call_tool|ToolCallMiddleware|Middleware\)|class \w+\(Middleware\)|@mcp\.middleware)", re.I),
    "health": re.compile(r"""(['"]/(health|healthz|healthcheck|ready|readyz|livez|live|status)['"]|custom_route\(\s*['"]/health|health_check)"""),
    "graceful_shutdown": re.compile(r"(lifespan|on_shutdown|SIGTERM|signal\.signal|process\.on\(\s*['\"]SIG|graceful|shutdown\()", re.I),
    "input_validation": re.compile(r"(pydantic|Field\(|zod|z\.object|Joi\.|yup\.|ajv|jsonschema|@Valid|validator)"),
    "dns_rebinding": re.compile(r"(enableDnsRebindingProtection|allowedHosts|allowedOrigins|TransportSecuritySettings|allowed_hosts|allowed_origins|enable_dns_rebinding_protection|TrustedHostMiddleware|['\"]origin['\"]|req\.headers\.origin|headers\.get\(\s*['\"]origin)", re.I),
    "human_confirmation": re.compile(r"(elicit|confirm(ation)?_required|require_confirmation|human_in_the_loop|approval|ctx\.elicit|requestConfirmation)", re.I),
}


def classify(tool: McpTool, body: str) -> None:
    caps = [c for c, rx in CAP_PATTERNS.items() if rx.search(body)]
    if DESTRUCTIVE_NAME.search(tool.name):
        caps.append("destructive")
    tool.capabilities = sorted(set(caps))
    reasons: list[str] = []
    risk = Severity.low
    exec_param = any(EXEC_PARAM.match(p.name) and not p.constrained for p in tool.params)
    sql_param = any(SQL_PARAM.match(p.name) and not p.constrained for p in tool.params)
    if "exec" in caps:
        risk = Severity.critical if exec_param else Severity.high
        reasons.append("spawns processes or evaluates code")
    if "fs_write" in caps or "destructive" in caps:
        risk = max(risk, Severity.high, key=lambda s: -s.rank)
        reasons.append("modifies or deletes data/files")
    if sql_param and "db" in caps:
        risk = max(risk, Severity.high, key=lambda s: -s.rank)
        reasons.append("accepts raw query text from the model")
    if "send" in caps:
        risk = max(risk, Severity.high, key=lambda s: -s.rank)
        reasons.append("sends messages outside the system (exfiltration channel)")
    if "network" in caps:
        risk = max(risk, Severity.medium, key=lambda s: -s.rank)
        reasons.append("calls network services")
    if "db" in caps:
        risk = max(risk, Severity.medium, key=lambda s: -s.rank)
        reasons.append("accesses a database")
    if "fs_read" in caps:
        risk = max(risk, Severity.medium, key=lambda s: -s.rank)
        reasons.append("reads files")
    tool.risk = risk
    tool.risk_reasons = reasons


# --------------------------------------------------------------------------- python
def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _literal_dict(node: ast.AST | None) -> dict:
    out: dict = {}
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                out[str(k.value)] = v.value
    elif isinstance(node, ast.Call):            # ToolAnnotations(readOnlyHint=True, ...)
        for k in node.keywords:
            if k.arg and isinstance(k.value, ast.Constant):
                out[k.arg] = k.value.value
    return out


_ALIASES: dict[str, str] = {}
_DEFS_SRC: dict[str, str] = {}
CONSTRAINT_TOKENS = re.compile(r"(Literal\[|Enum|max_length|min_length|pattern|regex|\bge\s*=|\ble\s*=|\bgt\s*=|\blt\s*=|conint|constr|PositiveInt|UUID|HttpUrl|AnyUrl|EmailStr|IPv4Address|datetime|date\b)")


def _py_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ToolParam]:
    params: list[ToolParam] = []
    args = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    n_defaults = len(fn.args.defaults)
    pos = fn.args.posonlyargs + fn.args.args
    for _i, a in enumerate(args):
        if a.arg in ("self", "cls"):
            continue
        shown = ann = ast.unparse(a.annotation) if a.annotation else ""
        resolved = _ALIASES.get(ann.split("|")[0].strip(), "")
        if resolved:
            ann = f"{ann} = {resolved}"
        if re.search(r"\b(Context|FastMCP|Request)\b", ann) or a.arg in ("ctx", "context"):
            continue
        required = True
        if a in pos:
            idx = pos.index(a)
            required = idx < len(pos) - n_defaults
        else:
            kidx = fn.args.kwonlyargs.index(a)
            required = fn.args.kw_defaults[kidx] is None
        base = ann.split(" = ", 1)[-1]
        constrained = bool(CONSTRAINT_TOKENS.search(ann)) or bool(re.search(r"^(Annotated\[)?(int|float|bool|Optional\[(int|float|bool)\]|(int|float|bool) \| None)\b", base)) \
            or bool(re.fullmatch(r"(int|float|bool)(\s*\|\s*None)?", ann))
        desc = ""
        m = re.search(r"description\s*=\s*['\"]([^'\"]+)", ann)
        if m:
            desc = m.group(1)
        if len(shown) > 60:
            shown = re.sub(r",\s*Field\([\s\S]*\)\]$", "]", shown)[:60]
        params.append(ToolParam(name=a.arg, type=shown or "untyped", required=required, constrained=constrained, description=desc))
    return params


def py_imported_modules(tree: ast.AST) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            mods.add(node.module)
    return mods


def _py_aliases(tree: ast.Module) -> dict[str, str]:
    """Module-level type aliases: SqlArg = Annotated[str, Field(...)] -> source text."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            src = ast.unparse(node.value)
            if re.match(r"(Annotated|Literal|Optional|Union|typing\.)\[", src):
                out[node.targets[0].id] = src
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None \
                and "TypeAlias" in ast.unparse(node.annotation):
            out[node.target.id] = ast.unparse(node.value)
        elif hasattr(ast, "TypeAlias") and isinstance(node, ast.TypeAlias):
            out[node.name.id] = ast.unparse(node.value)
    return out


def discover_python(ctx: Ctx, sf: SourceFile) -> None:
    text = sf.text
    if not re.search(r"\b(mcp|fastmcp)\b", text):
        return
    try:
        tree = ast.parse(text, filename=sf.rel)
    except SyntaxError:
        return
    mods = py_imported_modules(tree)
    roots = {m.split(".")[0] for m in mods}
    if not roots & {"mcp", "fastmcp"}:
        return
    srv = ctx.server
    srv.detected = True
    if "python" not in srv.languages:
        srv.languages.append("python")
    if "fastmcp" in roots:
        _add(srv.sdks, "fastmcp (python)")
    if any(m.startswith("mcp.server.fastmcp") for m in mods):
        _add(srv.sdks, "mcp python SDK (FastMCP)")
    elif any(m.startswith("mcp.server.lowlevel") or m == "mcp.server" for m in mods):
        _add(srv.sdks, "mcp python SDK (low-level)")
    elif "mcp" in roots:
        _add(srv.sdks, "mcp python SDK")
    global _ALIASES, _DEFS_SRC
    _ALIASES = _py_aliases(tree)
    defs: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(node.name, node)
    _DEFS_SRC = {name: "\n".join(sf.lines[n.lineno - 1:(n.end_lineno or n.lineno)]) for name, n in defs.items()}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")
            if fname in ("FastMCP", "Server", "MCPServer"):
                name = _const_str(node.args[0]) if node.args else _const_str(_kw(node, "name"))
                if name:
                    _add(srv.names, name)
                _add(srv.entrypoints, f"{sf.rel}:{node.lineno}")
                st = _kw(node, "stateless_http")
                if isinstance(st, ast.Constant):
                    srv.stateless_http = bool(st.value)
                for authkw in ("auth", "token_verifier", "auth_server_provider"):
                    if _kw(node, authkw) is not None and not (isinstance(_kw(node, authkw), ast.Constant) and _kw(node, authkw).value is None):
                        srv.auth.detected = True
                        _add(srv.auth.mechanisms, "MCP SDK auth provider")
                        _add(srv.auth.evidence, f"{sf.rel}:{node.lineno} FastMCP({authkw}=...)")
            if fname in ("run", "run_async", "http_app", "streamable_http_app", "sse_app"):
                t = _const_str(_kw(node, "transport"))
                if t and t.lower() in TRANSPORT_WORDS:
                    _add(srv.transports, TRANSPORT_WORDS[t.lower()])
                elif fname == "run" and not node.args and _kw(node, "transport") is None and isinstance(node.func, ast.Attribute):
                    recv = ast.unparse(node.func.value)
                    if re.search(r"(mcp|server|app)$", recv, re.I) and "uvicorn" not in recv:
                        _add(srv.transports, "stdio")
                st = _kw(node, "stateless_http")
                if isinstance(st, ast.Constant):
                    srv.stateless_http = bool(st.value)
            if fname in PY_TRANSPORT_HINTS:
                _add(srv.transports, PY_TRANSPORT_HINTS[fname])
            # mcp.add_tool(fn, name=..., description=...)
            if fname == "add_tool" and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in defs:
                fn = defs[node.args[0].id]
                _py_tool(ctx, sf, fn, "tool", _const_str(_kw(node, "name")), _const_str(_kw(node, "description")), _literal_dict(_kw(node, "annotations")))
            # low-level: types.Tool(name=..., description=..., inputSchema=...)
            if fname == "Tool" and _const_str(_kw(node, "name")):
                _lowlevel_tool(ctx, sf, node, tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                call = deco if isinstance(deco, ast.Call) else None
                target = deco.func if call else deco
                attr = target.attr if isinstance(target, ast.Attribute) else ""
                if attr in PY_TOOL_DECOS:
                    kind = PY_TOOL_DECOS[attr]
                    name = None
                    desc = None
                    ann: dict = {}
                    if call:
                        if call.args:
                            name = _const_str(call.args[0])
                        name = _const_str(_kw(call, "name")) or name
                        desc = _const_str(_kw(call, "description"))
                        ann = _literal_dict(_kw(call, "annotations"))
                        for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                            v = _kw(call, hint)
                            if isinstance(v, ast.Constant):
                                ann[hint] = v.value
                    if kind == "resource" and name:       # @mcp.resource("uri://{x}") — name is the URI
                        name = f"{name}"
                    _py_tool(ctx, sf, node, kind, name, desc, ann)
                elif attr == "call_tool":
                    # low-level dispatcher: every Tool(...) in this file is handled here
                    for t in srv.tools:
                        if t.file == sf.rel and t.end_line == t.line:
                            t.end_line = node.end_lineno or node.lineno
                    ctx.spans[sf.rel].append(ToolSpan(sf.rel, node.lineno, node.end_lineno or node.lineno, "call_tool (dispatcher)"))

    # transport words in argparse choices / env defaults, e.g. choices=["stdio", "http"]
    for _i, line in enumerate(sf.lines, 1):
        if "transport" in line.lower():
            for w in re.findall(r"['\"]([A-Za-z_-]+)['\"]", line):
                if w.lower() in TRANSPORT_WORDS:
                    _add(srv.transports, TRANSPORT_WORDS[w.lower()])


def _py_tool(ctx: Ctx, sf: SourceFile, fn, kind: str, name: str | None, desc: str | None, ann: dict) -> None:
    name = name or fn.name
    doc = ast.get_docstring(fn) or ""
    tool = McpTool(name=name, kind=kind, description=(desc or doc).strip(), file=sf.rel, line=fn.lineno,
                   end_line=fn.end_lineno or fn.lineno, params=_py_params(fn), annotations=ann)
    body = "\n".join(sf.lines[fn.lineno - 1: (fn.end_lineno or fn.lineno)])
    classify(tool, body + "\n" + _helper_bodies(body, fn.name))
    tool.is_async = isinstance(fn, ast.AsyncFunctionDef)
    ctx.server.tools.append(tool)
    ctx.spans[sf.rel].append(ToolSpan(sf.rel, fn.lineno, fn.end_lineno or fn.lineno, name))


def _helper_bodies(body: str, own: str, depth: int = 2) -> str:
    """Bodies of same-file functions/methods the handler calls, so a thin tool that delegates
    to `srv.run_sql(...)` is classified by what the delegate really does."""
    seen, frontier, out = {own}, [body], []
    for _ in range(depth):
        nxt = []
        for b in frontier:
            for name in set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", b)):
                if name not in seen and name in _DEFS_SRC:
                    seen.add(name)
                    out.append(_DEFS_SRC[name])
                    nxt.append(_DEFS_SRC[name])
        frontier = nxt
    return "\n".join(out)[:60_000]


def _lowlevel_tool(ctx: Ctx, sf: SourceFile, node: ast.Call, tree: ast.AST) -> None:
    name = _const_str(_kw(node, "name")) or "?"
    desc = _const_str(_kw(node, "description")) or ""
    schema = _kw(node, "inputSchema")
    params: list[ToolParam] = []
    if isinstance(schema, ast.Dict):
        for k, v in zip(schema.keys, schema.values):
            if isinstance(k, ast.Constant) and k.value == "properties" and isinstance(v, ast.Dict):
                for pk, pv in zip(v.keys, v.values):
                    if isinstance(pk, ast.Constant):
                        src = ast.unparse(pv)
                        ptype = re.search(r"'type':\s*'(\w+)'", src)
                        constrained = bool(re.search(r"'(enum|pattern|maxLength|maximum|minimum|const|format)'", src)) or (ptype and ptype.group(1) in ("integer", "number", "boolean"))
                        params.append(ToolParam(name=str(pk.value), type=ptype.group(1) if ptype else "", constrained=bool(constrained)))
    ann = _literal_dict(_kw(node, "annotations"))
    tool = McpTool(name=name, kind="tool", description=desc, file=sf.rel, line=node.lineno, end_line=node.lineno, params=params, annotations=ann)
    classify(tool, sf.text)       # low-level dispatchers mix every tool in one body: classify on the file
    ctx.server.tools.append(tool)


# --------------------------------------------------------------------------- bracket matcher (TS/JS/Go/Java/C#)
def match_bracket(text: str, start: int) -> int:
    """Index just past the bracket that closes the one at/after `start`; ignores strings & comments."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    i, n = start, len(text)
    while i < n and text[i] not in pairs:
        i += 1
    if i >= n:
        return n
    stack = [pairs[text[i]]]
    i += 1
    while i < n and stack:
        c = text[i]
        if c in "\"'`":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                elif q == "`" and text.startswith("${", i):
                    end = match_bracket(text, i + 1)
                    i = end - 1
                i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif text.startswith("/*", i):
            e = text.find("*/", i + 2)
            i = n if e < 0 else e + 1
        elif c in pairs:
            stack.append(pairs[c])
        elif c == stack[-1]:
            stack.pop()
        i += 1
    return i


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


STR = r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)"""


def _first_str(m: re.Match, base: int = 1) -> str:
    for g in range(base, base + 3):
        if m.group(g) is not None:
            return m.group(g)
    return ""


def _find_prop(region: str, prop: str) -> str:
    m = re.search(rf"\b{prop}\s*:\s*{STR}", region)
    if m:
        return _first_str(m)
    # description: "a" + "b" concatenations or template on several lines
    m = re.search(rf"\b{prop}\s*:\s*\[?\s*((?:{STR}\s*[+,]?\s*)+)", region)
    if m:
        return " ".join(x for t in re.findall(STR, m.group(1)) for x in t if x)
    return ""


def _zod_params(region: str) -> list[ToolParam]:
    params = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*:\s*z\s*\.\s*(\w+)\(([^\n]*)", region):
        name, ztype, rest = m.group(1), m.group(2), m.group(3)
        if name in ("type", "description", "title", "inputSchema", "outputSchema", "annotations"):
            continue
        chain = ztype + rest
        constrained = ztype in ("enum", "literal", "number", "boolean", "nativeEnum", "date", "bigint") or bool(
            re.search(r"\.(enum|regex|max|length|url|email|uuid|ip|datetime|int|positive|startsWith|endsWith|refine)\(", chain))
        required = ".optional()" not in rest and ".default(" not in rest
        desc = re.search(r"\.describe\(\s*" + STR, rest)
        params.append(ToolParam(name=name, type=ztype, constrained=constrained, required=required,
                                description=_first_str(desc) if desc else ""))
    if not params:
        # plain JSON schema objects: properties: { path: { type: "string" ... } }
        props = re.search(r"properties\s*:\s*\{", region)
        if props:
            end = match_bracket(region, props.end() - 1)
            block = region[props.end():end]
            for pm in re.finditer(r"\b([A-Za-z_]\w*)\s*:\s*\{\s*type\s*:\s*['\"](\w+)['\"]([^}]*)\}", block):
                constrained = pm.group(2) in ("integer", "number", "boolean") or bool(re.search(r"\b(enum|pattern|maxLength|maximum|format)\b", pm.group(3)))
                params.append(ToolParam(name=pm.group(1), type=pm.group(2), constrained=constrained))
    return params


def _js_annotations(region: str) -> dict:
    ann = {}
    for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        m = re.search(rf"\b{hint}\s*:\s*(true|false)", region)
        if m:
            ann[hint] = m.group(1) == "true"
    return ann


JS_TOOL_CALL = re.compile(r"\.(tool|registerTool|addTool|resource|registerResource|prompt|registerPrompt)\s*\(")


def discover_js(ctx: Ctx, sf: SourceFile) -> None:
    text = sf.text
    uses_sdk = "@modelcontextprotocol/sdk" in text
    uses_fastmcp = re.search(r"""from\s+['"]fastmcp['"]|require\(\s*['"]fastmcp['"]\)""", text) is not None
    uses_framework = "mcp-framework" in text
    if not (uses_sdk or uses_fastmcp or uses_framework or re.search(r"new\s+(McpServer|FastMCP)\s*\(", text)):
        return
    srv = ctx.server
    srv.detected = True
    _add(srv.languages, sf.language)
    if uses_sdk:
        _add(srv.sdks, "MCP TypeScript SDK")
    if uses_fastmcp:
        _add(srv.sdks, "fastmcp (TypeScript)")
    if uses_framework:
        _add(srv.sdks, "mcp-framework (TypeScript)")
    for m in re.finditer(r"new\s+(McpServer|Server|FastMCP)\s*\(\s*\{", text):
        region = text[m.end() - 1: match_bracket(text, m.end() - 1)]
        name = _find_prop(region, "name")
        if name:
            _add(srv.names, name)
        _add(srv.entrypoints, f"{sf.rel}:{_line_of(text, m.start())}")
    if "StdioServerTransport" in text or re.search(r"transportType\s*:\s*['\"]stdio", text):
        _add(srv.transports, "stdio")
    if "SSEServerTransport" in text or re.search(r"transportType\s*:\s*['\"]sse", text):
        _add(srv.transports, "sse")
    if "StreamableHTTPServerTransport" in text or re.search(r"transportType\s*:\s*['\"]httpStream", text):
        _add(srv.transports, "streamable-http")
    if re.search(r"sessionIdGenerator\s*:\s*undefined", text):
        srv.stateless_http = True
    elif re.search(r"sessionIdGenerator\s*:", text) and srv.stateless_http is None:
        srv.stateless_http = False
    if re.search(r"stateless\s*:\s*true", text):
        srv.stateless_http = True

    for m in JS_TOOL_CALL.finditer(text):
        method = m.group(1)
        kind = "resource" if "esource" in method else "prompt" if "rompt" in method else "tool"
        end = match_bracket(text, m.end() - 1)
        region = text[m.end(): end]
        start_line = _line_of(text, m.start())
        end_line = _line_of(text, end)
        name, desc = "", ""
        head = re.match(r"\s*" + STR + r"\s*(,\s*" + STR + r")?", region)
        if head:
            name = _first_str(head, 1)
            if head.group(4) is not None or head.group(5) is not None or head.group(6) is not None:
                desc = _first_str(head, 5) if method in ("tool", "prompt", "resource") else ""
        if kind == "resource":
            desc = ""
        if method in ("registerTool", "registerPrompt", "registerResource") or not desc:
            desc = desc or _find_prop(region[:4000], "description")
        if not name:
            name = _find_prop(region[:600], "name")           # addTool({ name: "...", ... })
        if not name:
            continue
        # .tool() / .resource() is a common method name — require MCP context in this file
        if method == "tool" and not (uses_sdk or uses_fastmcp):
            continue
        tool = McpTool(name=name, kind=kind, description=desc.strip(), file=sf.rel, line=start_line, end_line=end_line,
                       params=_zod_params(region[:6000]) if kind == "tool" else [], annotations=_js_annotations(region[:6000]))
        classify(tool, region)
        srv.tools.append(tool)
        ctx.spans[sf.rel].append(ToolSpan(sf.rel, start_line, end_line, name))

    # low-level Server: setRequestHandler(ListToolsRequestSchema, ...) => { tools: [ {name, description, inputSchema} ] }
    lm = re.search(r"setRequestHandler\(\s*ListToolsRequestSchema", text)
    if lm:
        lend = match_bracket(text, lm.end() - 1)
        block = text[lm.end(): lend]
        known = {t.name for t in srv.tools}
        for om in re.finditer(r"\{\s*name\s*:\s*" + STR, block):
            oend = match_bracket(block, om.start())
            obj = block[om.start(): oend]
            if "inputSchema" not in obj and "description" not in obj:
                continue
            name = _first_str(om)
            if name in known:
                continue
            tool = McpTool(name=name, description=_find_prop(obj, "description"), file=sf.rel,
                           line=_line_of(text, lm.end() + om.start()), end_line=_line_of(text, lm.end() + oend),
                           params=_zod_params(obj), annotations=_js_annotations(obj))
            classify(tool, text)
            srv.tools.append(tool)
        cm = re.search(r"setRequestHandler\(\s*CallToolRequestSchema", text)
        if cm:
            cend = match_bracket(text, cm.end() - 1)
            ctx.spans[sf.rel].append(ToolSpan(sf.rel, _line_of(text, cm.start()), _line_of(text, cend), "CallTool (dispatcher)"))


# --------------------------------------------------------------------------- Go / Java / C# (lighter)
def discover_other(ctx: Ctx, sf: SourceFile) -> None:
    text = sf.text
    srv = ctx.server
    lang = sf.language
    found = False
    if lang == "go" and ("mark3labs/mcp-go" in text or "modelcontextprotocol/go-sdk" in text):
        found = True
        _add(srv.sdks, "mcp-go" if "mark3labs" in text else "MCP Go SDK")
        for m in re.finditer(r"NewMCPServer\(\s*" + STR, text):
            _add(srv.names, _first_str(m))
        for m in re.finditer(r"mcp\.NewTool\(\s*" + STR, text):
            end = match_bracket(text, m.start() + len("mcp.NewTool"))
            region = text[m.start(): end]
            d = re.search(r"WithDescription\(\s*" + STR, region)
            _simple_tool(ctx, sf, _first_str(m), _first_str(d) if d else "", m.start(), end, region)
        for m in re.finditer(r"&mcp\.Tool\{", text):
            end = match_bracket(text, m.end() - 1)
            region = text[m.start(): end]
            n = re.search(r"Name\s*:\s*" + STR, region)
            d = re.search(r"Description\s*:\s*" + STR, region)
            if n:
                _simple_tool(ctx, sf, _first_str(n), _first_str(d) if d else "", m.start(), end, region)
        if re.search(r"ServeStdio|StdioTransport", text):
            _add(srv.transports, "stdio")
        if re.search(r"NewSSEServer|SSEHandler", text):
            _add(srv.transports, "sse")
        if re.search(r"NewStreamableHTTPServer|StreamableHTTPHandler", text):
            _add(srv.transports, "streamable-http")
    elif lang in ("java", "kotlin") and re.search(r"io\.modelcontextprotocol|org\.springframework\.ai\.(tool|mcp)", text):
        found = True
        _add(srv.sdks, "Spring AI MCP" if "springframework.ai" in text else "MCP Java SDK")
        for m in re.finditer(r"@Tool\s*\(([^)]*)\)\s*(?:public\s+)?[\w<>\[\], ]+\s+(\w+)\s*\(", text):
            d = re.search(r"description\s*=\s*" + STR, m.group(1))
            n = re.search(r"name\s*=\s*" + STR, m.group(1))
            end = match_bracket(text, m.end() - 1)
            end = match_bracket(text, end)          # method body
            _simple_tool(ctx, sf, _first_str(n) if n else m.group(2), _first_str(d) if d else "", m.start(), end, text[m.start(): end])
        if re.search(r"StdioServerTransportProvider", text):
            _add(srv.transports, "stdio")
        if re.search(r"SseServerTransportProvider", text):
            _add(srv.transports, "sse")
        if re.search(r"StreamableServerTransportProvider|Streamable", text):
            _add(srv.transports, "streamable-http")
    elif lang == "csharp" and "ModelContextProtocol" in text:
        found = True
        _add(srv.sdks, "MCP C# SDK")
        for m in re.finditer(r"\[McpServerTool[^\]]*\](?:\s*\[Description\(\s*" + STR + r"\s*\)\])?\s*public\s+[\w<>\[\], ?]+\s+(\w+)\s*\(", text):
            end = match_bracket(text, m.end() - 1)
            end = match_bracket(text, end)
            _simple_tool(ctx, sf, m.group(4), _first_str(m) if m.group(1) or m.group(2) or m.group(3) else "", m.start(), end, text[m.start(): end])
        if "WithStdioServerTransport" in text:
            _add(srv.transports, "stdio")
        if re.search(r"WithHttpTransport|MapMcp", text):
            _add(srv.transports, "streamable-http")
    if found:
        srv.detected = True
        _add(srv.languages, lang)


def _simple_tool(ctx: Ctx, sf: SourceFile, name: str, desc: str, start: int, end: int, region: str) -> None:
    tool = McpTool(name=name, description=desc, file=sf.rel, line=_line_of(sf.text, start), end_line=_line_of(sf.text, end))
    classify(tool, region)
    ctx.server.tools.append(tool)
    ctx.spans[sf.rel].append(ToolSpan(sf.rel, tool.line, tool.end_line, name))


# --------------------------------------------------------------------------- project-wide
def _add(lst: list, val: str) -> None:
    if val and val not in lst:
        lst.append(val)


def detect_auth_and_signals(ctx: Ctx) -> None:
    srv = ctx.server
    for sf in ctx.ws.files:
        if sf.is_test or sf.language in ("config", "dockerfile"):
            continue
        for label, rx in AUTH_PATTERNS:
            m = rx.search(sf.text)
            if m:
                # a bare "jwt.decode" mention is not auth unless something checks it
                srv.auth.detected = True
                _add(srv.auth.mechanisms, label)
                if len(srv.auth.evidence) < 8:
                    _add(srv.auth.evidence, f"{sf.rel}:{_line_of(sf.text, m.start())} {m.group(0)[:60]}")
        for sig, rx in SIGNAL_PATTERNS.items():
            m = rx.search(sf.text)
            if m:
                lst = srv.signals.setdefault(sig, [])
                if len(lst) < 5:
                    lst.append(f"{sf.rel}:{_line_of(sf.text, m.start())}")
    # dependency manifests also reveal controls (e.g. slowapi, opentelemetry in requirements)
    for rel in ctx.ws.other_files:
        low = rel.lower()
        if low.endswith(("requirements.txt", "pyproject.toml", "package.json", "go.mod", "pom.xml", "pipfile")):
            content = ctx.ws.read(rel, 200_000)
            for sig in ("rate_limit", "retry", "metrics_tracing", "structured_logging", "logging", "cache"):
                if SIGNAL_PATTERNS[sig].search(content):
                    lst = srv.signals.setdefault(sig, [])
                    if rel not in lst and len(lst) < 5:
                        lst.append(rel)
            for name, ver in _sdk_versions(content, low):
                srv.sdk_versions.setdefault(name, ver)


def _sdk_versions(content: str, low: str):
    if low.endswith("package.json"):
        for m in re.finditer(r'"(@modelcontextprotocol/sdk|fastmcp|mcp-framework)"\s*:\s*"([^"]+)"', content):
            yield m.group(1), m.group(2)
    elif low.endswith("pyproject.toml"):
        for m in re.finditer(r"""["'](mcp|fastmcp)(\[[\w,\s]+\])?\s*((?:==|>=|~=|<=|>|<|!=)\s*[\w.*]+(?:\s*,\s*[<>=!~]+\s*[\w.*]+)*)?\s*(;[^"']*)?["']""", content):
            yield m.group(1).lower(), (m.group(3) or "unpinned").replace(" ", "")
    else:
        for m in re.finditer(r"""(?im)^\s*(mcp|fastmcp)(\[[\w,]+\])?\s*((?:==|>=|~=|<=|>|<)\s*[\w.*]+(?:\s*,\s*[<>=!~]+\s*[\w.*]+)*)?\s*(#.*|;.*)?$""", content):
            yield m.group(1).lower(), (m.group(3) or "unpinned").replace(" ", "")
        for m in re.finditer(r'(?m)^\s*(mcp|fastmcp)\s*=\s*["\']([^"\']+)["\']', content):   # poetry
            yield m.group(1), m.group(2)


def discover(ctx: Ctx) -> None:
    for sf in ctx.ws.files:
        if sf.is_test:
            continue
        if sf.language == "python":
            discover_python(ctx, sf)
        elif sf.language in ("typescript", "javascript"):
            discover_js(ctx, sf)
        elif sf.language in ("go", "java", "kotlin", "csharp"):
            discover_other(ctx, sf)
    detect_auth_and_signals(ctx)
    srv = ctx.server
    if any(x.startswith("mcp python SDK (") for x in srv.sdks) and "mcp python SDK" in srv.sdks:
        srv.sdks.remove("mcp python SDK")
    if srv.detected and not srv.transports:
        srv.transports.append("stdio")       # every SDK defaults to stdio when nothing else is wired
    # de-duplicate tools registered twice (same name/file/line)
    seen, uniq = set(), []
    for t in srv.tools:
        k = (t.name, t.file, t.line)
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    srv.tools = uniq
