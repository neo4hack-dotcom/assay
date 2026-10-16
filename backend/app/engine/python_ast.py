"""Python checks on the syntax tree.

A light, intra-procedural taint model: a value is *tainted* when it derives
from the parameters of an MCP tool handler (or from any name assigned from a
tainted expression earlier in the same function). Sinks reached by tainted
data are reported with high confidence and the tool name; the same sink fed by
non-constant but untainted data is reported with lower confidence.
"""
from __future__ import annotations

import ast
import re

from .context import Ctx
from .models import Severity
from .workspace import SourceFile

SQL_WORDS = re.compile(r"\b(select|insert|update|delete|with|create|drop|alter|merge|truncate|from|where|values|exec)\b", re.I)
SECRETISH = re.compile(r"(password|passwd|secret|token|api_?key|apikey|authorization|bearer|credential|private_?key|client_secret|cookie|session_?id)", re.I)
NOT_SECRET = re.compile(r"(count|len|max|min|num|total|usage|limit|budget|used|estimate|tokens?_|_tokens?$|^tokens?$|tokenizer|tokenize|stream|type|name|url|path|file|header_name|env_var|field|key_name|_id$|expires?)", re.I)
TOKENISH_TARGET = re.compile(r"(token|secret|password|passwd|nonce|session|otp|salt|api_?key|csrf|reset_code|verification)", re.I)
FACTORY_FN = re.compile(r"(^__init__$|^lifespan|startup|^main$|^create_|^make_|^build_|^get_?(client|pool|engine|session|conn|connection|db)|factory|^setup|^init|^connect$|^_connect|^open_)", re.I)
GUARD_TOKENS = re.compile(r"(resolve\(|realpath|abspath|normpath)[\s\S]*(is_relative_to|commonpath|startswith|relative_to|in\s+allowed|ALLOWED)|safe_join|secure_filename|_safe_path|_resolve_path|ensure_within|within_root|check_path|validate_path", re.I)
ALLOWLIST_TOKENS = re.compile(r"(allow(ed)?_?(hosts|domains|urls|list)|allowlist|whitelist|ALLOWED_|urlparse|urlsplit|\.hostname\s+(not\s+)?in|netloc\s+(not\s+)?in|validate_url|is_private|ip_address)", re.I)
LIMIT_TOKENS = re.compile(r"(\blimit\b|LIMIT|fetchmany|max_rows|\[:\s*\w+\]|islice|truncat|page_size|max_results|top\s*\(|FETCH FIRST|ROWNUM)", re.I)

BLOCKING_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.head",
    "requests.request", "requests.Session", "urllib.request.urlopen", "time.sleep", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen", "os.system", "os.popen",
    "psycopg2.connect", "pymysql.connect", "mysql.connector.connect", "cx_Oracle.connect", "oracledb.connect",
    "pyodbc.connect", "pymongo.MongoClient", "sqlite3.connect", "socket.create_connection", "smtplib.SMTP",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request", "httpx.Client", "redis.Redis",
}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "request", "stream", "options"}
NETWORK_RECEIVER = re.compile(r"(client|session|http|requests|httpx|api|conn)$", re.I)
CONN_FACTORIES = {
    "psycopg2.connect", "psycopg.connect", "pymysql.connect", "mysql.connector.connect", "cx_Oracle.connect",
    "oracledb.connect", "pyodbc.connect", "pymongo.MongoClient", "redis.Redis", "redis.StrictRedis",
    "sqlalchemy.create_engine", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "requests.Session",
    "asyncpg.connect", "clickhouse_connect.get_client", "snowflake.connector.connect", "boto3.client",
}
DESERIALIZERS = {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads",
                 "marshal.load", "marshal.loads", "shelve.open", "jsonpickle.decode", "pandas.read_pickle",
                 "yaml.unsafe_load", "joblib.load", "torch.load"}
XML_PARSERS = {"xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.XML",
               "xml.dom.minidom.parse", "xml.dom.minidom.parseString", "xml.sax.parse", "xml.sax.parseString",
               "lxml.etree.parse", "lxml.etree.fromstring", "xml.etree.cElementTree.parse"}
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}


class _Func:
    def __init__(self, node, tool: str, parent: "_Func | None"):
        self.node = node
        self.tool = tool
        self.is_async = isinstance(node, ast.AsyncFunctionDef)
        self.name = node.name
        params = {a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs}
        if node.args.vararg:
            params.add(node.args.vararg.arg)
        if node.args.kwarg:
            params.add(node.args.kwarg.arg)
        params -= {"self", "cls", "ctx", "context"}
        self.params = params
        self.tainted: set[str] = set(params) if tool else set()
        self.built_strings: dict[str, ast.AST] = {}
        self.src = ""


class PyAnalyzer(ast.NodeVisitor):
    def __init__(self, ctx: Ctx, sf: SourceFile, tree: ast.Module):
        self.ctx, self.sf, self.tree = ctx, sf, tree
        self.aliases: dict[str, str] = {}
        self.funcs: list[_Func] = []
        self.loop_depth = 0
        self.main_guard_depth = 0
        self.module_mutables: dict[str, int] = {}
        self.mutated_globals: set[str] = set()
        self.http_transport = any(t in ("streamable-http", "sse") for t in ctx.server.transports)
        self.stdio = "stdio" in ctx.server.transports
        from .mcp_discovery import py_imported_modules
        self.imports_mcp = bool({m.split(".")[0] for m in py_imported_modules(tree)} & {"mcp", "fastmcp"})
        self.uses_defusedxml = "defusedxml" in sf.text
        self.except_names: list[tuple[str, bool]] = []

    # ------------------------------------------------------------------ helpers
    @property
    def fn(self) -> _Func | None:
        return self.funcs[-1] if self.funcs else None

    def dotted(self, node: ast.AST) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            inner = self.dotted(node.func)
            parts.append(inner + "()" if inner else "?()")
        else:
            return ""
        return ".".join(reversed(parts))

    def is_const(self, node: ast.AST | None) -> bool:
        if node is None:
            return True
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(self.is_const(e) for e in node.elts)
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self.is_const(node.left) and self.is_const(node.right)
        if isinstance(node, ast.Name) and node.id.isupper():
            return True                                  # MODULE_CONSTANT
        return False

    def tainted(self, node: ast.AST | None) -> bool:
        f = self.fn
        if node is None or f is None or not f.tainted:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in f.tainted:
                return True
        return False

    SAFE_FMT = re.compile(r"^(int|float|len|bool|round|abs|min|max)\(|^[A-Z_][A-Z0-9_]*$|^self\.[A-Z_]+$"
                          r"|^(ph|phs|placeholders?|qmarks|marks|binds?|bind_vars|bind_names|in_params|param_markers)$")

    def built_string(self, node: ast.AST) -> ast.AST | None:
        """Return the string-building expression (f-string, concat, %, .format) behind node, if any.
        Interpolating only numeric casts or CONSTANTS is not an injection vector and is ignored."""
        if isinstance(node, ast.JoinedStr):
            dyn = [v for v in node.values if isinstance(v, ast.FormattedValue)]
            if dyn and not all(self.SAFE_FMT.search(ast.unparse(v.value)) for v in dyn):
                return node
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)) and not self.is_const(node):
            if any(isinstance(n, ast.Constant) and isinstance(n.value, str) for n in ast.walk(node)):
                return node
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format" \
                and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
            return node
        if isinstance(node, ast.Name) and self.fn and node.id in self.fn.built_strings:
            return self.fn.built_strings[node.id]
        return None

    def string_text(self, node: ast.AST) -> str:
        return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))

    def add(self, rule: str, node: ast.AST, msg: str = "", sev: Severity | None = None, conf: str | None = None):
        line = getattr(node, "lineno", 0)
        tool = self.fn.tool if self.fn and self.fn.tool else ""
        return self.ctx.add(rule, self.sf, line, message=msg, severity=sev, confidence=conf, source="ast", tool=tool or None,
                            end_line=getattr(node, "end_lineno", line) or line)

    def kw(self, call: ast.Call, name: str) -> ast.AST | None:
        for k in call.keywords:
            if k.arg == name:
                return k.value
        return None

    # ------------------------------------------------------------------ structure
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            if a.asname:
                self.aliases[a.asname] = a.name

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    def visit_If(self, node: ast.If):
        is_main = isinstance(node.test, ast.Compare) and "__name__" in ast.unparse(node.test)
        if is_main:
            self.main_guard_depth += 1
        self.generic_visit(node)
        if is_main:
            self.main_guard_depth -= 1

    def _visit_func(self, node):
        tool = self.ctx.tool_at(self.sf.rel, node.lineno) if node.lineno else ""
        # nested helpers inside a tool keep the tool name, but only the tool's own params are tainted
        own_tool = tool if any(s.start == node.lineno or s.start == (node.decorator_list[0].lineno if node.decorator_list else -1)
                               for s in self.ctx.spans.get(self.sf.rel, ())) else ""
        f = _Func(node, own_tool, self.fn)
        if not own_tool and self.fn and self.fn.tool:
            f.tool = self.fn.tool
            f.tainted |= self.fn.tainted
        f.src = "\n".join(self.sf.lines[node.lineno - 1: (node.end_lineno or node.lineno)])
        self.funcs.append(f)
        saved_loop = self.loop_depth
        self.loop_depth = 0
        if own_tool:
            self._tool_checks(f)
        self.generic_visit(node)
        self.loop_depth = saved_loop
        self.funcs.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Lambda(self, node):
        self.generic_visit(node)

    def _loop(self, node):
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    visit_For = visit_AsyncFor = visit_While = _loop
    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _loop

    def visit_Assign(self, node: ast.Assign):
        f = self.fn
        if f is None:
            # module-level mutable containers (possible shared state)
            if isinstance(node.value, (ast.Dict, ast.List, ast.Set)) or (
                    isinstance(node.value, ast.Call) and self.dotted(node.value.func).split(".")[-1] in
                    ("dict", "list", "set", "defaultdict", "OrderedDict", "deque", "Counter")):
                for t in node.targets:
                    if isinstance(t, ast.Name) and not t.id.isupper():
                        self.module_mutables[t.id] = node.lineno
        else:
            for t in node.targets:
                names = [n.id for n in ast.walk(t) if isinstance(n, ast.Name)]
                if self.tainted(node.value):
                    f.tainted.update(names)
                b = self.built_string(node.value)
                if b is not None:
                    for n in names:
                        f.built_strings[n] = b
                # random value assigned to a token-like name
                if isinstance(node.value, ast.Call):
                    d = self.dotted(node.value.func)
                    if d.startswith("random.") and any(TOKENISH_TARGET.search(n) for n in names):
                        self.add("SEC-010", node, f"`{d}` used to generate `{names[0]}`.")
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in self.module_mutables:
                    self._global_mutation(t.value.id, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if self.fn and isinstance(node.target, ast.Name) and isinstance(node.value, (ast.JoinedStr, ast.BinOp)) and self.built_string(node.value) is not None:
            self.fn.built_strings[node.target.id] = node.value
        if self.fn and self.tainted(node.value) and isinstance(node.target, ast.Name):
            self.fn.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global):
        for n in node.names:
            if self.fn:
                self._global_mutation(n, node)

    def _global_mutation(self, name: str, node: ast.AST):
        if name in self.mutated_globals or self.sf.is_test:
            return
        self.mutated_globals.add(name)
        if self.fn and (self.fn.tool or self.http_transport):
            self.add("SCL-003", node, f"Module-level `{name}` is mutated at request time.", conf="medium" if self.fn.tool else "low")

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        body = node.body
        silent = all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in body)
        broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
        if silent and broad:
            self.add("REL-002", node, "Broad exception caught and discarded.")
        elif silent:
            self.add("REL-002", node, "Exception discarded without logging.", sev=Severity.info, conf="low")
        elif node.type is None:
            self.add("REL-002", node, "Bare `except:` also catches KeyboardInterrupt/SystemExit.", sev=Severity.low, conf="medium")
        self.except_names.append((node.name or "", broad))
        self.generic_visit(node)
        self.except_names.pop()

    def visit_Return(self, node: ast.Return):
        f = self.fn
        if f and f.tool and node.value is not None:
            src = ast.unparse(node.value)
            ename, ebroad = self.except_names[-1] if self.except_names else ("", False)
            if (ename and ebroad and re.search(rf"\b{re.escape(ename)}\b", src)) or "format_exc" in src:
                self.add("SEC-018", node, "Exception details are returned to the model/client.")
            if re.search(r"indent\s*=\s*[1-9]", src) and "json.dumps" in src:
                self.add("PRF-003", node, "Indented JSON returned from a tool.")
        self.generic_visit(node)

    # ------------------------------------------------------------------ calls
    def visit_Call(self, node: ast.Call):
        c = self._call_info(node)
        for check in self.CALL_CHECKS:
            check(self, node, c)
        self.generic_visit(node)

    def _call_info(self, node: ast.Call) -> dict:
        d = self.dotted(node.func)
        arg0 = node.args[0] if node.args else None
        is_http = d in BLOCKING_CALLS and d.split(".")[0] in ("requests", "httpx", "urllib") \
            or (isinstance(node.func, ast.Attribute) and d.split(".")[-1] in HTTP_VERBS
                and NETWORK_RECEIVER.search(self.dotted(node.func.value) or "") is not None
                and not d.startswith(("os.", "dict", "self.headers")))
        return {"d": d, "last": d.split(".")[-1] if d else "", "f": self.fn, "arg0": arg0,
                "in_tool": bool(self.fn and self.fn.tool), "is_http": is_http}

    def _c_command_injection(self, node: ast.Call, c: dict) -> None:
        """Command injection."""
        d, arg0 = c["d"], c["arg0"]
        if d in ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                 "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell") \
                or d in ("os.system", "os.popen", "commands.getoutput") or d.startswith(("os.exec", "os.spawn")):
            shell_kw = self.kw(node, "shell")
            shell = (isinstance(shell_kw, ast.Constant) and shell_kw.value is True) or d in (
                "os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell")
            dyn = arg0 is not None and not self.is_const(arg0)
            via_sh = isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts and isinstance(arg0.elts[0], ast.Constant) \
                and str(arg0.elts[0].value) in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "/bin/sh", "/bin/bash") \
                and any(isinstance(e, ast.Constant) and e.value in ("-c", "/c", "-Command") for e in arg0.elts)
            if shell and dyn:
                self.add("SEC-001", node, f"`{d}` runs a shell command built from non-constant data" + (" derived from tool input." if self.tainted(arg0) else "."),
                         conf="high" if self.tainted(arg0) else "medium")
            elif via_sh and dyn:
                self.add("SEC-001", node, "Command executed through `sh -c`-style invocation with dynamic content.", conf="medium")
            elif shell:
                self.add("SEC-001", node, f"`{d}` uses a shell with a constant command (low risk, but avoid shell=True).", sev=Severity.low, conf="medium")
            elif dyn and self.tainted(arg0):
                self.add("MCP-008", node, f"Process arguments for `{d}` come from tool input — validate each argument against an allow-list.",
                         sev=Severity.medium, conf="medium")

    def _c_dynamic_evaluation(self, node: ast.Call, c: dict) -> None:
        """Dynamic evaluation."""
        d, last, arg0 = c["d"], c["last"], c["arg0"]
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec") and arg0 is not None:
            if not self.is_const(arg0):
                self.add("SEC-002", node, f"`{node.func.id}()` on non-constant input" + (" from tool parameters." if self.tainted(arg0) else "."),
                         conf="high" if self.tainted(arg0) else "medium")
        if d in ("jinja2.Template", "flask.render_template_string", "render_template_string") and arg0 is not None and not self.is_const(arg0):
            self.add("SEC-017", node, "Template compiled from a non-constant string.")
        if last == "from_string" and "Environment" in d and arg0 is not None and not self.is_const(arg0):
            self.add("SEC-017", node, "Template compiled from a non-constant string.")

    def _c_sql(self, node: ast.Call, c: dict) -> None:
        """Sql."""
        d, last, arg0 = c["d"], c["last"], c["arg0"]
        if last in ("execute", "executescript", "exec_driver_sql", "raw", "query", "text", "read_sql", "read_sql_query", "sql") and arg0 is not None:
            b = self.built_string(arg0)
            if b is not None and SQL_WORDS.search(self.string_text(b)) and (last != "text" or "sqlalchemy" in d or d == "text"):
                taint = self.tainted(b) or self.tainted(arg0)
                self.add("SEC-003", node, "SQL text built with string formatting" + (" using tool input." if taint else "."),
                         conf="high" if taint else "medium")

    def _c_deserialization(self, node: ast.Call, c: dict) -> None:
        """Deserialization."""
        d = c["d"]
        if d in DESERIALIZERS:
            self.add("SEC-004", node, f"`{d}` deserialises data that may not be trusted.", conf="medium")
        if d == "yaml.load":
            loader = self.kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in ast.unparse(loader):
                self.add("SEC-004", node, "`yaml.load` without SafeLoader can construct arbitrary objects.", conf="high")

    def _c_tls(self, node: ast.Call, c: dict) -> None:
        """Tls."""
        d = c["d"]
        v = self.kw(node, "verify")
        if isinstance(v, ast.Constant) and v.value is False:
            self.add("SEC-008", node, f"`verify=False` on `{d or 'call'}`.", conf="high")
        if d in ("ssl._create_unverified_context",):
            self.add("SEC-008", node, "Unverified SSL context.", conf="high")

    def _c_weak_crypto(self, node: ast.Call, c: dict) -> None:
        """Weak crypto."""
        d, f, arg0 = c["d"], c["f"], c["arg0"]
        if d in ("hashlib.md5", "hashlib.sha1") or (d == "hashlib.new" and arg0 is not None and isinstance(arg0, ast.Constant) and str(arg0.value).lower() in ("md5", "sha1")):
            ufs = self.kw(node, "usedforsecurity")
            if not (isinstance(ufs, ast.Constant) and ufs.value is False):
                ctx_name = (f.name if f else "")
                low_risk = re.search(r"(cache|etag|checksum|fingerprint|digest|hash_key|dedup|id\b)", ctx_name, re.I)
                self.add("SEC-009", node, f"`{d}` used" + (" (looks non-security: mark usedforsecurity=False)." if low_risk else "."),
                         sev=Severity.low if low_risk else None, conf="low" if low_risk else "medium")

    def _c_xml(self, node: ast.Call, c: dict) -> None:
        """Xml."""
        d, arg0 = c["d"], c["arg0"]
        if d in XML_PARSERS and not self.uses_defusedxml:
            self.add("SEC-014", node, f"`{d}` parses XML without defusedxml.", conf="low" if not self.tainted(arg0) else "medium")

    def _c_jwt(self, node: ast.Call, c: dict) -> None:
        """Jwt."""
        d, in_tool = c["d"], c["in_tool"]
        if d.endswith("jwt.decode") or d in ("jwt.decode", "jose.jwt.decode"):
            src = ast.unparse(node)
            if re.search(r"verify_signature['\"]?\s*:\s*False|verify\s*=\s*False", src):
                self.add("SEC-015", node, "JWT decoded without signature verification.", conf="high")
            elif re.search(r"['\"]none['\"]", src, re.I):
                self.add("SEC-015", node, "JWT 'none' algorithm accepted.", conf="high")
            elif "audience" not in src and "verify_aud" not in src:
                self.add("MCP-015", node, "JWT decoded without an `audience` check.", conf="medium")
        if d.endswith("get_unverified_claims") or d.endswith("get_unverified_header") and in_tool:
            self.add("SEC-015", node, "Unverified JWT claims used.", sev=Severity.medium, conf="low")

    def _c_logging_secrets(self, node: ast.Call, c: dict) -> None:
        """Logging secrets."""
        d, last = c["d"], c["last"]
        if (last in LOG_METHODS and re.search(r"(log|logger|logging|_log|LOG)", d)) or d == "print":
            for a in list(node.args) + [k.value for k in node.keywords]:
                for n in ast.walk(a):
                    nm = n.id if isinstance(n, ast.Name) else (n.attr if isinstance(n, ast.Attribute) else "")
                    if nm and SECRETISH.search(nm) and not NOT_SECRET.search(nm):
                        self.add("SEC-016", node, f"`{nm}` is written to logs/output.", conf="medium")
                        break
                else:
                    continue
                break

    def _c_stdout_in_stdio_servers(self, node: ast.Call, c: dict) -> None:
        """Stdout in stdio servers."""
        d, in_tool = c["d"], c["in_tool"]
        if d == "print" and self.stdio and (in_tool or self.imports_mcp) and not self.sf.is_test:
            fkw = self.kw(node, "file")
            if fkw is None or "stderr" not in ast.unparse(fkw):
                self.add("REL-005", node, "print() writes to stdout, which carries the JSON-RPC stream in stdio mode.",
                         conf="high" if in_tool else "medium")

    def _c_ssrf_timeouts_blocking(self, node: ast.Call, c: dict) -> None:
        """Ssrf + timeouts + blocking."""
        d, last, f, arg0, is_http = c["d"], c["last"], c["f"], c["arg0"], c["is_http"]
        url_arg = arg0 if arg0 is not None else self.kw(node, "url")
        if is_http and url_arg is not None and self.tainted(url_arg) and f and not ALLOWLIST_TOKENS.search(f.src):
            self.add("SEC-006", node, f"`{d}` targets a URL derived from tool input with no allow-list check.", conf="high")
        if d.split(".")[0] == "requests" and last in HTTP_VERBS | {"request"} and self.kw(node, "timeout") is None:
            self.add("REL-001", node, f"`{d}` has no timeout (requests waits forever by default).", conf="high")
        if d == "urllib.request.urlopen" and self.kw(node, "timeout") is None and len(node.args) < 3:
            self.add("REL-001", node, "`urlopen` without timeout.", conf="high")
        if d.startswith("httpx.") and isinstance(self.kw(node, "timeout"), ast.Constant) and self.kw(node, "timeout").value is None:
            self.add("REL-001", node, "httpx timeout explicitly disabled.", conf="high")
        if f and f.is_async and d in BLOCKING_CALLS and not self._awaited(node):
            self.add("SCL-004", node, f"Blocking `{d}` inside `async def {f.name}` stalls the event loop for all concurrent requests.", conf="high")
        elif f and f.is_async and isinstance(node.func, ast.Attribute) and last in ("execute", "fetchall", "fetchone", "commit") \
                and re.search(r"(cursor|cur|conn|connection)$", self.dotted(node.func.value) or "") and not self._awaited(node) \
                and not re.search(r"(asyncpg|aiosqlite|aiomysql|psycopg\.AsyncConnection|connect_async|AsyncSession)", self.sf.text):
            self.add("SCL-004", node, f"Synchronous DB-API call `{d}` inside `async def {f.name}`.", conf="medium")
        if f and f.tool and not f.is_async and self.http_transport and (d in BLOCKING_CALLS and d != "time.sleep" or d == "time.sleep"):
            self.add("SCL-004", node, f"Synchronous tool `{f.tool}` performs blocking `{d}`. Depending on the SDK version, sync tools may run on the event-loop thread; prefer async I/O or asyncio.to_thread.",
                     sev=Severity.medium, conf="low")

    def _c_per_call_connections(self, node: ast.Call, c: dict) -> None:
        """Per-call connections."""
        d, f = c["d"], c["f"]
        if d in CONN_FACTORIES and f and f.tool and not FACTORY_FN.search(f.name):
            self.add("SCL-005", node, f"`{d}` is created inside tool handler `{f.tool}` on every call.", conf="high")

    def _c_loops(self, node: ast.Call, c: dict) -> None:
        """Loops."""
        d, last, f, is_http = c["d"], c["last"], c["f"], c["is_http"]
        if self.loop_depth > 0 and f:
            if is_http or (last in ("execute", "query", "fetch", "find_one", "get_item") and re.search(r"(cursor|cur|conn|session|db|client|collection|table)$", self.dotted(node.func.value) if isinstance(node.func, ast.Attribute) else "", re.I)):
                self.add("PRF-001", node, f"`{d}` is called inside a loop.", conf="medium")
            if d == "re.compile":
                self.add("PRF-005", node, "re.compile inside a loop.", conf="high")

    def _c_unbounded_reads(self, node: ast.Call, c: dict) -> None:
        """Unbounded reads."""
        d, last, f = c["d"], c["last"], c["f"]
        if last == "fetchall" and f and f.tool and not LIMIT_TOKENS.search(f.src):
            self.add("MCP-010", node, f"Tool `{f.tool}` returns `fetchall()` results without a row limit.", conf="medium")
        elif last == "fetchall" and f and not LIMIT_TOKENS.search(f.src):
            self.add("PRF-002", node, "fetchall() without a row limit.", conf="low")
        if d == "time.sleep" and f and f.tool and not f.is_async:
            self.add("PRF-004", node, "time.sleep in a tool handler.", conf="high")

    def _c_unsafe_archives_temp(self, node: ast.Call, c: dict) -> None:
        """Unsafe archives / temp."""
        last, f = c["last"], c["f"]
        if last == "extractall" and self.kw(node, "filter") is None and f and not GUARD_TOKENS.search(f.src):
            self.add("SEC-020", node, "Archive extracted without member path validation.", conf="medium")

    def _c_path_traversal(self, node: ast.Call, c: dict) -> None:
        """Path traversal."""
        d, last, f, arg0 = c["d"], c["last"], c["f"], c["arg0"]
        if f and f.tool and (d in ("open", "io.open", "os.open", "os.remove", "os.unlink", "shutil.rmtree", "os.rmdir", "shutil.copy",
                                   "shutil.move", "os.listdir", "os.scandir", "aiofiles.open", "starlette.responses.FileResponse",
                                   "fastapi.responses.FileResponse", "send_file", "pathlib.Path", "Path")
                             or last in ("read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "iterdir", "open")):
            target = arg0 if d not in ("pathlib.Path", "Path") or not arg0 else arg0
            recv = node.func.value if isinstance(node.func, ast.Attribute) else None
            if (target is not None and self.tainted(target)) or (recv is not None and last in ("read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "iterdir", "open") and self.tainted(recv)):
                if not GUARD_TOKENS.search(f.src) and d not in ("pathlib.Path", "Path"):
                    write = d in ("os.remove", "os.unlink", "shutil.rmtree", "os.rmdir", "shutil.move") or last in ("write_text", "write_bytes", "unlink", "rmdir") \
                        or (d in ("open", "io.open", "aiofiles.open") and re.search(r"['\"][wax]", ast.unparse(node)))
                    self.add("SEC-005", node, f"`{d}` uses a path derived from tool input of `{f.tool}` without a base-directory check"
                             + (" (write/delete)." if write else "."), sev=Severity.high if write else Severity.high, conf="high")

    def _c_process_exit(self, node: ast.Call, c: dict) -> None:
        """Process exit."""
        d, f = c["d"], c["f"]
        if d in ("sys.exit", "os._exit", "exit", "quit") and f and self.main_guard_depth == 0 and not re.search(r"^(main|cli|run|_main|entry|serve|start)", f.name):
            self.add("REL-004", node, f"`{d}` inside `{f.name}`.", conf="high" if f.tool else "medium")

    def _c_cors(self, node: ast.Call, c: dict) -> None:
        """Cors."""
        last = c["last"]
        if last == "add_middleware" and node.args and "CORS" in ast.unparse(node.args[0]):
            src = ast.unparse(node)
            if re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]", src):
                creds = re.search(r"allow_credentials\s*=\s*True", src)
                self.add("SEC-011", node, "CORS allows any origin" + (" with credentials." if creds else "."),
                         sev=Severity.high if creds else None, conf="high")

    def _c_fan_out(self, node: ast.Call, c: dict) -> None:
        """Fan-out."""
        d = c["d"]
        if d == "asyncio.gather" and any(isinstance(a, ast.Starred) for a in node.args) and "Semaphore" not in self.sf.text:
            self.add("SCL-007", node, "asyncio.gather over a dynamic collection without a semaphore.", conf="medium")

    def _c_debug_flags(self, node: ast.Call, c: dict) -> None:
        """Debug flags."""
        d, last = c["d"], c["last"]
        dbg = self.kw(node, "debug")
        if isinstance(dbg, ast.Constant) and dbg.value is True and last in ("run", "FastAPI", "Flask", "Starlette", "FastMCP", "Quart"):
            self.add("SEC-013", node, f"`debug=True` passed to `{d}`.", conf="high")

    def _c_sqlite_pickle_file_state(self, node: ast.Call, c: dict) -> None:
        """Sqlite / pickle file state."""
        d, arg0 = c["d"], c["arg0"]
        if d in ("sqlite3.connect", "shelve.open") and not self.sf.is_test:
            a = ast.unparse(arg0) if arg0 is not None else ""
            if ":memory:" not in a:
                self.add("SCL-008", node, f"Local file state via `{d}`.", conf="medium")

    CALL_CHECKS: list = []   # filled after the class body

    def _awaited(self, node: ast.Call) -> bool:
        # `await x()` puts the Call under an Await node; we don't keep parents, so check source text
        line = self.sf.line(node.lineno)
        return "await " in line and line.find("await ") < line.find(self.dotted(node.func).split(".")[-1])

    # ------------------------------------------------------------------ per-tool checks
    def _tool_checks(self, f: _Func):
        node = f.node
        untyped = [a.arg for a in node.args.args + node.args.kwonlyargs
                   if a.arg not in ("self", "cls", "ctx", "context") and (a.annotation is None or re.fullmatch(r"(Any|dict|Dict|object|typing\.Any)", ast.unparse(a.annotation)))]
        if untyped:
            self.ctx.add("REL-006", self.sf, node.lineno, message=f"Tool `{f.tool}`: untyped/permissive parameters {', '.join(untyped)}.",
                         source="ast", tool=f.tool, confidence="high")
        # returns raw external content (indirect prompt injection)
        if re.search(r"(requests\.|httpx|aiohttp|urlopen|fetch|imaplib|exchangelib|get_message|read_email|confluence|jira|\.download)", f.src) and \
                re.search(r"return\s+[^\n]*(\.text\b|\.content\b|\.read\(\)|get_text\(|markdownify|html2text|\.body\b)", f.src):
            self.ctx.add("SEC-019", self.sf, node.lineno, message=f"Tool `{f.tool}` returns fetched external content verbatim.",
                         source="ast", tool=f.tool, confidence="medium")


PyAnalyzer.CALL_CHECKS = [PyAnalyzer._c_command_injection, PyAnalyzer._c_dynamic_evaluation, PyAnalyzer._c_sql, PyAnalyzer._c_deserialization, PyAnalyzer._c_tls, PyAnalyzer._c_weak_crypto, PyAnalyzer._c_xml, PyAnalyzer._c_jwt, PyAnalyzer._c_logging_secrets, PyAnalyzer._c_stdout_in_stdio_servers, PyAnalyzer._c_ssrf_timeouts_blocking, PyAnalyzer._c_per_call_connections, PyAnalyzer._c_loops, PyAnalyzer._c_unbounded_reads, PyAnalyzer._c_unsafe_archives_temp, PyAnalyzer._c_path_traversal, PyAnalyzer._c_process_exit, PyAnalyzer._c_cors, PyAnalyzer._c_fan_out, PyAnalyzer._c_debug_flags, PyAnalyzer._c_sqlite_pickle_file_state]


def analyze_python(ctx: Ctx) -> None:
    for sf in ctx.ws.by_language("python"):
        if sf.is_test and not ctx.options.include_tests:
            continue
        try:
            tree = ast.parse(sf.text, filename=sf.rel)
        except SyntaxError:
            continue
        PyAnalyzer(ctx, sf, tree).visit(tree)
