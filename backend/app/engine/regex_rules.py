"""Line-oriented checks for every language (and the only checks for non-Python code).

Each pattern is deliberately narrow: a noisy auditor gets ignored. Patterns that
are only meaningful inside a tool handler declare `in_tool=True`, and file-level
guards (e.g. "this file never sets a timeout") are expressed as `unless_file`.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .context import Ctx
from .models import Severity

JS = ("typescript", "javascript")
ALL_CODE = ("python", "typescript", "javascript", "go", "java", "kotlin", "csharp", "rust", "ruby", "php", "shell", "powershell")

PLACEHOLDER = re.compile(r"(^\$\{|^\{\{|^<|^\*+$|x{4,}|changeme|change_me|example|placeholder|dummy|sample|your[_-]|my[_-]?(secret|token|key|password)|^test|fake|redacted|^none$|^null$|^password$|^secret$|^pass$|\.\.\.|^env\b|os\.environ|process\.env|getenv|^\w+_(KEY|TOKEN|SECRET)$|^sk-\.\.\.|^sk-x+|^(sk-)?(1234|abcd)|not[-_ ]?(needed|required|used|set)|unused|no[-_]?key|^anything|^ollama|^lm-?studio|^local\b)", re.I)
LOWER_WORDS = re.compile(r"^[a-z][a-z_-]*$")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(v / len(s) * math.log2(v / len(s)) for v in freq.values())


@dataclass
class LineRule:
    rule: str
    pattern: re.Pattern
    langs: tuple[str, ...]
    message: str
    severity: Severity | None = None
    confidence: str = "medium"
    in_tool: bool = False
    unless_file: re.Pattern | None = None
    only_if_file: re.Pattern | None = None
    include_comments: bool = False
    include_tests: bool = False
    validator: object = None          # callable(match) -> bool
    once_per_file: bool = False
    skip_files: re.Pattern | None = None
    extra: dict = field(default_factory=dict)


def _secret_ok(m: re.Match) -> bool:
    val = m.group("val") if "val" in m.groupdict() and m.group("val") else m.group(0)
    if PLACEHOLDER.search(val) or LOWER_WORDS.match(val):
        return False
    return entropy(val) >= 3.0 and len(set(val)) > 5


def _generic_secret_ok(m: re.Match) -> bool:
    """Generic `password = "..."` hits: also require secret-like shape (a digit, or mixed case and length)."""
    val = m.group("val")
    if not _secret_ok(m):
        return False
    if re.search(r"\s|\{|\}|\$|%s|%\(|^https?://|\.(json|ya?ml|txt|pem|key)$", val):
        return False
    return bool(re.search(r"\d", val)) or (re.search(r"[a-z]", val) and re.search(r"[A-Z]", val) and len(val) >= 12)


def _conn_ok(m: re.Match) -> bool:
    pwd = m.group("pwd")
    return not PLACEHOLDER.search(pwd) and not re.fullmatch(r"[\w]*(pass|pwd|password)[\w]*", pwd, re.I) and pwd not in ("user", "root")


R = re.compile
SECRET_RULES = [
    LineRule("SEC-007", R(r"\bAKIA[0-9A-Z]{16}\b"), ALL_CODE + ("config", "dockerfile"), "AWS access key ID.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"), ALL_CODE + ("config",), "Private key material.", Severity.critical, "high",
             include_comments=True, include_tests=True, validator=lambda m: not re.search(r"REDACTED|\[A-Z|\\s|\(\?", m.string)),
    LineRule("SEC-007", R(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), ALL_CODE + ("config", "dockerfile"), "GitHub token.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), ALL_CODE + ("config", "dockerfile"), "GitLab token.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), ALL_CODE + ("config",), "Slack token.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"\b(?P<val>sk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{24,})\b"), ALL_CODE + ("config", "dockerfile"), "LLM provider API key (OpenAI/Anthropic style).", Severity.critical, "high", include_comments=True, include_tests=True, validator=_secret_ok),
    LineRule("SEC-007", R(r"\bAIza[0-9A-Za-z_-]{35}\b"), ALL_CODE + ("config",), "Google API key.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b"), ALL_CODE + ("config",), "Stripe live key.", Severity.critical, "high", include_comments=True, include_tests=True),
    LineRule("SEC-007", R(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), ALL_CODE + ("config",), "Hard-coded JWT.", Severity.high, "medium", include_tests=True),
    LineRule("SEC-007", R(r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|sqlserver|oracle|clickhouse)://[^:/\s\"'@]+:(?P<pwd>[^@\s\"'/]{3,})@"), ALL_CODE + ("config", "dockerfile"), "Connection string with an embedded password.", Severity.high, "high", validator=_conn_ok, include_tests=False),
    LineRule("SEC-007", R(r"""(?i)\b(?<![-"'/])(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|bearer[_-]?token|secret[_-]?key)\b["']?\s*[:=]\s*(?:r|b)?["'](?P<val>[^"'\s]{8,})["']"""),
             ALL_CODE + ("config", "dockerfile"), "Credential assigned from a string literal.", Severity.high, "medium", validator=_generic_secret_ok),
    LineRule("SEC-007", R(r"""(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*["']?(?P<val>[^"'\s#]{8,})"""),
             ("config", "shell", "dockerfile"), "Credential value in a configuration/env file.", Severity.high, "medium", validator=_secret_ok),
]

LINE_RULES = SECRET_RULES + [
    # ---- command / code injection (non-Python; Python uses the AST)
    LineRule("SEC-001", R(r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^'\"`)\s][^)]*|['\"][^'\"]*['\"]\s*\+)"), JS, "child_process exec with a dynamic command string.",
             only_if_file=R(r"child_process|shelljs|['\"]execa['\"]")),
    LineRule("SEC-001", R(r"\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true"), JS, "spawn with shell: true.", Severity.high,
             only_if_file=R(r"child_process")),
    LineRule("SEC-001", R(r"exec\.Command(Context)?\(\s*(ctx\s*,\s*)?\"(sh|bash|cmd|powershell)\"\s*,\s*\"(-c|/c|-Command)\""), ("go",), "Shell invocation via exec.Command(\"sh\", \"-c\", ...)."),
    LineRule("SEC-001", R(r"Runtime\.getRuntime\(\)\.exec\(|new ProcessBuilder\([^)]*(\+|String\.format)"), ("java", "kotlin"), "Process execution with dynamic arguments."),
    LineRule("SEC-001", R(r"Process\.Start\(\s*[^\"\s)][^)]*\)|FileName\s*=\s*\"(cmd|cmd\.exe|powershell|bash)\""), ("csharp",), "Process execution with dynamic arguments.", Severity.high),
    LineRule("SEC-002", R(r"(?<![\w.])eval\s*\(\s*[^)'\"`\s]"), JS, "eval() on a dynamic value."),
    LineRule("SEC-002", R(r"new\s+Function\s*\("), JS, "new Function() compiles code at runtime."),
    LineRule("SEC-002", R(r"\bvm\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\("), JS, "Node `vm` is not a security sandbox."),
    # ---- SQL injection
    LineRule("SEC-003", R(r"\.(query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|exec)\s*\(\s*`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|WITH|FROM|WHERE)\b[^`]*\$\{", re.I), JS, "SQL template literal with interpolation."),
    LineRule("SEC-003", R(r"\.(query|execute|raw)\s*\(\s*['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^'\"]*['\"]\s*\+", re.I), JS, "SQL concatenated with a variable."),
    LineRule("SEC-003", R(r"\$queryRawUnsafe|\$executeRawUnsafe|sequelize\.query\(\s*`[^`]*\$\{|knex\.raw\(\s*`[^`]*\$\{"), JS, "Unsafe raw query API."),
    LineRule("SEC-003", R(r"\.(Query|Exec|QueryRow|QueryContext|ExecContext)\(\s*(ctx\s*,\s*)?fmt\.Sprintf\("), ("go",), "SQL built with fmt.Sprintf."),
    LineRule("SEC-003", R(r"(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\(\s*\"[^\"]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^\"]*\"\s*\+", re.I), ("java", "kotlin"), "SQL concatenated with a variable."),
    LineRule("SEC-003", R(r"(SqlCommand|ExecuteSqlRaw|FromSqlRaw)\(\s*(\$\"|\"[^\"]*\"\s*\+)"), ("csharp",), "SQL built by interpolation/concatenation."),
    # ---- deserialization
    LineRule("SEC-004", R(r"require\(\s*['\"]node-serialize['\"]\)|\bunserialize\s*\("), JS, "node-serialize / unserialize executes embedded functions."),
    LineRule("SEC-004", R(r"new\s+ObjectInputStream\s*\(|XMLDecoder\s*\("), ("java", "kotlin"), "Java native deserialization."),
    LineRule("SEC-004", R(r"BinaryFormatter|NetDataContractSerializer|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects)"), ("csharp",), "Unsafe .NET deserializer."),
    # ---- filesystem / SSRF reachable from tool input (JS)
    LineRule("SEC-005", R(r"\b(fs\.|fsp\.|fs\.promises\.|promises\.)?(readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|unlinkSync|rm|rmSync|rmdir|createReadStream|createWriteStream|readdir|readdirSync|copyFile|rename)\s*\(\s*(?!['\"`])[A-Za-z_][\w.\[\]'\"]*"),
             JS, "File system access with a dynamic path inside a tool handler.", Severity.high, in_tool=True,
             unless_file=R(r"(path\.resolve|realpath)[\s\S]{0,4000}startsWith|isWithin|isInside|allowedDirectories|allowedRoots|validatePath|assertInside|safePath")),
    LineRule("SEC-006", R(r"\b(fetch|axios(\.(get|post|put|patch|delete|request))?|got|request|ky|undici\.request)\s*\(\s*(?!['\"])[A-Za-z_`][^,)]*"),
             JS, "Outbound HTTP request to a dynamic URL inside a tool handler.", Severity.high, in_tool=True,
             unless_file=R(r"allow(ed)?(Hosts|Domains|Urls|List)|allowlist|whitelist|new URL\([^)]*\)\.(hostname|host)|isPrivate|ipaddr", re.I)),
    LineRule("SEC-006", R(r"http\.(Get|Post|Head)\(\s*[a-zA-Z_]"), ("go",), "Outbound HTTP request to a dynamic URL inside a tool handler.", Severity.high, in_tool=True),
    # ---- TLS
    LineRule("SEC-008", R(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0|strictSSL\s*:\s*false"), JS + ("config", "shell", "dockerfile"), "TLS certificate verification disabled."),
    LineRule("SEC-008", R(r"InsecureSkipVerify\s*:\s*true"), ("go",), "TLS certificate verification disabled."),
    LineRule("SEC-008", R(r"ServerCertificateCustomValidationCallback\s*=|DangerousAcceptAnyServerCertificateValidator"), ("csharp",), "TLS certificate verification overridden."),
    LineRule("SEC-008", R(r"TrustAllCerts|X509TrustManager[\s\S]{0,40}\{|NoopHostnameVerifier|setHostnameVerifier\(\s*\(.*\)\s*->\s*true"), ("java", "kotlin"), "Trust-all TLS configuration."),
    LineRule("SEC-008", R(r"\bcurl\s+[^\n|]*(-k\b|--insecure)|wget\s+[^\n|]*--no-check-certificate"), ("shell", "dockerfile", "powershell"), "Insecure download (certificate check disabled)."),
    LineRule("SEC-008", R(r"ssl\s*\.\s*CERT_NONE|check_hostname\s*=\s*False"), ("python",), "TLS verification disabled.", Severity.high, "high"),
    # ---- weak crypto / randomness
    LineRule("SEC-009", R(r"createHash\(\s*['\"](md5|sha1)['\"]|createCipheriv\(\s*['\"](des|des-ede3|rc4|bf|aes-\d+-ecb)", re.I), JS, "Weak hash/cipher."),
    LineRule("SEC-009", R(r"\b(md5|sha1)\.(New|Sum)\(|des\.NewCipher|rc4\.NewCipher"), ("go",), "Weak hash/cipher."),
    LineRule("SEC-009", R(r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|Cipher\.getInstance\(\s*\"(DES|RC4|AES/ECB)"), ("java", "kotlin"), "Weak hash/cipher."),
    LineRule("SEC-009", R(r"\b(MD5|SHA1)\.Create\(|new\s+(MD5|SHA1)CryptoServiceProvider|CipherMode\.ECB"), ("csharp",), "Weak hash/cipher."),
    LineRule("SEC-009", R(r"\bDES\.new\(|ARC4\.new\(|MODE_ECB"), ("python",), "Weak cipher or ECB mode.", confidence="high"),
    LineRule("SEC-010", R(r"Math\.random\(\)[^\n]*|[^\n]*(token|secret|session|password|nonce|otp|apiKey|api_key|salt)[^\n]*Math\.random\(\)", re.I), JS, "Math.random() used for a security-sensitive value.",
             validator=lambda m: re.search(r"(token|secret|session|password|nonce|otp|apikey|api_key|salt)", m.group(0), re.I) is not None),
    # ---- CORS / binding / debug
    LineRule("SEC-011", R(r"\bcors\(\s*\)|origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true\b|Access-Control-Allow-Origin['\"]?\s*,\s*['\"]\*"), JS, "CORS allows any origin."),
    LineRule("SEC-011", R(r"AllowAnyOrigin\(\)|SetIsOriginAllowed\(\s*_\s*=>\s*true"), ("csharp",), "CORS allows any origin."),
    LineRule("SEC-011", R(r"@CrossOrigin\(\s*(origins\s*=\s*)?\"\*\"|allowedOrigins\(\s*\"\*\""), ("java", "kotlin"), "CORS allows any origin."),
    LineRule("SEC-012", R(r"""(host|hostname|bind|HOST|BIND_ADDRESS|listen_addr)\s*[:=]\s*["'](0\.0\.0\.0|::|\[::\])["']|\.listen\(\s*\w+\s*,\s*['"]0\.0\.0\.0['"]|--host[= ]0\.0\.0\.0"""),
             ALL_CODE + ("config",), "Listens on all interfaces.", skip_files=R(r"(^|/)(docker-compose|compose)\.ya?ml$|Dockerfile", re.I)),
    LineRule("SEC-013", R(r"""^\s*DEBUG\s*=\s*True\b|['"]?debug['"]?\s*:\s*true\b|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|NODE_ENV['"]?\s*[:=]\s*['"]development"""),
             ("python",) + JS + ("config",), "Debug mode enabled.", skip_files=R(r"(tsconfig|package|\.eslintrc|launch|settings)\.json$|vite\.config|jest\.config", re.I)),
    # ---- JWT
    LineRule("SEC-015", R(r"\bjwt\.decode\s*\("), JS, "jwt.decode() does not verify the signature — use jwt.verify().", unless_file=R(r"jwt\.verify\s*\(|jwtVerify\s*\(")),
    LineRule("SEC-015", R(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]|ignoreExpiration\s*:\s*true", re.I), JS, "JWT verification weakened."),
    LineRule("SEC-015", R(r"""verify_signature['"]?\s*:\s*False|options\s*=\s*\{[^}]*["']verify_exp["']\s*:\s*False"""), ("python",), "JWT verification disabled.", confidence="high"),
    LineRule("MCP-015", R(r"\bjwt\.verify\s*\(|jwtVerify\s*\("), JS, "Token verified without an audience constraint.", unless_file=R(r"audience\s*:")),
    # ---- secrets in logs (JS)
    LineRule("SEC-016", R(r"console\.(log|info|debug|warn|error)\([^)]*\b(password|passwd|secret|apiKey|api_key|accessToken|access_token|authorization|bearer|clientSecret)\b(?!\s*(Count|Length|_count|\.length))", re.I), JS, "Credential-like value written to logs."),
    LineRule("SEC-016", R(r"(logger|log|logging)\.\w+\([^)]*\b(password|passwd|secret|apiKey|accessToken|authorization|bearer)\b", re.I), ("go", "java", "kotlin", "csharp"), "Credential-like value written to logs."),
    # ---- supply chain in scripts
    LineRule("SEC-024", R(r"(curl|wget|iwr|Invoke-WebRequest)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*iex\b|Invoke-Expression\s*\(\s*\(?\s*(New-Object\s+Net\.WebClient|iwr)", re.I),
             ("shell", "dockerfile", "powershell", "config", "javascript", "typescript", "python"), "Remote script piped into a shell."),
    # ---- MCP specifics
    LineRule("MCP-002", R(r"""["']?[Aa]uthorization["']?\s*[:=]\s*(req|request|ctx|context|extra|incoming|headers)\b[\w.\[\]'"()]*(authorization|headers\[|headers\.get|authInfo\.token|\.token)""", re.I),
             ALL_CODE, "Incoming Authorization header/token forwarded to a downstream call.", Severity.high),
    LineRule("MCP-002", R(r"""headers\s*[:=]\s*(req|request)\.headers\b|headers\s*=\s*dict\(\s*request\.headers|\*\*request\.headers|\.\.\.req\.headers"""),
             ALL_CODE, "All incoming headers (including Authorization) forwarded downstream.", Severity.high, confidence="medium"),
    LineRule("MCP-012", R(r"sessionIdGenerator\s*:\s*\(\)\s*=>\s*[^,}\n]*(Math\.random|Date\.now|\+\+|counter|nextId)"), JS, "Predictable MCP session id generator.", Severity.high, "high"),
    LineRule("SCL-002", R(r"(transports|sessions)\s*(:\s*[^=]+)?=\s*(\{\}|new Map\b)|\[\s*sessionId\s*\]\s*=\s*transport|transports\.set\(\s*\w+\s*,\s*transport"), JS, "Session transports kept in a process-local map (stateful mode).", once_per_file=True),
    # ---- reliability / performance (JS)
    LineRule("REL-001", R(r"\baxios(\.(get|post|put|patch|delete|request))?\s*\("), JS, "axios call with no timeout configured in this file.", unless_file=R(r"timeout\s*:"), once_per_file=True),
    LineRule("REL-001", R(r"(?<![\w.])fetch\s*\("), JS, "fetch() without AbortSignal/timeout in this file.", unless_file=R(r"AbortSignal\.timeout|AbortController|signal\s*:|timeout\s*:"), once_per_file=True, confidence="medium"),
    LineRule("REL-001", R(r"http\.(Get|Post|Head|PostForm)\(|&http\.Client\{\s*\}|http\.DefaultClient"), ("go",), "Go default HTTP client has no timeout.", unless_file=R(r"Timeout\s*:")),
    LineRule("REL-002", R(r"catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}"), JS + ("java", "kotlin", "csharp"), "Empty catch block."),
    LineRule("REL-002", R(r"if\s+err\s*!=\s*nil\s*\{\s*\}|_\s*=\s*err\b"), ("go",), "Error ignored."),
    LineRule("REL-004", R(r"\bprocess\.exit\s*\("), JS, "process.exit() inside a tool handler.", in_tool=True),
    LineRule("REL-004", R(r"\bos\.Exit\(|log\.Fatal"), ("go",), "Process exit inside a tool handler.", in_tool=True),
    LineRule("SCL-004", R(r"\b(readFileSync|writeFileSync|execSync|spawnSync|execFileSync|readdirSync|statSync|appendFileSync)\s*\("), JS, "Synchronous I/O blocks the Node.js event loop for all requests.", Severity.medium, in_tool=True),
    LineRule("SCL-007", R(r"Promise\.all\(\s*\w+\.map\("), JS, "Promise.all over a dynamic list without a concurrency limit.", unless_file=R(r"p-limit|pLimit|p-map|Bottleneck|concurrency")),
    LineRule("PRF-003", R(r"JSON\.stringify\([^)]*,\s*(null|undefined)\s*,\s*\d"), JS, "Pretty-printed JSON returned from a tool.", in_tool=True),
    LineRule("PRF-004", R(r"Thread\.sleep\(|time\.Sleep\(|Task\.Delay\(\s*\d{4,}|Atomics\.wait\("), ("java", "kotlin", "go", "csharp", "javascript", "typescript"), "Blocking sleep in a tool handler.", in_tool=True),
    LineRule("REL-005", R(r"\bconsole\.(log|info|debug)\s*\("), JS, "console.log writes to stdout, which carries the JSON-RPC stream in stdio mode.", Severity.high,
             only_if_file=R(r"StdioServerTransport|transportType\s*:\s*['\"]stdio")),
    LineRule("REL-005", R(r"\bfmt\.Print(ln|f)?\("), ("go",), "fmt.Print writes to stdout, which carries the JSON-RPC stream in stdio mode.", Severity.high,
             only_if_file=R(r"ServeStdio|StdioTransport")),
    LineRule("REL-005", R(r"System\.out\.print"), ("java", "kotlin"), "System.out writes to stdout, which carries the JSON-RPC stream in stdio mode.", Severity.high,
             only_if_file=R(r"StdioServerTransportProvider")),
    LineRule("REL-005", R(r"Console\.Write(Line)?\("), ("csharp",), "Console.Write writes to stdout, which carries the JSON-RPC stream in stdio mode.", Severity.high,
             only_if_file=R(r"WithStdioServerTransport")),
    # ---- maintainability
    LineRule("MNT-013", R(r"""["'`](https?://)?(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(:\d+)?|["'`]https?://[\w.-]+\.(internal|corp|intra|intranet|lan|local)\b"""),
             ALL_CODE, "Environment-specific address hard-coded.", confidence="medium"),
]

COMMENT_PREFIX = re.compile(r"^\s*(#|//|\*|/\*|--|<!--|')")


def analyze_lines(ctx: Ctx) -> None:
    for sf in ctx.ws.files:
        rules = [r for r in LINE_RULES if sf.language in r.langs]
        if not rules:
            continue
        rules = [r for r in rules
                 if (r.include_tests or not sf.is_test or ctx.options.include_tests)
                 and not (r.only_if_file and not r.only_if_file.search(sf.text))
                 and not (r.unless_file and r.unless_file.search(sf.text))
                 and not (r.skip_files and r.skip_files.search(sf.rel))]
        if not rules:
            continue
        if sf.language == "python":
            # Python dangerous calls are covered by the AST pass; avoid duplicate line hits
            rules = [r for r in rules if r.rule not in ("SEC-001", "SEC-002", "SEC-003", "SEC-004")]
        done_once: set[str] = set()
        in_block_comment = False
        in_docstring = False
        for i, line in enumerate(sf.lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            is_comment = bool(COMMENT_PREFIX.match(line)) or in_block_comment or in_docstring
            if sf.language in JS + ("java", "kotlin", "csharp", "go"):
                if "/*" in stripped and "*/" not in stripped:
                    in_block_comment = True
                elif "*/" in stripped:
                    in_block_comment = False
            if sf.language == "python":
                q = stripped.count('"""') + stripped.count("'''")
                if q % 2 == 1:
                    in_docstring = not in_docstring
                    is_comment = True
            if len(line) > 1000:
                continue
            for r in rules:
                if is_comment and not r.include_comments:
                    continue
                if r.once_per_file and r.rule + r.message in done_once:
                    continue
                m = r.pattern.search(line)
                if not m:
                    continue
                if r.validator and not r.validator(m):
                    continue
                tool = ctx.tool_at(sf.rel, i)
                if r.in_tool and not tool:
                    continue
                sev = r.severity
                if r.rule == "SEC-007" and sf.is_test:
                    sev = Severity.low
                ctx.add(r.rule, sf, i, message=r.message + (" (test file)" if sf.is_test and r.rule == "SEC-007" else ""),
                        severity=sev, confidence=("high" if tool and r.confidence == "medium" else r.confidence), source="static")
                if r.once_per_file:
                    done_once.add(r.rule + r.message)
