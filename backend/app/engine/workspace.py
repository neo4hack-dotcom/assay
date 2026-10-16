"""Getting the code under audit onto disk — without ever executing any of it.

The code being audited is untrusted by definition. Three rules hold everywhere
in this module:
  * nothing from the source is executed (no install, no build, no git hooks);
  * archives are extracted member by member with path, size and count limits;
  * credentials embedded in a git URL never reach logs or the stored audit.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go", ".java": "java", ".kt": "kotlin", ".cs": "csharp", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    # config-like files: scanned for secrets / insecure settings only
    ".yaml": "config", ".yml": "config", ".json": "config", ".toml": "config", ".ini": "config",
    ".cfg": "config", ".properties": "config", ".conf": "config", ".env": "config", ".xml": "config",
}
LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "pipfile.lock",
                  "pdm.lock", "go.sum", "composer.lock", "cargo.lock", "gemfile.lock", "npm-shrinkwrap.json"}
CONFIG_NAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", ".env", "makefile",
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".env.d", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".nox", "dist", "build", ".next", ".nuxt", "out", "coverage",
    "htmlcov", "site-packages", "vendor", "target", ".gradle", ".idea", ".vscode", "obj", ".terraform",
    ".turbo", ".cache", "storybook-static", ".yarn", "bower_components",
}
TEST_DIR_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testing|e2e|fixtures?)(/|$)", re.I)
TEST_FILE_RE = re.compile(r"(^test_.*\.py$|.*_test\.(py|go)$|.*\.(test|spec)\.[jt]sx?$|.*Tests?\.(java|cs|kt)$|conftest\.py$)", re.I)
AUX_DIR_RE = re.compile(r"(^|/)(docs?|documentation|examples?|samples?|demos?|scripts|tools/dev|benchmarks?|playground|sandbox|notebooks?)(/|$)", re.I)
MAX_FILE_BYTES = 1_500_000
MAX_LINE_LEN_MINIFIED = 2_000


@dataclass
class SourceFile:
    rel: str
    abs: Path
    language: str
    text: str
    is_test: bool
    lines: list[str] = field(default_factory=list)
    is_aux: bool = False              # docs/examples/scripts: shipped with the repo, not part of the server

    @property
    def loc(self) -> int:
        return sum(1 for l in self.lines if l.strip())

    def line(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    def snippet(self, n: int, before: int = 2, after: int = 2) -> str:
        lo, hi = max(1, n - before), min(len(self.lines), n + after)
        return "\n".join(f"{i:>5} | {self.lines[i - 1]}" for i in range(lo, hi + 1))


@dataclass
class Workspace:
    root: Path
    files: list[SourceFile]
    other_files: list[str]          # every relative path seen (configs, docs, keys...)
    skipped: int
    commit: str = ""

    def by_language(self, *langs: str) -> list[SourceFile]:
        return [f for f in self.files if f.language in langs]

    def get(self, rel: str) -> SourceFile | None:
        for f in self.files:
            if f.rel == rel:
                return f
        return None

    def exists(self, pattern: str) -> list[str]:
        rx = re.compile(pattern, re.I)
        return [p for p in self.other_files if rx.search(p)]

    def read(self, rel: str, limit: int = 400_000) -> str:
        p = (self.root / rel).resolve()
        if self.root not in p.parents and p != self.root:
            return ""
        try:
            return p.read_text("utf-8", errors="replace")[:limit]
        except OSError:
            return ""


class IngestError(RuntimeError):
    pass


def mask_url(url: str) -> str:
    """https://user:token@host/x -> https://***@host/x"""
    return re.sub(r"(?<=://)[^/@\s]+@", "***@", url)


def safe_extract_zip(zip_path: Path, dest: Path, max_bytes: int, max_files: int) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()
        if len(members) > max_files:
            raise IngestError(f"Archive has {len(members)} entries (limit {max_files}).")
        for m in members:
            name = m.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            # Symlinks in zips are encoded in the external attributes; never materialise them.
            if stat.S_ISLNK(m.external_attr >> 16):
                continue
            target = (dest_root / name).resolve()
            if dest_root not in target.parents:
                raise IngestError(f"Archive entry escapes the extraction folder: {name!r}")
            total += m.file_size
            if total > max_bytes:
                raise IngestError(f"Archive expands beyond {max_bytes // 1_000_000} MB.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(m) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
    # A zip of a single top-level folder is the common case: descend into it.


def unwrap_single_dir(root: Path) -> Path:
    entries = [e for e in root.iterdir() if not e.name.startswith(("__MACOSX", "."))]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def git_clone(url: str, dest: Path, ref: str = "", timeout: int = 300) -> None:
    if not shutil.which("git"):
        raise IngestError("git is not installed on this machine — upload a ZIP or use a local path instead.")
    if not re.match(r"^(https?://|ssh://|git@)[\w.@:/~+-]+$", url):
        raise IngestError("Unsupported git URL. Use https://, ssh:// or git@host:org/repo.")
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",          # never hang on a credential prompt
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    hooks_off = "NUL" if os.name == "nt" else "/dev/null"
    cmd = [
        "git", "-c", f"core.hooksPath={hooks_off}", "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never", "-c", "core.symlinks=false", "-c", "submodule.recurse=false",
        "clone", "--no-tags", "--single-branch", "--depth", "200",
    ]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, str(dest)]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise IngestError(f"git clone timed out after {timeout}s") from e
    if proc.returncode != 0:
        err = mask_url(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "unknown error")
        raise IngestError(f"git clone failed: {err}")


def git_head(root: Path) -> str:
    if not (root / ".git").exists() or not shutil.which("git"):
        return ""
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=15)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def is_test_path(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return bool(TEST_DIR_RE.search(rel.rsplit("/", 1)[0] if "/" in rel else "") or TEST_FILE_RE.match(name))


def scan_tree(root: Path, extra_skip: set[str] | None = None, max_files: int = 20_000) -> Workspace:
    root = root.resolve()
    skip = SKIP_DIRS | (extra_skip or set())
    files: list[SourceFile] = []
    others: list[str] = []
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            ap = Path(dirpath) / fn
            rel = ap.relative_to(root).as_posix()
            others.append(rel)
            if ap.is_symlink():
                skipped += 1
                continue
            ext = ap.suffix.lower()
            lang = LANG_BY_EXT.get(ext)
            low = fn.lower()
            if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
                lang = "dockerfile"
            elif low == ".env" or low.startswith(".env."):
                lang = "config"
            if low in LOCKFILE_NAMES:
                continue
            if not lang:
                continue
            if fn.endswith((".min.js", ".bundle.js", ".d.ts")) or ".min." in fn:
                skipped += 1
                continue
            try:
                if ap.stat().st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                text = ap.read_text("utf-8", errors="replace")
            except OSError:
                skipped += 1
                continue
            lines = text.splitlines()
            if lines and max(len(l) for l in lines[:50]) > MAX_LINE_LEN_MINIFIED:
                skipped += 1           # generated / minified
                continue
            is_test = is_test_path(rel)
            files.append(SourceFile(rel=rel, abs=ap, language=lang, text=text, lines=lines, is_test=is_test,
                                    is_aux=not is_test and bool(AUX_DIR_RE.search(rel.rsplit("/", 1)[0] if "/" in rel else ""))))
            if len(files) >= max_files:
                break
    return Workspace(root=root, files=files, other_files=others, skipped=skipped, commit=git_head(root))
