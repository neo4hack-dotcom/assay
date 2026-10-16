"""Engine behaviour on the bundled sample MCP servers."""
import time
import zipfile
from pathlib import Path

import pytest

from app.engine.context import redact
from app.engine.llm import extract_json
from app.engine.llm_review import _similar, numbers_consistent
from app.engine.models import AuditOptions, AuditResult, SourceSpec
from app.engine.pipeline import PipelineSettings, run_audit
from app.engine.llm import LlmConfig
from app.engine.workspace import IngestError, mask_url, safe_extract_zip
from conftest import SAMPLES


def audit(name: str, **ctx) -> AuditResult:
    opts = AuditOptions(use_llm=False, external_tools=[])
    for k, v in ctx.items():
        setattr(opts.context, k, v)
    a = AuditResult(id=name, project=name, created_at=time.time(), source=SourceSpec(kind="path", location=str(SAMPLES / name)), options=opts)
    return run_audit(a, PipelineSettings(work_dir=Path("/tmp"), llm=LlmConfig()))


@pytest.fixture(scope="module")
def vuln_py():
    return audit("vulnerable-python-mcp")


@pytest.fixture(scope="module")
def vuln_ts():
    return audit("vulnerable-ts-mcp")


@pytest.fixture(scope="module")
def hardened():
    return audit("hardened-python-mcp")


def rules(a):
    return {f.rule_id for f in a.findings}


def test_python_discovery(vuln_py):
    s = vuln_py.server
    assert s.detected and "streamable-http" in s.transports
    assert {t.name for t in s.tools} >= {"run_command", "fetch_url", "read_file", "calc"}
    assert next(t for t in s.tools if t.name == "run_command").risk.value == "critical"


@pytest.mark.parametrize("rule", ["SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "MCP-001",
                                  "MCP-003", "SCL-004", "REL-001", "MNT-001", "SEC-021", "SEC-022", "SEC-024"])
def test_python_rules(vuln_py, rule):
    assert rule in rules(vuln_py)


def test_taint_reaches_tool(vuln_py):
    f = next(f for f in vuln_py.findings if f.rule_id == "SEC-001")
    assert f.tool == "run_command" and f.confidence == "high"


@pytest.mark.parametrize("rule", ["SEC-001", "SEC-005", "SEC-006", "MCP-002", "MCP-012", "SCL-002", "SEC-011", "MCP-014", "SEC-027"])
def test_typescript_rules(vuln_ts, rule):
    assert rule in rules(vuln_ts)


def test_ts_tools_and_zod(vuln_ts):
    names = {t.name for t in vuln_ts.server.tools}
    assert names == {"read_file", "delete_file", "git_log", "proxy"}
    assert next(t for t in vuln_ts.server.tools if t.name == "delete_file").description.startswith("Deletes")


def test_gates_block_criticals(vuln_py):
    assert vuln_py.verdict.decision == "NO_GO" and vuln_py.verdict.readiness <= 35
    assert any("critical" in g for g in vuln_py.verdict.gates)
    assert vuln_py.actions[0].priority == "P0"


def test_hardened_is_go(hardened):
    assert hardened.verdict.decision == "GO", hardened.verdict
    assert hardened.server.auth.detected and hardened.server.stateless_http is True
    assert not [f for f in hardened.findings if f.severity.value in ("critical", "high")]


def test_context_changes_severity():
    local = audit("vulnerable-ts-mcp", deployment="local")
    f = next(f for f in local.findings if f.rule_id == "SCL-002")
    assert f.severity.value == "info" and f.context_note


def test_secrets_are_redacted_in_reports(vuln_py):
    for f in vuln_py.findings:
        if f.rule_id == "SEC-007":
            assert "9fA3kLmN0pQrStUvWxYz" not in f.snippet and "Sup3rS3cret" not in f.snippet
    assert "REDACTED" in redact('API_KEY = "sk-proj-abcdefghijklmnop1234"')


def test_fingerprints_stable_across_runs(vuln_py):
    again = audit("vulnerable-python-mcp")
    assert {f.fingerprint for f in again.findings} == {f.fingerprint for f in vuln_py.findings}


def test_zip_slip_rejected(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.txt", "x")
    with pytest.raises(IngestError):
        safe_extract_zip(z, tmp_path / "out", 10_000_000, 100)


def test_mask_url():
    assert mask_url("https://user:tok@git.corp/x.git") == "https://***@git.corp/x.git"


def test_extract_json_variants():
    assert extract_json('<think>hmm</think>```json\n{"a": 1,}\n```') == {"a": 1}
    assert extract_json('Sure! Here it is: {"v": [1, 2]} hope it helps') == {"v": [1, 2]}


def test_llm_guards():
    assert numbers_consistent("Readiness is 35% and sustainability 47%.", {35, 47})
    assert not numbers_consistent("must reach 50% first", {35, 47})
    assert _similar("Missing tool description", "Missing or weak tool description")
    assert not _similar("SQL injection", "Blocking call inside async handler")
