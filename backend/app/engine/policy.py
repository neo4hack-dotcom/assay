"""Thresholds that evolve over time (SDK floors, runtime end-of-life, scoring).

They live in data, not in code, so the security team can update them without a
release: drop a YAML file and point ASSAY_POLICY_FILE at it. Keys that are not
overridden keep these defaults.
"""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULT_POLICY: dict = {
    # Minimum MCP SDK versions. Older releases are affected by published advisories
    # (e.g. Python SDK < 1.10 HTTP transport DoS fixes; TypeScript SDK < 1.24 did not
    # enable DNS-rebinding protection by default). Review and raise periodically.
    "sdk_minimums": {
        "mcp": "1.10.0",
        "fastmcp": "2.10.0",
        "@modelcontextprotocol/sdk": "1.24.0",
    },
    "runtime_minimums": {"python": "3.10", "node": "22"},
    "thresholds": {
        "complexity_medium": 15,
        "complexity_high": 25,
        "large_file_loc": 1000,
        "test_ratio_low": 0.15,
        "tools_many": 25,
        "tools_too_many": 50,
        "bus_factor_share": 0.85,
        "stale_days": 365,
        "todo_per_kloc": 10,
        "short_description_chars": 25,
    },
    "dimension_weights": {
        "security": 0.35,
        "scalability": 0.15,
        "performance": 0.10,
        "reliability": 0.12,
        "observability": 0.08,
        "maintainability": 0.20,
    },
    "decision_bands": {"go": 80, "conditions": 65, "not_ready": 45},
    "score_decay": 55.0,
}


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_policy(path: str = "") -> dict:
    policy = copy.deepcopy(DEFAULT_POLICY)
    if path and Path(path).is_file():
        data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
        if isinstance(data, dict):
            _merge(policy, data)
    return policy


def parse_version(v: str) -> tuple[int, ...]:
    import re
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) if nums else ()


def lower_bound(spec: str) -> str:
    """'>=1.2,<2' -> '1.2'; '^1.4.0' -> '1.4.0'; '==1.3' -> '1.3'; 'unpinned' -> ''."""
    import re
    if not spec or spec in ("unpinned", "*", "latest"):
        return ""
    m = re.search(r"(==|>=|~=|\^|~|>)?\s*v?(\d+(?:\.\d+){0,2})", spec)
    return m.group(2) if m else ""
