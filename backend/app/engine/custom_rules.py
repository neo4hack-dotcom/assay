"""Organisation-specific rules without code changes.

Drop YAML files in the custom rules folder (ASSAY_CUSTOM_RULES_DIR, default
data/rules). Each file holds a list of rules:

    - id: ORG-001
      title: Internal API called without the corporate gateway
      dimension: security          # security|scalability|performance|reliability|observability|maintainability
      severity: high               # critical|high|medium|low|info
      languages: [python, typescript, javascript]
      pattern: 'https?://api\\.internal\\.example'
      message: Calls must go through the API gateway.
      remediation: Use the GATEWAY_URL configuration value.
      in_tool_only: false

Rules are registered in the catalog so they appear in reports, SARIF and the UI.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from . import catalog
from .context import Ctx
from .models import Dimension, Severity


def load_custom_rules(folder: str) -> list[dict]:
    if not folder or not Path(folder).is_dir():
        return []
    rules: list[dict] = []
    for p in sorted(Path(folder).glob("*.y*ml")):
        try:
            data = yaml.safe_load(p.read_text("utf-8")) or []
        except yaml.YAMLError:
            continue
        for r in data if isinstance(data, list) else []:
            if not isinstance(r, dict) or not r.get("id") or not r.get("pattern"):
                continue
            try:
                r["_rx"] = re.compile(r["pattern"], re.I if r.get("ignore_case", True) else 0)
                dim = Dimension(r.get("dimension", "security"))
                sev = Severity(r.get("severity", "medium"))
            except (re.error, ValueError):
                continue
            catalog.RULES[r["id"]] = catalog.Rule(
                id=r["id"], title=r.get("title", r["id"]), dimension=dim, severity=sev,
                description=r.get("description", r.get("message", "Organisation rule.")), impact=r.get("impact", ""),
                remediation=r.get("remediation", ""), effort=r.get("effort", "M"), tags=["custom"])
            rules.append(r)
    return rules


def run_custom_rules(ctx: Ctx, folder: str) -> None:
    for r in load_custom_rules(folder):
        langs = set(r.get("languages") or [])
        for sf in ctx.ws.files:
            if (langs and sf.language not in langs) or (sf.is_test and not ctx.options.include_tests):
                continue
            for i, line in enumerate(sf.lines, 1):
                if r["_rx"].search(line) and (not r.get("in_tool_only") or ctx.in_tool(sf.rel, i)):
                    ctx.add(r["id"], sf, i, message=r.get("message", ""), source="custom", confidence=r.get("confidence", "medium"))
