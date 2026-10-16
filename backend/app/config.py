"""Configuration: one class, one env prefix (ASSAY_), everything starts empty/off.

Precedence: real environment > backend/.env > defaults. LLM settings edited in
the UI are persisted to data/settings.json and override these defaults at runtime.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ASSAY_", env_file=str(BACKEND_DIR / ".env"), extra="ignore")

    app_name: str = "Assay"
    host: str = "127.0.0.1"           # local by default; set 0.0.0.0 on a server AND set auth_token
    port: int = 3101
    data_dir: str = str(BACKEND_DIR / "data")
    static_dir: str = ""              # empty => ../frontend/dist

    # Access control for the Assay UI/API itself (empty = no auth, only sensible on 127.0.0.1)
    auth_token: str = ""
    # Server-side folders that "Local path" audits may read. Empty = any folder (local use).
    allowed_roots: str = ""

    # Default LLM (OpenAI-compatible). Empty = static analysis only.
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_context_window: int = 16384
    llm_max_output_tokens: int = 1800
    llm_timeout_s: int = 180
    llm_max_concurrency: int = 2
    llm_verify_tls: bool = True
    llm_ca_bundle: str = ""

    max_parallel_audits: int = 2
    scanner_timeout_s: int = 300
    semgrep_config: str = "auto"      # or a local rules folder for air-gapped use
    policy_file: str = ""             # YAML overriding engine/policy.py thresholds
    custom_rules_dir: str = ""        # empty => <data_dir>/rules
    max_upload_mb: int = 500
    keep_workspaces: bool = False

    @property
    def data(self) -> Path:
        p = Path(self.data_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def roots(self) -> list[Path]:
        sep = ";" if ";" in self.allowed_roots else ","
        return [Path(r.strip()).expanduser().resolve() for r in self.allowed_roots.split(sep) if r.strip()]


settings = Settings()
