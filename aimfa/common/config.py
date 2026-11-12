"""Runtime configuration, loaded from environment variables / `.env`.

Every tunable lives here so tests can build a Settings object with overrides
(e.g. a 2-second token TTL) instead of monkeypatching modules.
See .env.example for documentation of each value.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from aimfa.common.models import Mode

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policy"


class Settings(BaseSettings):
    # Absolute path: the repo-root .env is found no matter which folder a script is run
    # from (e.g. VS Code's Run button uses the script's own folder as the cwd).
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    aimfa_mode: Mode = Mode.AIMFA

    control_plane_url: str = "http://127.0.0.1:8000"
    gateway_url: str = "http://127.0.0.1:8100"
    resources_url: str = "http://127.0.0.1:8200"
    dashboard_url: str = "http://127.0.0.1:8501"

    # SecretStr keeps secrets out of reprs/logs. Use .get_secret_value() only at the
    # point of comparison, and compare with hmac.compare_digest (constant time).
    admin_api_key: SecretStr = SecretStr("change-me-admin")
    internal_service_secret: SecretStr = SecretStr("change-me-internal")
    gateway_resource_secret: SecretStr = SecretStr("change-me-resources")
    baseline_api_key: SecretStr = SecretStr("change-me-baseline")

    data_dir: Path = REPO_ROOT / "var"
    keys_dir: Path = REPO_ROOT / "keys"
    policy_dir: Path = POLICY_DIR

    identity_token_ttl_seconds: int = 3600
    access_token_ttl_seconds: int = 900
    dpop_max_age_seconds: int = 60
    attest_nonce_ttl_seconds: int = 60
    approval_timeout_seconds: int = 300

    risk_step_up_threshold: float = 50
    risk_revoke_threshold: float = 80
    risk_decay_per_minute: float = 5

    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_enabled: bool = True

    tamu_ai_base_url: str = "https://chat-api.tamu.ai/openai"
    tamu_ai_api_key: SecretStr = SecretStr("")
    tamu_ai_model: str = ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "aimfa.db"


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings. Tests should construct Settings(...) directly instead."""
    return Settings()
