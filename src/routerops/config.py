from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ROUTEROPS_",
        extra="ignore",
        case_sensitive=False,
    )

    mode: int = Field(default=1, ge=1, le=4)
    backend: Literal["mock"] = "mock"
    scenario: str = "healthy"
    data_dir: Path = Path("data")
    llm_enabled: bool = False
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4.1-mini"
    llm_api_key: SecretStr | None = None
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = "root"
    ssh_password: SecretStr | None = None
    ssh_private_key: SecretStr | None = None
    ssh_host_key_sha256: SecretStr | None = None
    telegram_token: SecretStr | None = None

    @field_validator("backend")
    @classmethod
    def phase_one_mock_only(cls, value: str) -> str:
        if value != "mock":
            raise ValueError("phase one only permits the mock backend")
        return value

    def ensure_directories(self) -> None:
        for name in ("devices/tr3000", "evidence", "backups", "logs"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)

