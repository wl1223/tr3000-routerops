from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from routerops.device import AuthenticationMethod, DeviceConnectionProfile


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ROUTEROPS_",
        extra="ignore",
        case_sensitive=False,
    )

    mode: int = Field(default=1, ge=1, le=4)
    backend: Literal["mock", "ssh", "replay"] = "mock"
    scenario: str = "healthy"
    data_dir: Path = Path("var")
    llm_enabled: bool = False
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4.1-mini"
    llm_api_key: SecretStr | None = None
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = "root"
    ssh_auth_method: AuthenticationMethod = AuthenticationMethod.AGENT
    ssh_password: SecretStr | None = None
    ssh_private_key: SecretStr | None = None
    ssh_host_key_sha256: SecretStr | None = None
    device_model_expectation: str = "Cudy TR3000 v1"
    device_firmware_expectation: str = "QWRT R26.1.1"
    fixture_capture_dir: Path | None = None
    fixture_replay_dir: Path | None = None
    telegram_token: SecretStr | None = None

    @model_validator(mode="after")
    def validate_phase_two_boundary(self) -> "Settings":
        if self.backend in {"ssh", "replay"} and self.mode != 1:
            raise ValueError("real SSH and fixture replay are restricted to MODE 1")
        if self.backend == "ssh":
            if not self.ssh_host or self.ssh_host_key_sha256 is None:
                raise ValueError("SSH backend requires host and pinned host-key SHA256")
        if self.fixture_capture_dir is not None and self.backend != "ssh":
            raise ValueError("fixture capture is available only for the SSH backend")
        if self.backend == "replay" and self.fixture_replay_dir is None:
            raise ValueError("replay backend requires a fixture replay directory")
        return self

    def ensure_directories(self) -> None:
        for name in ("devices/tr3000", "evidence", "backups", "logs"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)

    def device_profile(self) -> DeviceConnectionProfile:
        if self.backend != "ssh" or self.ssh_host is None or self.ssh_host_key_sha256 is None:
            raise ValueError("SSH device profile requested while SSH backend is disabled")
        return DeviceConnectionProfile(
            host=self.ssh_host,
            port=self.ssh_port,
            username=self.ssh_username,
            authentication_method=self.ssh_auth_method,
            password=self.ssh_password,
            private_key_path=self.ssh_private_key,
            host_key_sha256=self.ssh_host_key_sha256,
            firmware_expectation=self.device_firmware_expectation,
            model_expectation=self.device_model_expectation,
        )

