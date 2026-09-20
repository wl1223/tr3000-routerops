from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class AuthenticationMethod(StrEnum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    AGENT = "agent"


class DeviceConnectionProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = "tr3000"
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "root"
    authentication_method: AuthenticationMethod = AuthenticationMethod.AGENT
    password: SecretStr | None = None
    private_key_path: SecretStr | None = None
    host_key_sha256: SecretStr
    firmware_expectation: str = "QWRT R26.1.1"
    model_expectation: str = "Cudy TR3000 v1"
    readonly: Literal[True] = True
    connect_timeout_seconds: int = Field(default=10, ge=1, le=30)
    command_timeout_seconds: int = Field(default=15, ge=1, le=60)
    max_output_bytes: int = Field(default=262144, ge=4096, le=1048576)

    @model_validator(mode="after")
    def validate_authentication(self) -> "DeviceConnectionProfile":
        if self.authentication_method == AuthenticationMethod.PASSWORD and self.password is None:
            raise ValueError("password authentication requires a password")
        if (
            self.authentication_method == AuthenticationMethod.PRIVATE_KEY
            and self.private_key_path is None
        ):
            raise ValueError("private-key authentication requires a private key path")
        return self

