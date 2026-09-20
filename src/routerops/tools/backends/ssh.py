import base64
import hashlib
from typing import Any

import paramiko

from routerops.device import AuthenticationMethod, DeviceConnectionProfile
from routerops.tools.backends.ssh_commands import ReadonlyCommandRegistry
from routerops.tools.normalizers import RawObservation, normalize_observation


class SSHConnectionError(RuntimeError):
    pass


class HostKeyMismatchError(SSHConnectionError):
    def __init__(self) -> None:
        super().__init__("HOST_KEY_MISMATCH")


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return base64.b64encode(digest).decode().rstrip("=")


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str) -> None:
        self.expected = expected.removeprefix("SHA256:").rstrip("=")

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        del client, hostname
        if _fingerprint(key) != self.expected:
            raise HostKeyMismatchError()


class ParamikoSSHAdapter:
    """Read-only adapter with no generic command or mutation method."""

    readonly = True

    def __init__(
        self,
        profile: DeviceConnectionProfile,
        client: paramiko.SSHClient | None = None,
        commands: ReadonlyCommandRegistry | None = None,
    ) -> None:
        self.profile = profile
        self.device_id = profile.device_id
        self._client = client
        self._commands = commands or ReadonlyCommandRegistry()
        self._owns_client = client is None

    @property
    def allowed_tools(self) -> frozenset[str]:
        return self._commands.tools()

    def connect(self) -> None:
        if self._client is not None:
            return
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        expected = self.profile.host_key_sha256.get_secret_value()
        client.set_missing_host_key_policy(_PinnedHostKeyPolicy(expected))
        kwargs: dict[str, Any] = {
            "hostname": self.profile.host,
            "port": self.profile.port,
            "username": self.profile.username,
            "timeout": self.profile.connect_timeout_seconds,
            "banner_timeout": self.profile.connect_timeout_seconds,
            "auth_timeout": self.profile.connect_timeout_seconds,
            "allow_agent": self.profile.authentication_method == AuthenticationMethod.AGENT,
            "look_for_keys": self.profile.authentication_method == AuthenticationMethod.AGENT,
        }
        if self.profile.authentication_method == AuthenticationMethod.PASSWORD:
            assert self.profile.password is not None
            kwargs["password"] = self.profile.password.get_secret_value()
        elif self.profile.authentication_method == AuthenticationMethod.PRIVATE_KEY:
            assert self.profile.private_key_path is not None
            kwargs["key_filename"] = self.profile.private_key_path.get_secret_value()
        try:
            client.connect(**kwargs)
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise SSHConnectionError("SSH_CONNECTION_FAILED")
            if _fingerprint(transport.get_remote_server_key()) != expected.removeprefix(
                "SHA256:"
            ).rstrip("="):
                raise HostKeyMismatchError()
        except (HostKeyMismatchError, paramiko.BadHostKeyException):
            client.close()
            raise HostKeyMismatchError() from None
        except Exception:
            client.close()
            raise SSHConnectionError("SSH_CONNECTION_FAILED") from None
        self._client = client

    def execute_readonly(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        command = self._commands.resolve(tool, arguments)
        self.connect()
        if self._client is None:
            raise SSHConnectionError("SSH connection unavailable")
        try:
            stdin, stdout, stderr = self._client.exec_command(
                command.command,
                timeout=self.profile.command_timeout_seconds,
                get_pty=False,
            )
            stdin.close()
            limit = self.profile.max_output_bytes
            stdout_bytes = stdout.read(limit + 1)
            stderr_bytes = stderr.read(limit + 1)
            if len(stdout_bytes) > limit or len(stderr_bytes) > limit:
                return normalize_observation(
                    RawObservation(
                        tool=tool,
                        stdout="",
                        stderr="",
                        exit_code=254,
                    )
                )
            exit_code = stdout.channel.recv_exit_status()
        except Exception:
            return normalize_observation(
                RawObservation(tool=tool, stdout="", stderr="", exit_code=255)
            )
        raw = RawObservation(
            tool=tool,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            exit_code=exit_code,
        )
        return normalize_observation(raw)

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
        self._client = None

