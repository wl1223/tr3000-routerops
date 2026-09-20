import pytest
from pydantic import ValidationError

from routerops.config import Settings


def test_ssh_requires_mode_one_and_host_key():
    with pytest.raises(ValidationError, match="MODE 1"):
        Settings(
            backend="ssh",
            mode=4,
            ssh_host="192.0.2.1",
            ssh_host_key_sha256="SHA256:test",
        )
    with pytest.raises(ValidationError, match="host-key"):
        Settings(backend="ssh", mode=1, ssh_host="192.0.2.1")


def test_ssh_profile_is_always_readonly():
    settings = Settings(
        backend="ssh",
        mode=1,
        ssh_host="192.0.2.1",
        ssh_host_key_sha256="SHA256:test",
    )
    assert settings.device_profile().readonly is True

