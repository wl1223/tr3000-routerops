from pathlib import Path

import pytest

from routerops.device import DeviceConnectionProfile
from routerops.evidence import EvidenceStore
from routerops.models import RiskLevel, RunMode, ToolCall, ToolStatus
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends.ssh_commands import (
    ReadonlyCommandError,
    ReadonlyCommandRegistry,
)


def test_paramiko_adapter_has_no_generic_or_mutation_execution(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    assert hasattr(adapter, "execute_readonly")
    assert not hasattr(adapter, "execute")
    assert not hasattr(adapter, "execute_mutation")
    assert not hasattr(adapter, "snapshot")
    assert not hasattr(adapter, "restore")


def test_readonly_command_registry_rejects_commands_and_write_tools():
    registry = ReadonlyCommandRegistry()
    for name in (
        "uci_set",
        "restart_network",
        "restart_dns",
        "restart_openclash",
        "restore_backup",
        "reboot",
        "sysupgrade",
        "shell",
    ):
        with pytest.raises(ReadonlyCommandError):
            registry.resolve(name, {})
    with pytest.raises(ReadonlyCommandError):
        registry.resolve("get_system_info", {"command": "id"})


def test_adapter_contract_for_all_real_read_tools(make_ssh_adapter):
    adapter, client = make_ssh_adapter()
    for tool in sorted(adapter.allowed_tools):
        arguments = {"target": "1.1.1.1"} if tool in {"ping", "traceroute", "curl_test"} else {}
        result = adapter.execute_readonly(tool, arguments)
        assert isinstance(result, dict)
    assert client.commands
    assert all("uci set" not in command for command in client.commands)


def test_real_device_write_is_impossible_in_phase2(
    make_ssh_adapter, tmp_path: Path
):
    adapter, _ = make_ssh_adapter()
    facade = ToolFacade(
        adapter,
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "evidence"),
        RunMode.DIAGNOSE,
    )
    mutation_specs = [
        spec for spec in build_registry().specs() if spec.risk != RiskLevel.READ_ONLY
    ]
    assert mutation_specs
    for spec in mutation_specs:
        result = facade.invoke(ToolCall(name=spec.name, workflow_id="phase2-write-test"))
        assert result.status == ToolStatus.DENIED
        assert result.error == "REAL_DEVICE_WRITE_DISABLED_IN_PHASE2"


def test_profile_secrets_are_masked():
    profile = DeviceConnectionProfile(
        host="192.0.2.1",
        authentication_method="password",
        password="router-password",
        host_key_sha256="SHA256:host-fingerprint",
    )
    representation = repr(profile)
    assert "router-password" not in representation
    assert "host-fingerprint" not in representation


def test_failed_command_returns_safe_observation(make_ssh_adapter):
    adapter, _ = make_ssh_adapter(
        {"get_system_info": ("ubus: not found", "", 127)}
    )
    result = adapter.execute_readonly("get_system_info", {})
    assert result["model"] == "unknown"
    assert result["_meta"]["available"] is False
    assert result["_meta"]["error_code"] == "NORMALIZATION_FAILED"


def test_transport_command_error_returns_safe_observation(make_ssh_adapter):
    adapter, client = make_ssh_adapter()
    command = ReadonlyCommandRegistry().resolve("get_memory", {}).command
    del client.responses[command]
    result = adapter.execute_readonly("get_memory", {})
    assert result["total_mb"] == 0
    assert result["_meta"]["available"] is False
    assert result["_meta"]["exit_code"] == 255

