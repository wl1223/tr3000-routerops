import json
from pathlib import Path

import paramiko
import pytest
from pydantic import ValidationError

from routerops.agents import OpenClashAgent
from routerops.config import Settings
from routerops.evidence import EvidenceStore
from routerops.fixtures.store import (
    FixtureSource,
    FixtureSourceMetadata,
    ObservationFixtureRecorder,
    ReplayRouterAdapter,
)
from routerops.models import RunMode, ToolCall, ToolStatus
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends.ssh import (
    HostKeyMismatchError,
    ParamikoSSHAdapter,
    _PinnedHostKeyPolicy,
)
from routerops.tools.backends.ssh_commands import ReadonlyCommandError


def _test_fixture(root: Path) -> ReplayRouterAdapter:
    recorder = ObservationFixtureRecorder(
        root,
        "test-device",
        source=FixtureSource.TEST_GENERATED,
    )
    recorder.record("get_system_info", {}, {"model": "test-only"})
    return ReplayRouterAdapter(root)


def test_real_ssh_has_no_generic_shell(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    assert not hasattr(adapter, "execute")
    assert not hasattr(adapter, "run_shell")
    assert not hasattr(adapter, "exec_anything")


def test_real_ssh_rejects_mutation_command(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    with pytest.raises(ReadonlyCommandError):
        adapter.execute_readonly("shell", {"command": "id"})


def test_real_ssh_rejects_restart(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    with pytest.raises(ReadonlyCommandError):
        adapter.execute_readonly("restart_network", {})


def test_real_ssh_rejects_uci_write(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    with pytest.raises(ReadonlyCommandError):
        adapter.execute_readonly("uci_set", {})


def test_real_ssh_rejects_reboot(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    with pytest.raises(ReadonlyCommandError):
        adapter.execute_readonly("reboot", {})


def test_real_ssh_rejects_sysupgrade(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    with pytest.raises(ReadonlyCommandError):
        adapter.execute_readonly("sysupgrade", {})


def test_real_device_forces_mode_1():
    with pytest.raises(ValidationError, match="MODE 1"):
        Settings(
            backend="ssh",
            mode=2,
            ssh_host="192.0.2.1",
            ssh_host_key_sha256="SHA256:test",
        )


def test_real_device_has_no_mutation_tools(make_ssh_adapter):
    adapter, _ = make_ssh_adapter()
    forbidden = {
        "uci_set",
        "restore_backup",
        "restart_network",
        "restart_dns",
        "restart_openclash",
        "reboot",
        "sysupgrade",
    }
    assert adapter.allowed_tools.isdisjoint(forbidden)
    assert not hasattr(adapter, "execute_mutation")


def test_replay_cannot_connect_ssh(tmp_path: Path):
    adapter = _test_fixture(tmp_path / "fixture")
    assert not hasattr(adapter, "connect")
    assert not isinstance(adapter, ParamikoSSHAdapter)


def test_replay_forces_mode_1(tmp_path: Path):
    with pytest.raises(ValidationError, match="MODE 1"):
        Settings(
            backend="replay",
            mode=2,
            fixture_replay_dir=tmp_path / "fixture",
        )


def test_fixture_integrity(tmp_path: Path):
    root = tmp_path / "fixture"
    adapter = _test_fixture(root)
    assert adapter.execute_readonly("get_system_info", {})["model"] == "test-only"
    manifest = json.loads((root / "manifest.json").read_text())
    record_path = root / manifest["records"][0]
    record = json.loads(record_path.read_text())
    record["observation"]["model"] = "tampered"
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="integrity"):
        ReplayRouterAdapter(root)


def test_fixture_source_separation():
    with pytest.raises(ValidationError, match="inconsistent"):
        FixtureSourceMetadata(
            type=FixtureSource.REAL_DEVICE_REDACTED,
            is_device_evidence=False,
            device_profile_identifier="tr3000",
        )
    generated = FixtureSourceMetadata(
        type=FixtureSource.TEST_GENERATED,
        is_device_evidence=False,
        device_profile_identifier="test",
    )
    assert generated.type == FixtureSource.TEST_GENERATED
    assert not generated.is_device_evidence


def test_raw_stdout_not_persisted(tmp_path: Path):
    recorder = ObservationFixtureRecorder(
        tmp_path / "fixture",
        "test-device",
        source=FixtureSource.TEST_GENERATED,
    )
    with pytest.raises(ValueError, match="raw SSH output"):
        recorder.record("get_system_info", {}, {"raw_stdout": "sensitive"})
    assert recorder.manifest.records == []


def test_secret_redaction(tmp_path: Path):
    root = tmp_path / "fixture"
    recorder = ObservationFixtureRecorder(
        root,
        "test-device",
        source=FixtureSource.TEST_GENERATED,
    )
    recorder.record("get_usb_logs", {}, {"lines": ["token=secret-value"]})
    persisted = (root / recorder.manifest.records[0]).read_text()
    assert "secret-value" not in persisted
    assert "REDACTED" in persisted


def test_host_key_mismatch():
    key = paramiko.RSAKey.generate(1024)
    policy = _PinnedHostKeyPolicy("SHA256:not-the-device-key")
    with pytest.raises(HostKeyMismatchError, match="HOST_KEY_MISMATCH"):
        policy.missing_host_key(paramiko.SSHClient(), "router", key)


def test_unknown_command_degrades_gracefully(make_ssh_adapter, tmp_path: Path):
    adapter, _ = make_ssh_adapter()
    facade = ToolFacade(
        adapter,
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "evidence"),
        RunMode.DIAGNOSE,
    )
    result = facade.invoke(ToolCall(name="unknown_tool", workflow_id="unknown"))
    assert result.status == ToolStatus.ERROR


def test_parser_failure_degrades_gracefully(make_ssh_adapter):
    adapter, _ = make_ssh_adapter(
        {"get_interfaces": ("QWRT changed this output", "", 0)}
    )
    result = adapter.execute_readonly("get_interfaces", {})
    assert result["interfaces"] == []
    assert result["_meta"]["available"] is False
    assert result["_meta"]["reason"] == "output_format_changed_or_unparseable"


def test_openclash_unknown_is_not_not_installed(make_ssh_adapter, tmp_path: Path):
    adapter, _ = make_ssh_adapter(
        {
            "get_openclash_status": ("--PACKAGES--\n--PROCESSES--\n", "", 0),
            "get_openclash_version": ("--PACKAGES--\n--PROCESSES--\n", "", 0),
            "get_openclash_process": ("", "", 0),
            "get_openclash_config": (
                "--PROCESS--\n--UCI--\n--RUNTIME-SAFE--\n",
                "",
                0,
            ),
            "get_openclash_logs": ("", "", 0),
            "test_openclash": ("--PROCESS--\n--SOCKETS--\n", "", 0),
        }
    )
    facade = ToolFacade(
        adapter,
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "evidence"),
        RunMode.DIAGNOSE,
    )
    report = OpenClashAgent().diagnose(facade, "OpenClash unknown")
    assert "未安装" not in report.cause
    assert "未发现" in report.cause

