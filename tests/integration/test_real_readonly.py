import json
from pathlib import Path

from routerops.agents import F50Agent, OpenClashAgent
from routerops.device.discovery import CapabilityDiscovery
from routerops.evidence import EvidenceStore
from routerops.memory import MemoryStore
from routerops.models import FaultLayer, RunMode
from routerops.orchestration import Supervisor
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends.ssh_commands import ReadonlyCommandRegistry


def real_facade(adapter, tmp_path: Path) -> ToolFacade:
    return ToolFacade(
        adapter,
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "evidence"),
        RunMode.DIAGNOSE,
    )


def test_capability_discovery_from_readonly_ssh(make_ssh_adapter, tmp_path: Path):
    adapter, _ = make_ssh_adapter()
    capabilities = CapabilityDiscovery().discover(
        real_facade(adapter, tmp_path),
        device_id=adapter.device_id,
        model_expectation="Cudy TR3000 v1",
        firmware_expectation="QWRT R26.1.1",
    )
    assert capabilities.readonly
    assert capabilities.permission_level == 0
    assert capabilities.model_matches_expectation
    assert capabilities.firmware_matches_expectation
    assert capabilities.uci_available
    assert capabilities.openclash["status"]["running"]


def test_real_baseline_generation_is_sanitized(make_ssh_adapter, tmp_path: Path):
    adapter, _ = make_ssh_adapter(
        {
            "get_openclash_config": (
                "--PROCESS--\n1234 root mihomo\n--UCI--\n"
                "openclash.config.enable='1'\n"
                "openclash.config.password='router-secret'\n"
                "openclash.config.token='subscription-secret'\n"
                "--RUNTIME-SAFE--\nmode: fake-ip\n",
                "",
                0,
            )
        }
    )
    facade = real_facade(adapter, tmp_path)
    supervisor = Supervisor(
        facade,
        EvidenceStore(tmp_path / "evidence"),
        MemoryStore(tmp_path / "memory.sqlite3"),
        tmp_path / "devices" / "tr3000",
    )
    capabilities = CapabilityDiscovery().discover(
        facade, adapter.device_id, "Cudy TR3000 v1", "QWRT R26.1.1"
    )
    snapshot, digest = supervisor.capture_device_baseline(
        capabilities.model_dump(mode="json")
    )
    assert len(digest) == 64
    assert snapshot["get_system_info"]["kernel"] == "6.6.121"
    for name in (
        "TR3000_BASELINE.json",
        "CURRENT_STATE.json",
        "current.json",
        "capabilities.json",
    ):
        path = tmp_path / "devices" / "tr3000" / name
        assert path.exists()
        persisted = path.read_text()
        assert "router-secret" not in persisted
        assert "subscription-secret" not in persisted
        json.loads(persisted)


def test_real_f50_diagnostic_stops_when_usb_absent(make_ssh_adapter, tmp_path: Path):
    adapter, client = make_ssh_adapter(
        {
            "get_usb_devices": ("", "", 0),
            "get_usb_logs": ("usb descriptor read error -71", "", 0),
        }
    )
    report = F50Agent().diagnose(real_facade(adapter, tmp_path), "F50 无法识别")
    assert report.fault_layer == FaultLayer.L1_USB_DRIVER
    openclash_commands = [
        command for command in client.commands if "openclash" in command.lower()
    ]
    assert not openclash_commands


def test_real_openclash_discovery_is_readonly(make_ssh_adapter, tmp_path: Path):
    adapter, client = make_ssh_adapter()
    report = OpenClashAgent().diagnose(
        real_facade(adapter, tmp_path), "检查 OpenClash"
    )
    assert report.fault_layer == FaultLayer.L6_OPENCLASH
    assert "正常" in report.cause
    assert all(
        forbidden not in command
        for command in client.commands
        for forbidden in ("uci set", "restart", "kill ", "rm ", "sysupgrade")
    )


def test_real_current_state_diff(make_ssh_adapter, tmp_path: Path):
    adapter, client = make_ssh_adapter()
    facade = real_facade(adapter, tmp_path)
    supervisor = Supervisor(
        facade,
        EvidenceStore(tmp_path / "evidence"),
        MemoryStore(tmp_path / "memory.sqlite3"),
        tmp_path / "devices" / "tr3000",
    )
    supervisor.capture_state(baseline=True)
    command = ReadonlyCommandRegistry().resolve("get_memory", {}).command
    client.responses[command] = (
        "MemTotal: 262144 kB\nMemAvailable: 81920 kB\n"
        "SwapTotal: 0 kB\nSwapFree: 0 kB\n--SWAPS--\n",
        "",
        0,
    )
    changes = supervisor.state_diff()
    assert changes["get_memory.available_mb"] == {"before": 112, "after": 80}

