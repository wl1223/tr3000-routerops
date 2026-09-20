import json
from pathlib import Path

from typer.testing import CliRunner

from routerops.agents import F50Agent, OpenClashAgent
from routerops.cli import app
from routerops.device.discovery import CapabilityDiscovery
from routerops.evidence import EvidenceStore
from routerops.fixtures.store import FixtureSource, ObservationFixtureRecorder
from routerops.memory import MemoryStore
from routerops.models import RunMode
from routerops.orchestration import Supervisor
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry


def test_six_required_cli_entries_work_with_exact_replay(
    make_ssh_adapter, tmp_path: Path
):
    adapter, _ = make_ssh_adapter()
    fixture_dir = tmp_path / "fixture"
    recorder = ObservationFixtureRecorder(
        fixture_dir,
        adapter.device_id,
        source=FixtureSource.TEST_GENERATED,
    )
    facade = ToolFacade(
        adapter,
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "capture-evidence"),
        RunMode.DIAGNOSE,
        recorder=recorder,
    )
    CapabilityDiscovery().discover(
        facade, adapter.device_id, "Cudy TR3000 v1", "QWRT R26.1.1"
    )
    supervisor = Supervisor(
        facade,
        EvidenceStore(tmp_path / "state-evidence"),
        MemoryStore(tmp_path / "capture.sqlite3"),
        tmp_path / "capture-device",
    )
    supervisor.capture_state(baseline=True)
    F50Agent().diagnose(facade, "capture")
    OpenClashAgent().diagnose(facade, "capture")

    runtime_dir = tmp_path / "runtime"
    env = {
        "ROUTEROPS_BACKEND": "replay",
        "ROUTEROPS_MODE": "1",
        "ROUTEROPS_FIXTURE_REPLAY_DIR": str(fixture_dir),
        "ROUTEROPS_DATA_DIR": str(runtime_dir),
    }
    runner = CliRunner()
    status = runner.invoke(app, ["status"], env=env)
    assert status.exit_code == 0
    invariants = json.loads(status.output)["real_device_invariants"]
    assert invariants == {
        "mutation_tools": 0,
        "write_capability": False,
        "generic_shell": False,
        "auto_repair": False,
        "restart": False,
        "reboot": False,
        "uci_write": False,
        "sysupgrade": False,
        "restore": False,
    }
    commands = [
        ["device", "probe"],
        ["device", "baseline"],
        ["device", "status"],
        ["state-diff"],
        ["diagnose", "f50"],
        ["diagnose", "openclash"],
    ]
    for command in commands:
        result = runner.invoke(app, command, env=env)
        assert result.exit_code == 0, (command, result.output, result.exception)

