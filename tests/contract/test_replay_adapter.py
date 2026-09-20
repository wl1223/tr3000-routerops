from pathlib import Path

from routerops.evidence import EvidenceStore
from routerops.fixtures.store import (
    FixtureSource,
    ObservationFixtureRecorder,
    ReplayRouterAdapter,
)
from routerops.models import RunMode, ToolCall, ToolStatus
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry


def test_fixture_round_trip_is_readonly_and_redacted(tmp_path: Path):
    root = tmp_path / "fixture"
    recorder = ObservationFixtureRecorder(
        root,
        "test-device",
        source=FixtureSource.TEST_GENERATED,
    )
    recorder.record(
        "get_usb_devices",
        {},
        {
            "devices": [{"description": "password=fixture-secret", "is_f50": False}],
            "_meta": {"available": True},
        },
    )
    persisted = (root / next(name for name in recorder.manifest.records)).read_text()
    assert "fixture-secret" not in persisted
    assert "REDACTED" in persisted
    assert recorder.manifest.source.type == FixtureSource.TEST_GENERATED
    assert recorder.manifest.source.is_device_evidence is False

    adapter = ReplayRouterAdapter(root)
    assert adapter.readonly
    assert not hasattr(adapter, "execute_mutation")
    result = adapter.execute_readonly("get_usb_devices", {})
    assert result["devices"][0]["description"] == "password=REDACTED"


def test_missing_replay_observation_is_safe_tool_error(tmp_path: Path):
    root = tmp_path / "fixture"
    ObservationFixtureRecorder(
        root,
        "test-device",
        source=FixtureSource.TEST_GENERATED,
    )
    facade = ToolFacade(
        ReplayRouterAdapter(root),
        build_registry(),
        SafetyPolicy(),
        EvidenceStore(tmp_path / "evidence"),
        RunMode.DIAGNOSE,
    )
    result = facade.invoke(ToolCall(name="get_system_info", workflow_id="replay"))
    assert result.status == ToolStatus.ERROR
    assert "exact read-only call" in (result.error or "")

