import uuid
from pathlib import Path
from typing import Any

from routerops.agents import F50Agent, OpenClashAgent
from routerops.evidence import EvidenceStore
from routerops.memory import MemoryStore
from routerops.models import DiagnosticReport, ToolCall, ToolStatus, WorkflowState
from routerops.orchestration.state import StateMachine
from routerops.tools.facade import ToolFacade

BASELINE_TOOLS = (
    "get_system_info",
    "get_memory",
    "get_storage",
    "get_interfaces",
    "get_routes",
    "get_dns",
    "get_firewall",
    "get_dhcp",
    "get_usb_devices",
    "get_usb_network_devices",
    "get_f50_status",
    "get_openclash_status",
    "get_openclash_version",
    "get_openclash_process",
    "get_openclash_config",
)


class Supervisor:
    def __init__(
        self,
        facade: ToolFacade,
        evidence: EvidenceStore,
        memory: MemoryStore,
        device_dir: Path,
    ) -> None:
        self.facade = facade
        self.evidence = evidence
        self.memory = memory
        self.device_dir = device_dir

    def capture_state(self, baseline: bool = False) -> tuple[dict[str, Any], str]:
        workflow_id = f"baseline-{uuid.uuid4().hex[:12]}"
        machine = StateMachine()
        machine.transition(WorkflowState.DISCOVERY)
        snapshot: dict[str, Any] = {}
        unavailable: list[str] = []
        for tool in BASELINE_TOOLS:
            result = self.facade.invoke(ToolCall(name=tool, workflow_id=workflow_id))
            if result.status != ToolStatus.OK:
                unavailable.append(tool)
                snapshot[tool] = self._unavailable_observation(tool, result.error)
            else:
                snapshot[tool] = result.data
        snapshot["source"] = self._source_metadata(snapshot)
        machine.transition(WorkflowState.DIAGNOSIS)
        machine.transition(WorkflowState.SUCCEEDED)
        name = "TR3000_BASELINE.json" if baseline else "CURRENT_STATE.json"
        digest = self.evidence.snapshot(self.device_dir / name, snapshot)
        if not baseline:
            self.evidence.snapshot(self.device_dir / "current.json", snapshot)
        self.memory.event(
            workflow_id,
            "state_capture",
            {"path": name, "hash": digest, "unavailable_tools": unavailable},
        )
        return snapshot, digest

    def capture_device_baseline(
        self, capabilities: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        snapshot, digest = self.capture_state(baseline=True)
        self.evidence.snapshot(self.device_dir / "current.json", snapshot)
        self.evidence.snapshot(self.device_dir / "CURRENT_STATE.json", snapshot)
        self.evidence.snapshot(self.device_dir / "capabilities.json", capabilities)
        return snapshot, digest

    def state_diff(self) -> dict[str, dict[str, Any]]:
        baseline_path = self.device_dir / "TR3000_BASELINE.json"
        if not baseline_path.exists():
            raise RuntimeError("baseline does not exist; run `routerops baseline` first")
        import json

        baseline = json.loads(baseline_path.read_text())
        current, _ = self.capture_state(baseline=False)
        return self.evidence.diff(baseline, current)

    def diagnose_f50(self, problem: str) -> DiagnosticReport:
        report = F50Agent().diagnose(self.facade, problem)
        self.memory.event(
            f"diagnosis-{uuid.uuid4().hex[:12]}",
            "diagnostic_report",
            report.model_dump(),
        )
        return report

    def diagnose_openclash(self, problem: str) -> DiagnosticReport:
        report = OpenClashAgent().diagnose(self.facade, problem)
        self.memory.event(
            f"diagnosis-{uuid.uuid4().hex[:12]}",
            "diagnostic_report",
            report.model_dump(),
        )
        return report

    def _source_metadata(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        backend_name = type(self.facade.backend).__name__
        if backend_name == "ParamikoSSHAdapter":
            source_type = "real_device"
        elif backend_name == "ReplayRouterAdapter":
            source_type = "replay"
        else:
            source_type = "mock"
        system = snapshot.get("get_system_info", {})
        return {
            "type": source_type,
            "device": system.get("model", "unknown"),
            "firmware": system.get("firmware", "unknown"),
            "mode": "readonly" if self.facade.backend.readonly else "mock",
            "backend": backend_name,
            "real_device_connected": source_type == "real_device",
            "real_device_validated": False,
        }

    def _unavailable_observation(
        self, tool: str, error: str | None
    ) -> dict[str, Any]:
        source = (
            "real_ssh"
            if type(self.facade.backend).__name__ == "ParamikoSSHAdapter"
            else "replay"
            if type(self.facade.backend).__name__ == "ReplayRouterAdapter"
            else "mock"
        )
        return {
            "_meta": {
                "available": False,
                "partial": False,
                "exit_code": None,
                "error_code": "TOOL_ERROR",
                "reason": error or "tool_error",
                "source": source,
                "command": tool,
                "fallback": None,
            }
        }

