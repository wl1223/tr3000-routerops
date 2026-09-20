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
        for tool in BASELINE_TOOLS:
            result = self.facade.invoke(ToolCall(name=tool, workflow_id=workflow_id))
            if result.status != ToolStatus.OK:
                machine.transition(WorkflowState.FAILED_SAFE)
                raise RuntimeError(f"baseline tool {tool} failed: {result.error}")
            snapshot[tool] = result.data
        machine.transition(WorkflowState.DIAGNOSIS)
        machine.transition(WorkflowState.SUCCEEDED)
        name = "TR3000_BASELINE.json" if baseline else "CURRENT_STATE.json"
        digest = self.evidence.snapshot(self.device_dir / name, snapshot)
        if not baseline:
            self.evidence.snapshot(self.device_dir / "current.json", snapshot)
        self.memory.event(workflow_id, "state_capture", {"path": name, "hash": digest})
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

