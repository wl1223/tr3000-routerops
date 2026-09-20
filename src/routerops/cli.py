import json
import uuid
from typing import Annotated

import typer

from routerops.config import Settings
from routerops.device.discovery import CapabilityDiscovery, DeviceCapabilities
from routerops.evidence import EvidenceStore
from routerops.memory import MemoryStore
from routerops.models import (
    Change,
    ChangePlan,
    RiskLevel,
    RunMode,
    ToolCall,
    ToolStatus,
    VerificationResult,
)
from routerops.orchestration import Supervisor
from routerops.recovery import ChangeWorkflow
from routerops.safety import ApprovalService, SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends import (
    MockRouterBackend,
    RouterBackend,
    build_backend,
)

app = typer.Typer(help="TR3000 RouterOps safety-first network agent")
device_app = typer.Typer(help="Read-only device discovery and state capture")
diagnose_app = typer.Typer(help="Layered read-only diagnostics")
app.add_typer(device_app, name="device")
app.add_typer(diagnose_app, name="diagnose")


def runtime() -> tuple[Settings, RouterBackend, ToolFacade, Supervisor]:
    settings = Settings()
    settings.ensure_directories()
    backend = build_backend(settings)
    evidence = EvidenceStore(settings.data_dir / "evidence")
    memory = MemoryStore(settings.data_dir / "routerops.sqlite3")
    facade = ToolFacade(
        backend=backend,
        registry=build_registry(),
        policy=SafetyPolicy(),
        evidence=evidence,
        mode=RunMode(settings.mode),
    )
    supervisor = Supervisor(
        facade,
        evidence,
        memory,
        settings.data_dir / "devices" / "tr3000",
    )
    return settings, backend, facade, supervisor


@app.command()
def status() -> None:
    """Show the enforced execution boundary."""
    settings, backend, facade, _ = runtime()
    typer.echo(
        json.dumps(
            {
                "mode": settings.mode,
                "backend": settings.backend,
                "scenario": settings.scenario,
                "real_ssh_enabled": settings.backend == "ssh",
                "real_device_readonly": backend.readonly,
                "registered_tools": [item.name for item in facade.registry.specs()],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@app.command()
def baseline() -> None:
    """Capture a TR3000 baseline using read-only tools."""
    _, _, _, supervisor = runtime()
    _, digest = supervisor.capture_state(baseline=True)
    typer.echo(f"TR3000_BASELINE.json created (sha256={digest})")


@app.command("current-state")
def current_state() -> None:
    """Capture current state."""
    _, _, _, supervisor = runtime()
    _, digest = supervisor.capture_state(baseline=False)
    typer.echo(f"CURRENT_STATE.json created (sha256={digest})")


@app.command("state-diff")
def state_diff() -> None:
    """Compare current state with the baseline."""
    _, _, _, supervisor = runtime()
    typer.echo(json.dumps(supervisor.state_diff(), ensure_ascii=False, indent=2))


@app.command("diagnose-f50")
def diagnose_f50(
    problem: Annotated[str, typer.Argument()] = "F50启动后TR3000无法自动识别。",
) -> None:
    """Compatibility alias for `routerops diagnose f50`."""
    _, _, _, supervisor = runtime()
    typer.echo(supervisor.diagnose_f50(problem).chinese_sections())


def _discover(
    settings: Settings,
    backend: RouterBackend,
    facade: ToolFacade,
) -> DeviceCapabilities:
    model = settings.device_model_expectation
    firmware = settings.device_firmware_expectation
    return CapabilityDiscovery().discover(
        facade,
        backend.device_id,
        model_expectation=model,
        firmware_expectation=firmware,
    )


@device_app.command("probe")
def device_probe() -> None:
    """Discover real capabilities without assuming paths or service names."""
    settings, backend, facade, _ = runtime()
    capabilities = _discover(settings, backend, facade)
    facade.evidence.snapshot(
        settings.data_dir / "devices" / "tr3000" / "capabilities.json",
        capabilities.model_dump(mode="json"),
    )
    typer.echo(capabilities.model_dump_json(indent=2))


@device_app.command("baseline")
def device_baseline() -> None:
    """Create baseline, current state, and capability files in one read-only run."""
    settings, backend, facade, supervisor = runtime()
    capabilities = _discover(settings, backend, facade)
    _, digest = supervisor.capture_device_baseline(
        capabilities.model_dump(mode="json")
    )
    typer.echo(
        json.dumps(
            {
                "baseline": "TR3000_BASELINE.json",
                "current": "current.json",
                "capabilities": "capabilities.json",
                "sha256": digest,
                "readonly": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@device_app.command("status")
def device_status() -> None:
    """Capture CURRENT_STATE and current.json using read-only tools."""
    _, _, _, supervisor = runtime()
    _, digest = supervisor.capture_state(baseline=False)
    typer.echo(
        json.dumps(
            {"current": "current.json", "sha256": digest, "readonly": True},
            ensure_ascii=False,
            indent=2,
        )
    )


@diagnose_app.command("f50")
def diagnose_f50_nested(
    problem: Annotated[str, typer.Argument()] = "F50启动后TR3000无法自动识别。",
) -> None:
    """Diagnose F50 from USB enumeration through VPS/Internet."""
    _, _, _, supervisor = runtime()
    typer.echo(supervisor.diagnose_f50(problem).chinese_sections())


@diagnose_app.command("openclash")
def diagnose_openclash(
    problem: Annotated[str, typer.Argument()] = "检查 OpenClash 当前状态",
) -> None:
    """Discover and diagnose OpenClash without modifying it."""
    _, _, _, supervisor = runtime()
    typer.echo(supervisor.diagnose_openclash(problem).chinese_sections())


@app.command("change-demo")
def change_demo(
    approve: Annotated[
        bool,
        typer.Option("--approve", help="Approve the exact displayed mock plan."),
    ] = False,
) -> None:
    """Exercise backup, approval, verification, and rollback on Mock Router."""
    settings, backend, facade, _ = runtime()
    if not isinstance(backend, MockRouterBackend):
        raise typer.BadParameter("REAL_DEVICE_WRITE_DISABLED_IN_PHASE2")
    if settings.mode != 4:
        raise typer.BadParameter("change-demo requires ROUTEROPS_MODE=4")
    workflow_id = f"change-{uuid.uuid4().hex[:12]}"
    old_result = facade.invoke(
        ToolCall(
            name="uci_get",
            arguments={"package": "dhcp", "section": "dnsmasq", "option": "cachesize"},
            workflow_id=workflow_id,
        )
    )
    if old_result.status != ToolStatus.OK:
        raise typer.BadParameter(f"read failed: {old_result.error}")
    old = old_result.data["value"]
    plan = ChangePlan(
        workflow_id=workflow_id,
        device_id=backend.device_id,
        summary="Mock-only DNS cache size change",
        changes=[
            Change(
                package="dhcp",
                section="dnsmasq",
                option="cachesize",
                old_value=str(old),
                new_value="800",
            )
        ],
        risk=RiskLevel.HIGH,
        verification_tools=["uci_get"],
    )
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, settings.data_dir / "backups")
    artifact, request = workflow.prepare(plan)
    typer.echo(
        json.dumps(
            {
                "risk": "HIGH",
                "diff": plan.changes[0].model_dump(),
                "backup": artifact.model_dump(mode="json"),
                "approval_id": request.approval_id,
                "plan_hash": request.plan_hash,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if not approve:
        typer.echo("No change executed. Re-run with --approve to approve this generated plan.")
        raise typer.Exit()
    approved = approvals.approve(request, plan, artifact.content_hash)

    def verify() -> VerificationResult:
        result = facade.invoke(
            ToolCall(
                name="uci_get",
                arguments={
                    "package": "dhcp",
                    "section": "dnsmasq",
                    "option": "cachesize",
                },
                workflow_id=workflow_id,
            )
        )
        success = result.status == ToolStatus.OK and result.data.get("value") == "800"
        return VerificationResult(
            success=success,
            checks={"dns_cache_value": success},
            message="verification passed" if success else "injected verification failure",
        )

    result = workflow.execute(plan, artifact, approved, verify)
    typer.echo(
        json.dumps(
            {"workflow_state": workflow.state, "verification": result.model_dump()},
            ensure_ascii=False,
            indent=2,
        )
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()

