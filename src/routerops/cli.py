import json
import uuid
from typing import Annotated

import typer

from routerops.config import Settings
from routerops.evidence import EvidenceStore
from routerops.memory import MemoryStore
from routerops.models import Change, ChangePlan, RiskLevel, RunMode, VerificationResult
from routerops.orchestration import Supervisor
from routerops.recovery import ChangeWorkflow
from routerops.safety import ApprovalService, SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends import MockRouterBackend

app = typer.Typer(help="TR3000 RouterOps (phase one: mock backend only)")


def runtime() -> tuple[Settings, MockRouterBackend, ToolFacade, Supervisor]:
    settings = Settings()
    settings.ensure_directories()
    backend = MockRouterBackend(settings.scenario)
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
    settings, _, facade, _ = runtime()
    typer.echo(
        json.dumps(
            {
                "mode": settings.mode,
                "backend": settings.backend,
                "scenario": settings.scenario,
                "real_ssh_enabled": False,
                "registered_tools": [item.name for item in facade.registry.specs()],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


@app.command()
def baseline() -> None:
    """Capture a mock TR3000 baseline using read-only tools."""
    _, _, _, supervisor = runtime()
    _, digest = supervisor.capture_state(baseline=True)
    typer.echo(f"TR3000_BASELINE.json created (sha256={digest})")


@app.command("current-state")
def current_state() -> None:
    """Capture current mock state."""
    _, _, _, supervisor = runtime()
    _, digest = supervisor.capture_state(baseline=False)
    typer.echo(f"CURRENT_STATE.json created (sha256={digest})")


@app.command("state-diff")
def state_diff() -> None:
    """Compare current mock state with the baseline."""
    _, _, _, supervisor = runtime()
    typer.echo(json.dumps(supervisor.state_diff(), ensure_ascii=False, indent=2))


@app.command("diagnose-f50")
def diagnose_f50(
    problem: Annotated[str, typer.Argument()] = "F50启动后TR3000无法自动识别。",
) -> None:
    """Run the layered F50 diagnosis against a mock scenario."""
    _, _, _, supervisor = runtime()
    typer.echo(supervisor.diagnose_f50(problem).chinese_sections())


@app.command("change-demo")
def change_demo(
    approve: Annotated[
        bool,
        typer.Option("--approve", help="Approve the exact displayed mock plan."),
    ] = False,
) -> None:
    """Exercise backup, approval, verification, and rollback on Mock Router."""
    settings, backend, facade, _ = runtime()
    if settings.mode != 4:
        raise typer.BadParameter("change-demo requires ROUTEROPS_MODE=4")
    workflow_id = f"change-{uuid.uuid4().hex[:12]}"
    old = backend.execute(
        "uci_get", {"package": "dhcp", "section": "dnsmasq", "option": "cachesize"}
    )["value"]
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
        value = backend.execute(
            "uci_get", {"package": "dhcp", "section": "dnsmasq", "option": "cachesize"}
        )["value"]
        success = value == "800" and not backend.state.get("faults", {}).get("verify_fail")
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

