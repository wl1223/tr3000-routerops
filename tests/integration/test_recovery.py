from pathlib import Path

import pytest

from routerops.models import (
    Change,
    ChangePlan,
    RiskLevel,
    RunMode,
    VerificationResult,
    WorkflowState,
)
from routerops.recovery import ChangeWorkflow
from routerops.safety import ApprovalService
from routerops.safety.policy import SafetyError


def plan(device_id: str) -> ChangePlan:
    return ChangePlan(
        workflow_id="wf-change",
        device_id=device_id,
        summary="test",
        changes=[
            Change(
                package="dhcp",
                section="dnsmasq",
                option="cachesize",
                old_value="500",
                new_value="800",
            )
        ],
        risk=RiskLevel.HIGH,
        verification_tools=["uci_get"],
    )


def test_successful_change(make_facade, tmp_path: Path):
    backend, facade = make_facade(mode=RunMode.MAINTENANCE)
    change = plan(backend.device_id)
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, tmp_path / "backups")
    artifact, request = workflow.prepare(change)
    approved = approvals.approve(request, change, artifact.content_hash)
    result = workflow.execute(
        change,
        artifact,
        approved,
        lambda: VerificationResult(success=True, checks={"value": True}, message="ok"),
    )
    assert result.success
    assert workflow.state == WorkflowState.SUCCEEDED


def test_verification_failure_rolls_back(make_facade, tmp_path: Path):
    backend, facade = make_facade("rollback_required", RunMode.MAINTENANCE)
    change = plan(backend.device_id)
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, tmp_path / "backups")
    artifact, request = workflow.prepare(change)
    approved = approvals.approve(request, change, artifact.content_hash)
    result = workflow.execute(
        change,
        artifact,
        approved,
        lambda: VerificationResult(success=False, checks={"probe": False}, message="failed"),
    )
    assert not result.success
    assert result.checks["rollback"]
    assert workflow.state == WorkflowState.ROLLED_BACK
    assert backend.state["uci"]["dhcp"]["dnsmasq"]["cachesize"] == "500"


def test_tampered_plan_invalidates_approval(make_facade, tmp_path: Path):
    backend, facade = make_facade(mode=RunMode.MAINTENANCE)
    change = plan(backend.device_id)
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, tmp_path / "backups")
    artifact, request = workflow.prepare(change)
    change.changes[0].new_value = "9999"
    with pytest.raises(SafetyError, match="changed"):
        approvals.approve(request, change, artifact.content_hash)

