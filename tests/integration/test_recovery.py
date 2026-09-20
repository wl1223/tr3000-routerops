import json
from pathlib import Path

import pytest

from routerops.models import (
    Change,
    ChangePlan,
    RiskLevel,
    RunMode,
    ToolCall,
    ToolStatus,
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


def test_approval_cannot_authorize_different_write(make_facade, tmp_path: Path):
    backend, facade = make_facade(mode=RunMode.MAINTENANCE)
    change = plan(backend.device_id)
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, tmp_path / "backups")
    artifact, request = workflow.prepare(change)
    approved = approvals.approve(request, change, artifact.content_hash)
    result = facade.invoke(
        ToolCall(
            name="uci_set",
            arguments={
                "package": "network",
                "section": "wan",
                "option": "proto",
                "value": "static",
            },
            workflow_id=change.workflow_id,
            approval_id=approved.approval_id,
        ),
        approved,
    )
    assert result.status == ToolStatus.DENIED
    assert "outside" in (result.error or "")


def test_backup_failure_stops_before_approval(make_facade, tmp_path: Path):
    backend, facade = make_facade(mode=RunMode.MAINTENANCE)
    backend.state["faults"]["error_backup_config"] = True
    workflow = ChangeWorkflow(
        backend, facade, ApprovalService(), tmp_path / "backups"
    )
    with pytest.raises(SafetyError, match="backup failed"):
        workflow.prepare(plan(backend.device_id))
    assert workflow.state == WorkflowState.FAILED_SAFE


def test_rollback_failure_enters_failed_safe(make_facade, tmp_path: Path):
    backend, facade = make_facade("rollback_failure", RunMode.MAINTENANCE)
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
    assert not result.checks["rollback"]
    assert workflow.state == WorkflowState.FAILED_SAFE


def test_approval_is_consumed_after_rollback(make_facade, tmp_path: Path):
    backend, facade = make_facade("rollback_required", RunMode.MAINTENANCE)
    change = plan(backend.device_id)
    approvals = ApprovalService()
    workflow = ChangeWorkflow(backend, facade, approvals, tmp_path / "backups")
    artifact, request = workflow.prepare(change)
    approved = approvals.approve(request, change, artifact.content_hash)
    workflow.execute(
        change,
        artifact,
        approved,
        lambda: VerificationResult(success=False, checks={"probe": False}, message="failed"),
    )
    with pytest.raises(SafetyError, match="consumed"):
        workflow.execute(
            change,
            artifact,
            approved,
            lambda: VerificationResult(success=True, checks={"probe": True}, message="ok"),
        )


def test_persisted_backup_is_redacted(make_facade, tmp_path: Path):
    backend, facade = make_facade(mode=RunMode.MAINTENANCE)
    backend.state["uci"]["wireless"] = {
        "radio": {"key": "wifi-secret", "password": "admin-secret"}
    }
    workflow = ChangeWorkflow(
        backend, facade, ApprovalService(), tmp_path / "backups"
    )
    artifact, _ = workflow.prepare(plan(backend.device_id))
    persisted = json.loads(Path(artifact.path).read_text())
    encoded = json.dumps(persisted)
    assert "wifi-secret" not in encoded
    assert "admin-secret" not in encoded
    assert encoded.count("REDACTED") >= 2

