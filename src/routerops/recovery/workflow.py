import json
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from routerops.evidence.store import content_hash
from routerops.models import (
    ApprovalRequest,
    BackupArtifact,
    ChangePlan,
    ToolCall,
    ToolStatus,
    VerificationResult,
    WorkflowState,
)
from routerops.safety.policy import ApprovalService, SafetyError
from routerops.tools.backends.base import RouterBackend
from routerops.tools.facade import ToolFacade


class ChangeWorkflow:
    def __init__(
        self,
        backend: RouterBackend,
        facade: ToolFacade,
        approvals: ApprovalService,
        backup_dir: Path,
    ) -> None:
        self.backend = backend
        self.facade = facade
        self.approvals = approvals
        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.state = WorkflowState.RECEIVED
        self._snapshot: dict[str, Any] | None = None

    def prepare(self, plan: ChangePlan) -> tuple[BackupArtifact, ApprovalRequest]:
        self.state = WorkflowState.POLICY_CHECK
        self._snapshot = self.backend.snapshot()
        baseline_hash = content_hash(self._snapshot)
        backup_id = f"backup-{uuid.uuid4().hex[:12]}"
        result = self.facade.invoke(
            ToolCall(
                name="backup_config",
                arguments={"backup_id": backup_id},
                workflow_id=plan.workflow_id,
            )
        )
        if result.status != ToolStatus.OK:
            self.state = WorkflowState.FAILED_SAFE
            raise SafetyError(f"backup failed: {result.error}")
        path = self.backup_dir / f"{backup_id}.json"
        path.write_text(json.dumps(self._snapshot, ensure_ascii=False, indent=2))
        artifact = BackupArtifact(
            backup_id=backup_id,
            workflow_id=plan.workflow_id,
            device_id=plan.device_id,
            firmware_fingerprint=content_hash(self._snapshot.get("system", {})),
            content_hash=baseline_hash,
            path=str(path),
        )
        request = self.approvals.request(plan, baseline_hash, backup_id)
        self.state = WorkflowState.WAITING_APPROVAL
        return artifact, request

    def execute(
        self,
        plan: ChangePlan,
        artifact: BackupArtifact,
        approval: ApprovalRequest,
        verifier: Callable[[], VerificationResult],
    ) -> VerificationResult:
        if not approval.approved:
            raise SafetyError("change request is not approved")
        current_hash = content_hash(self.backend.snapshot())
        expected_hash = self.approvals.plan_hash(
            plan, artifact.content_hash, artifact.backup_id
        )
        if current_hash != artifact.content_hash or approval.plan_hash != expected_hash:
            raise SafetyError("plan or router state changed after preview")
        self.state = WorkflowState.EXECUTING
        for change in plan.changes:
            result = self.facade.invoke(
                ToolCall(
                    name="uci_set",
                    arguments={
                        "package": change.package,
                        "section": change.section,
                        "option": change.option,
                        "value": change.new_value,
                    },
                    workflow_id=plan.workflow_id,
                    approval_id=approval.approval_id,
                ),
                approval,
            )
            if result.status != ToolStatus.OK:
                return self._rollback(plan, artifact, approval, f"execution failed: {result.error}")
        self.state = WorkflowState.VERIFYING
        verification = verifier()
        if not verification.success:
            return self._rollback(plan, artifact, approval, verification.message)
        self.state = WorkflowState.SUCCEEDED
        return verification

    def _rollback(
        self,
        plan: ChangePlan,
        artifact: BackupArtifact,
        approval: ApprovalRequest,
        reason: str,
    ) -> VerificationResult:
        self.state = WorkflowState.ROLLING_BACK
        result = self.facade.invoke(
            ToolCall(
                name="restore_backup",
                arguments={"backup_id": artifact.backup_id},
                workflow_id=plan.workflow_id,
                approval_id=approval.approval_id,
            ),
            approval,
        )
        if result.status != ToolStatus.OK or self._snapshot is None:
            self.state = WorkflowState.FAILED_SAFE
            return VerificationResult(
                success=False,
                checks={"rollback": False},
                message=f"{reason}; automatic rollback failed",
            )
        restored = content_hash(self.backend.snapshot()) == artifact.content_hash
        self.state = WorkflowState.ROLLED_BACK if restored else WorkflowState.FAILED_SAFE
        return VerificationResult(
            success=False,
            checks={"rollback": restored},
            message=f"{reason}; automatic rollback {'succeeded' if restored else 'failed'}",
        )

