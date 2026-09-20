from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RiskLevel(IntEnum):
    READ_ONLY = 0
    LOW = 1
    HIGH = 2


class RunMode(IntEnum):
    DIAGNOSE = 1
    ADVISE = 2
    SEMI_AUTO = 3
    MAINTENANCE = 4


class WorkflowState(StrEnum):
    RECEIVED = "received"
    DISCOVERY = "discovery"
    DIAGNOSIS = "diagnosis"
    PLAN = "plan"
    POLICY_CHECK = "policy_check"
    WAITING_APPROVAL = "waiting_approval"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED_SAFE = "failed_safe"


class FaultLayer(StrEnum):
    L0_HARDWARE = "L0 Hardware"
    L1_USB_DRIVER = "L1 USB / Driver"
    L2_LINUX = "L2 Linux"
    L3_NETWORK = "L3 QWRT/OpenWrt Network"
    L4_DHCP_NAT_FIREWALL = "L4 DHCP/NAT/Firewall"
    L5_DNS = "L5 DNS"
    L6_OPENCLASH = "L6 OpenClash"
    L7_VPS = "L7 VPS"
    L8_INTERNET = "L8 Internet"


class ToolStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    DENIED = "denied"


class ToolSpec(StrictModel):
    name: str
    version: str = "1.0"
    description: str
    risk: RiskLevel
    min_mode: RunMode
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_output_bytes: int = Field(default=65536, ge=256, le=1048576)
    capability: str


class ToolCall(StrictModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    workflow_id: str
    approval_id: str | None = None


class ToolResult(StrictModel):
    status: ToolStatus
    data: dict[str, Any] = Field(default_factory=dict)
    evidence_ref: str | None = None
    warnings: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None


class Change(StrictModel):
    package: str
    section: str
    option: str
    old_value: str | None = None
    new_value: str


class ChangePlan(StrictModel):
    workflow_id: str
    device_id: str
    summary: str
    changes: list[Change]
    risk: RiskLevel
    verification_tools: list[str]
    rollback_required: bool = True


class ApprovalRequest(StrictModel):
    approval_id: str
    plan_hash: str
    baseline_hash: str
    tool_schema_version: str
    expires_at: datetime
    approved: bool = False


class BackupArtifact(StrictModel):
    backup_id: str
    workflow_id: str
    device_id: str
    firmware_fingerprint: str
    content_hash: str
    path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class VerificationResult(StrictModel):
    success: bool
    checks: dict[str, bool]
    message: str


class DiagnosticReport(StrictModel):
    problem: str
    current_status: str
    evidence: list[str]
    fault_layer: FaultLayer
    cause: str
    confidence: float = Field(ge=0, le=1)
    risk: str
    recommendations: list[str]
    required_tools: list[str]
    expected_result: str

    def chinese_sections(self) -> str:
        items = [
            ("问题", self.problem),
            ("当前状态", self.current_status),
            ("证据", "\n".join(f"- {item}" for item in self.evidence)),
            ("故障层级", self.fault_layer.value),
            ("原因", f"{self.cause}（置信度 {self.confidence:.0%}）"),
            ("风险", self.risk),
            ("建议", "\n".join(f"- {item}" for item in self.recommendations)),
            ("需要执行的工具", ", ".join(self.required_tools) or "无"),
            ("预期结果", self.expected_result),
        ]
        return "\n\n".join(f"【{title}】\n{value}" for title, value in items)

