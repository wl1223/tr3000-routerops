import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from routerops.evidence.store import content_hash
from routerops.models import ApprovalRequest, ChangePlan, RiskLevel, RunMode, ToolSpec

UCI_NAME = re.compile(r"^[A-Za-z0-9_@-]{1,64}$")
PROTECTED_PACKAGES = {"network", "firewall", "dhcp", "openclash", "dropbear", "system"}
SAFE_PROBE_DOMAINS = {"connectivitycheck.gstatic.com", "www.cloudflare.com", "1.1.1.1"}


class SafetyError(RuntimeError):
    pass


class SafetyPolicy:
    def authorize(
        self,
        spec: ToolSpec,
        mode: RunMode,
        arguments: dict[str, Any],
        approval: ApprovalRequest | None,
    ) -> None:
        if mode < spec.min_mode:
            raise SafetyError(f"{spec.name} requires mode {int(spec.min_mode)}")
        self.validate_arguments(spec.name, arguments)
        if spec.risk == RiskLevel.HIGH:
            if approval is None or not approval.approved:
                raise SafetyError("high-risk tool requires an approved, unexpired change request")
            if approval.expires_at <= datetime.now(UTC):
                raise SafetyError("approval has expired")

    def validate_arguments(self, tool: str, arguments: dict[str, Any]) -> None:
        if tool.startswith("uci_") and tool not in {"uci_diff"}:
            for key in ("package", "section", "option"):
                value = arguments.get(key)
                if value is not None and not UCI_NAME.fullmatch(str(value)):
                    raise SafetyError(f"invalid UCI {key}")
        if tool == "uci_set":
            required = {"package", "section", "option", "value"}
            if set(arguments) != required:
                raise SafetyError("uci_set requires only package, section, option, and value")
            if arguments["package"] not in PROTECTED_PACKAGES:
                raise SafetyError("UCI package is not allowlisted")
            if len(str(arguments["value"])) > 2048 or "\x00" in str(arguments["value"]):
                raise SafetyError("UCI value is unsafe")
        if tool in {"ping", "traceroute", "curl_test"}:
            if set(arguments) - {"target"}:
                raise SafetyError("probe accepts only a target")
            if str(arguments.get("target", "")) not in SAFE_PROBE_DOMAINS:
                raise SafetyError("probe target is not allowlisted")
        if tool in {"restore_backup", "backup_config"}:
            if set(arguments) != {"backup_id"} or not UCI_NAME.fullmatch(
                str(arguments.get("backup_id", ""))
            ):
                raise SafetyError("invalid backup id")


class ApprovalService:
    schema_version = "1.0"

    @staticmethod
    def plan_hash(plan: ChangePlan, baseline_hash: str) -> str:
        payload = {
            "plan": plan.model_dump(mode="json"),
            "baseline_hash": baseline_hash,
            "tool_schema_version": ApprovalService.schema_version,
        }
        return content_hash(payload)

    def request(self, plan: ChangePlan, baseline_hash: str) -> ApprovalRequest:
        digest = self.plan_hash(plan, baseline_hash)
        return ApprovalRequest(
            approval_id=f"approval-{uuid.uuid4().hex[:12]}",
            plan_hash=digest,
            baseline_hash=baseline_hash,
            tool_schema_version=self.schema_version,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )

    def approve(
        self, request: ApprovalRequest, plan: ChangePlan, baseline_hash: str
    ) -> ApprovalRequest:
        expected = self.plan_hash(plan, baseline_hash)
        if not hashlib.compare_digest(request.plan_hash, expected):
            raise SafetyError("plan or baseline changed after approval request")
        if request.expires_at <= datetime.now(UTC):
            raise SafetyError("approval request expired")
        return request.model_copy(update={"approved": True})

    @staticmethod
    def fingerprint(value: dict[str, Any]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode()).hexdigest()

