import hashlib
import hmac
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
        user_notified: bool,
    ) -> None:
        if mode < spec.min_mode:
            raise SafetyError(f"{spec.name} requires mode {int(spec.min_mode)}")
        self.validate_tool_schema(spec, arguments)
        self.validate_arguments(spec.name, arguments)
        if spec.risk == RiskLevel.LOW and not user_notified:
            raise SafetyError("user notification required before low-risk action")
        if spec.risk == RiskLevel.HIGH:
            if approval is None or not approval.approved:
                raise SafetyError("approval required for high-risk tool")
            if approval.expires_at <= datetime.now(UTC):
                raise SafetyError("approval has expired")
            action = self.action_hash(spec.name, arguments)
            if action not in approval.authorized_actions:
                raise SafetyError("tool call is outside the approved change plan")
            approval.authorized_actions.remove(action)

    def validate_tool_schema(
        self, spec: ToolSpec, arguments: dict[str, Any]
    ) -> None:
        properties = spec.input_schema.get("properties", {})
        required = set(spec.input_schema.get("required", []))
        if not isinstance(properties, dict):
            raise SafetyError("invalid internal tool schema")
        if set(arguments) - set(properties):
            raise SafetyError("tool arguments contain undeclared fields")
        if required - set(arguments):
            raise SafetyError("tool arguments are missing required fields")
        for name, value in arguments.items():
            rule = properties.get(name, {})
            if not isinstance(rule, dict):
                raise SafetyError("invalid internal argument schema")
            if rule.get("type") == "string" and not isinstance(value, str):
                raise SafetyError(f"{name} must be a string")
            if "enum" in rule and value not in rule["enum"]:
                raise SafetyError(f"{name} is not allowlisted")
            if "maxLength" in rule and len(str(value)) > int(rule["maxLength"]):
                raise SafetyError(f"{name} exceeds the maximum length")
            if "pattern" in rule and not re.fullmatch(str(rule["pattern"]), str(value)):
                raise SafetyError(f"{name} has an invalid format")

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
        if tool in {"restore_backup", "backup_config"} and (
            set(arguments) != {"backup_id"}
            or not UCI_NAME.fullmatch(str(arguments.get("backup_id", "")))
        ):
            raise SafetyError("invalid backup id")

    @staticmethod
    def action_hash(tool: str, arguments: dict[str, Any]) -> str:
        return content_hash({"tool": tool, "arguments": arguments})


class ApprovalService:
    schema_version = "1.0"

    @staticmethod
    def authorized_actions(plan: ChangePlan, backup_id: str) -> list[str]:
        actions = [
            SafetyPolicy.action_hash(
                "uci_set",
                {
                    "package": change.package,
                    "section": change.section,
                    "option": change.option,
                    "value": change.new_value,
                },
            )
            for change in plan.changes
        ]
        actions.append(SafetyPolicy.action_hash("restore_backup", {"backup_id": backup_id}))
        return sorted(actions)

    @staticmethod
    def plan_hash(plan: ChangePlan, baseline_hash: str, backup_id: str) -> str:
        actions = ApprovalService.authorized_actions(plan, backup_id)
        payload = {
            "plan": plan.model_dump(mode="json"),
            "baseline_hash": baseline_hash,
            "backup_id": backup_id,
            "authorized_actions": actions,
            "tool_schema_version": ApprovalService.schema_version,
        }
        return content_hash(payload)

    def request(
        self, plan: ChangePlan, baseline_hash: str, backup_id: str
    ) -> ApprovalRequest:
        actions = self.authorized_actions(plan, backup_id)
        digest = self.plan_hash(plan, baseline_hash, backup_id)
        return ApprovalRequest(
            approval_id=f"approval-{uuid.uuid4().hex[:12]}",
            plan_hash=digest,
            baseline_hash=baseline_hash,
            backup_id=backup_id,
            authorized_actions=actions,
            tool_schema_version=self.schema_version,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )

    def approve(
        self, request: ApprovalRequest, plan: ChangePlan, baseline_hash: str
    ) -> ApprovalRequest:
        expected = self.plan_hash(plan, baseline_hash, request.backup_id)
        if not hmac.compare_digest(request.plan_hash, expected):
            raise SafetyError("plan or baseline changed after approval request")
        expected_actions = self.authorized_actions(plan, request.backup_id)
        if request.authorized_actions != expected_actions:
            raise SafetyError("authorized tool calls changed after approval request")
        if request.expires_at <= datetime.now(UTC):
            raise SafetyError("approval request expired")
        return request.model_copy(update={"approved": True})

    @staticmethod
    def fingerprint(value: dict[str, Any]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode()).hexdigest()

