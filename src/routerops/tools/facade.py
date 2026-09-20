import json
import threading

from routerops.evidence import EvidenceStore
from routerops.models import ApprovalRequest, RunMode, ToolCall, ToolResult, ToolStatus
from routerops.observability.redaction import redact
from routerops.safety.policy import SafetyError, SafetyPolicy
from routerops.tools.backends.base import RouterBackend
from routerops.tools.registry import ToolRegistry


class ToolFacade:
    def __init__(
        self,
        backend: RouterBackend,
        registry: ToolRegistry,
        policy: SafetyPolicy,
        evidence: EvidenceStore,
        mode: RunMode,
    ) -> None:
        self.backend = backend
        self.registry = registry
        self.policy = policy
        self.evidence = evidence
        self.mode = mode
        self._write_lock = threading.Lock()

    def invoke(
        self, call: ToolCall, approval: ApprovalRequest | None = None
    ) -> ToolResult:
        try:
            spec = self.registry.get(call.name)
            self.policy.authorize(
                spec,
                self.mode,
                call.arguments,
                approval,
                call.user_notified,
            )
            lock = self._write_lock if spec.risk.value > 0 else _NullLock()
            with lock:
                raw = self.backend.execute(call.name, call.arguments)
            safe = redact(raw)
            encoded = json.dumps(safe, ensure_ascii=False, default=str).encode()
            warnings: list[str] = []
            if len(encoded) > spec.max_output_bytes:
                safe = {"truncated": True, "bytes": len(encoded)}
                warnings.append("output exceeded the tool limit and was not retained")
            evidence_ref = self.evidence.write(call.name, safe)
            return ToolResult(
                status=ToolStatus.OK,
                data=safe,
                evidence_ref=evidence_ref,
                warnings=warnings,
            )
        except (KeyError, ValueError, RuntimeError, SafetyError) as exc:
            return ToolResult(
                status=ToolStatus.DENIED if isinstance(exc, SafetyError) else ToolStatus.ERROR,
                error=str(redact(str(exc))),
            )


class _NullLock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None

