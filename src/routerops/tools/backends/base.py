from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RouterBackend(Protocol):
    device_id: str
    readonly: bool

    def execute_readonly(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a registered read-only tool, never a command string."""
        ...


@runtime_checkable
class MutableRouterBackend(RouterBackend, Protocol):
    readonly: bool

    def execute_mutation(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a registered mutation after the facade authorizes it."""
        ...

    def snapshot(self) -> dict[str, Any]:
        """Return a deep-copy-compatible complete state."""
        ...

    def restore(self, state: dict[str, Any]) -> None:
        """Restore a compatible state snapshot."""
        ...

