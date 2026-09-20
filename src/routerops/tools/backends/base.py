from typing import Any, Protocol


class RouterBackend(Protocol):
    device_id: str

    def execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a registered tool, never an arbitrary command."""
        ...

    def snapshot(self) -> dict[str, Any]:
        """Return a deep-copy-compatible complete state."""
        ...

    def restore(self, state: dict[str, Any]) -> None:
        """Restore a compatible state snapshot."""
        ...

