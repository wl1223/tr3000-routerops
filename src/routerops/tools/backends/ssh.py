"""Phase-two SSH contract.

This module intentionally contains no connection implementation. A future backend must
pin the server host key and map registered tools to fixed command templates. It must
never expose an arbitrary command execution method.
"""

from typing import Any


class SSHBackendDisabled:
    device_id = "disabled"

    def execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        del tool, arguments
        raise RuntimeError("real SSH is disabled in phase one")

    def snapshot(self) -> dict[str, Any]:
        raise RuntimeError("real SSH is disabled in phase one")

    def restore(self, state: dict[str, Any]) -> None:
        del state
        raise RuntimeError("real SSH is disabled in phase one")

