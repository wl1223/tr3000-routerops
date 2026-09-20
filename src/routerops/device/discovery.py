import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from routerops.models import ToolCall, ToolStatus
from routerops.tools.facade import ToolFacade


class DeviceCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    readonly: Literal[True] = True
    permission_level: Literal[0] = 0
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    model: str
    firmware: str
    kernel: str
    architecture: str
    platform: str
    model_matches_expectation: bool
    firmware_matches_expectation: bool
    available_tools: list[str]
    unavailable_tools: list[str]
    services: list[str]
    uci_available: bool
    ubus_available: bool
    usb_devices: list[dict[str, Any]]
    usb_network_devices: list[dict[str, Any]]
    openclash: dict[str, Any]


DISCOVERY_TOOLS = (
    "get_system_info",
    "get_services",
    "get_uci_capability",
    "get_usb_devices",
    "get_usb_network_devices",
    "get_openclash_status",
    "get_openclash_version",
    "get_openclash_process",
    "get_openclash_config",
)


class CapabilityDiscovery:
    def discover(
        self,
        facade: ToolFacade,
        device_id: str,
        model_expectation: str,
        firmware_expectation: str,
    ) -> DeviceCapabilities:
        workflow_id = f"probe-{uuid.uuid4().hex[:12]}"
        observations: dict[str, dict[str, Any]] = {}
        available: list[str] = []
        unavailable: list[str] = []
        for name in DISCOVERY_TOOLS:
            result = facade.invoke(ToolCall(name=name, workflow_id=workflow_id))
            if result.status == ToolStatus.OK:
                available.append(name)
                observations[name] = result.data
            else:
                unavailable.append(name)
        system = observations.get("get_system_info", {})
        services = observations.get("get_services", {}).get("services", [])
        uci = observations.get("get_uci_capability", {})
        openclash = {
            "status": observations.get("get_openclash_status", {}),
            "version": observations.get("get_openclash_version", {}),
            "process": observations.get("get_openclash_process", {}),
            "config": observations.get("get_openclash_config", {}),
        }
        model = str(system.get("model", "unknown"))
        firmware = str(system.get("firmware", "unknown"))
        return DeviceCapabilities(
            device_id=device_id,
            model=model,
            firmware=firmware,
            kernel=str(system.get("kernel", "unknown")),
            architecture=str(system.get("architecture", system.get("cpu", "unknown"))),
            platform=str(system.get("platform", "unknown")),
            model_matches_expectation=model_expectation.lower() in model.lower(),
            firmware_matches_expectation=firmware_expectation.lower() in firmware.lower(),
            available_tools=sorted(available),
            unavailable_tools=sorted(unavailable),
            services=[str(item) for item in services],
            uci_available=bool(uci.get("uci")),
            ubus_available=bool(uci.get("ubus")),
            usb_devices=list(observations.get("get_usb_devices", {}).get("devices", [])),
            usb_network_devices=list(
                observations.get("get_usb_network_devices", {}).get("interfaces", [])
            ),
            openclash=openclash,
        )

