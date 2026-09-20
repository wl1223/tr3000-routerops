import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from routerops.models import ToolCall, ToolStatus
from routerops.tools.facade import ToolFacade


class CapabilityEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    available: bool | None
    version: str | None = None
    confidence: Literal["observed", "unknown"]
    source: str


class DeviceCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    readonly: Literal[True] = True
    permission_level: Literal[0] = 0
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    os: str
    model: str
    firmware: str
    kernel: str
    architecture: str
    platform: str
    model_matches_expectation: bool | None
    firmware_matches_expectation: bool | None
    available_tools: list[str]
    unavailable_tools: list[str]
    unsupported_tools: list[str]
    unknown_tools: list[str]
    services: list[str]
    uci_available: bool | None
    ubus_available: bool | None
    usb_devices: list[dict[str, Any]]
    usb_network_devices: list[dict[str, Any]]
    openclash: dict[str, Any]
    capabilities: dict[str, CapabilityEntry]


DISCOVERY_TOOLS = (
    "get_system_info",
    "get_cpu_temp",
    "get_memory",
    "get_storage",
    "get_interfaces",
    "get_routes",
    "get_dns",
    "get_dhcp",
    "get_firewall",
    "get_services",
    "get_uci_capability",
    "get_usb_devices",
    "get_usb_network_devices",
    "get_f50_status",
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
        unsupported: list[str] = []
        unknown: list[str] = []
        for name in DISCOVERY_TOOLS:
            result = facade.invoke(ToolCall(name=name, workflow_id=workflow_id))
            observation_available = result.data.get("_meta", {}).get("available", True)
            if result.status == ToolStatus.OK and observation_available:
                available.append(name)
                observations[name] = result.data
            else:
                unavailable.append(name)
                if result.status == ToolStatus.OK:
                    observations[name] = result.data
                    reason = result.data.get("_meta", {}).get("reason")
                    if reason == "command_unavailable_or_unsupported":
                        unsupported.append(name)
                    else:
                        unknown.append(name)
                else:
                    unknown.append(name)
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
        tool_capabilities = {
            name: self._tool_capability(name, observations.get(name))
            for name in DISCOVERY_TOOLS
        }
        status = openclash["status"]
        process = openclash["process"]
        version = openclash["version"]
        semantic_capabilities = {
            "openclash": CapabilityEntry(
                name="openclash",
                available=True if status.get("installed") else None,
                version=version.get("plugin"),
                confidence="observed" if status.get("installed") else "unknown",
                source="get_openclash_status",
            ),
            "mihomo_core": CapabilityEntry(
                name="mihomo_core",
                available=True if process.get("running") else None,
                version=version.get("core"),
                confidence="observed" if process.get("running") else "unknown",
                source="get_openclash_process",
            ),
            "f50": CapabilityEntry(
                name="f50",
                available=(
                    True
                    if any(
                        item.get("is_f50")
                        for item in observations.get("get_usb_devices", {}).get(
                            "devices", []
                        )
                    )
                    else None
                ),
                confidence=(
                    "observed"
                    if any(
                        item.get("is_f50")
                        for item in observations.get("get_usb_devices", {}).get(
                            "devices", []
                        )
                    )
                    else "unknown"
                ),
                source="get_usb_devices",
            ),
            "uci": self._boolean_capability("uci", uci.get("uci"), "get_uci_capability"),
            "ubus": self._boolean_capability(
                "ubus", uci.get("ubus"), "get_uci_capability"
            ),
        }
        capabilities = {**tool_capabilities, **semantic_capabilities}
        model_match = (
            model_expectation.lower() in model.lower() if model != "unknown" else None
        )
        firmware_match = (
            firmware_expectation.lower() in firmware.lower()
            if firmware != "unknown"
            else None
        )
        return DeviceCapabilities(
            device_id=device_id,
            os=str(system.get("os", "unknown")),
            model=model,
            firmware=firmware,
            kernel=str(system.get("kernel", "unknown")),
            architecture=str(system.get("architecture", system.get("cpu", "unknown"))),
            platform=str(system.get("platform", "unknown")),
            model_matches_expectation=model_match,
            firmware_matches_expectation=firmware_match,
            available_tools=sorted(available),
            unavailable_tools=sorted(unavailable),
            unsupported_tools=sorted(set(unsupported)),
            unknown_tools=sorted(set(unknown)),
            services=[str(item) for item in services],
            uci_available=uci.get("uci") if "uci" in uci else None,
            ubus_available=uci.get("ubus") if "ubus" in uci else None,
            usb_devices=list(observations.get("get_usb_devices", {}).get("devices", [])),
            usb_network_devices=list(
                observations.get("get_usb_network_devices", {}).get("interfaces", [])
            ),
            openclash=openclash,
            capabilities=capabilities,
        )

    @staticmethod
    def _tool_capability(
        name: str, observation: dict[str, Any] | None
    ) -> CapabilityEntry:
        if observation is None:
            return CapabilityEntry(
                name=name,
                available=None,
                confidence="unknown",
                source=name,
            )
        metadata = observation.get("_meta")
        if not isinstance(metadata, dict):
            return CapabilityEntry(
                name=name,
                available=True,
                confidence="observed",
                source=name,
            )
        if metadata.get("available"):
            return CapabilityEntry(
                name=name,
                available=True,
                confidence="observed",
                source=name,
            )
        if metadata.get("reason") == "command_unavailable_or_unsupported":
            return CapabilityEntry(
                name=name,
                available=False,
                confidence="observed",
                source=name,
            )
        return CapabilityEntry(
            name=name,
            available=None,
            confidence="unknown",
            source=name,
        )

    @staticmethod
    def _boolean_capability(
        name: str, value: Any, source: str
    ) -> CapabilityEntry:
        if isinstance(value, bool):
            return CapabilityEntry(
                name=name,
                available=value,
                confidence="observed",
                source=source,
            )
        return CapabilityEntry(
            name=name,
            available=None,
            confidence="unknown",
            source=source,
        )

