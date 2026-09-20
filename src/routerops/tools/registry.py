from routerops.models import RiskLevel, RunMode, ToolSpec

NO_ARGUMENTS: dict[str, object] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def input_schema(name: str) -> dict[str, object]:
    if name in {"ping", "traceroute", "curl_test"}:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "enum": [
                        "1.1.1.1",
                        "www.cloudflare.com",
                        "connectivitycheck.gstatic.com",
                    ],
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        }
    if name == "uci_get":
        return {
            "type": "object",
            "properties": {
                key: {"type": "string", "pattern": "^[A-Za-z0-9_@-]{1,64}$"}
                for key in ("package", "section", "option")
            },
            "required": ["package"],
            "additionalProperties": False,
        }
    if name == "uci_set":
        properties = {
            key: {"type": "string", "maxLength": 2048}
            for key in ("package", "section", "option", "value")
        }
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }
    if name in {"backup_config", "restore_backup"}:
        return {
            "type": "object",
            "properties": {
                "backup_id": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9_@-]{1,64}$",
                }
            },
            "required": ["backup_id"],
            "additionalProperties": False,
        }
    return dict(NO_ARGUMENTS)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"duplicate tool: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"tool is not registered: {name}")
        return self._tools[name]

    def specs(self) -> list[ToolSpec]:
        return list(self._tools.values())


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    groups = {
        "system": [
            "get_system_info",
            "get_cpu_temp",
            "get_memory",
            "get_storage",
            "get_uptime",
        ],
        "network": [
            "get_interfaces",
            "get_routes",
            "get_dns",
            "get_dhcp",
            "get_firewall",
            "ping",
            "traceroute",
            "curl_test",
        ],
        "usb": [
            "get_usb_devices",
            "get_usb_logs",
            "get_usb_network_devices",
            "get_f50_status",
        ],
        "openclash": [
            "get_openclash_status",
            "get_openclash_version",
            "get_openclash_process",
            "get_openclash_logs",
            "get_openclash_config",
            "test_openclash",
        ],
        "uci": ["uci_get", "uci_show", "uci_export", "uci_diff"],
        "diagnostics": ["get_vps_status", "get_security_status"],
    }
    for capability, names in groups.items():
        for name in names:
            registry.register(
                ToolSpec(
                    name=name,
                    description=f"Read-only {name.replace('_', ' ')}",
                    risk=RiskLevel.READ_ONLY,
                    min_mode=RunMode.DIAGNOSE,
                    capability=capability,
                    input_schema=input_schema(name),
                )
            )
    for name in ("restart_openclash", "restart_dns"):
        registry.register(
            ToolSpec(
                name=name,
                description=f"Restart the allowlisted {name.removeprefix('restart_')} service",
                risk=RiskLevel.LOW,
                min_mode=RunMode.SEMI_AUTO,
                capability="service",
                input_schema=input_schema(name),
            )
        )
    registry.register(
        ToolSpec(
            name="backup_config",
            description="Create an immutable RouterOps backup without changing router state",
            risk=RiskLevel.READ_ONLY,
            min_mode=RunMode.ADVISE,
            capability="backup",
            input_schema=input_schema("backup_config"),
        )
    )
    for name in ("restore_backup", "uci_set", "restart_network"):
        registry.register(
            ToolSpec(
                name=name,
                description=f"Protected change operation: {name}",
                risk=RiskLevel.HIGH,
                min_mode=RunMode.MAINTENANCE,
                capability="change",
                input_schema=input_schema(name),
            )
        )
    registry.register(
        ToolSpec(
            name="list_backups",
            description="List RouterOps-created backups",
            risk=RiskLevel.READ_ONLY,
            min_mode=RunMode.DIAGNOSE,
            capability="backup",
            input_schema=input_schema("list_backups"),
        )
    )
    return registry

