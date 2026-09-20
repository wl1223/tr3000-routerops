import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any


class MockRouterBackend:
    device_id = "mock-tr3000-v1"
    readonly = False
    mutation_tools = {
        "restore_backup",
        "uci_set",
        "restart_openclash",
        "restart_dns",
        "restart_network",
    }

    def __init__(self, scenario: str = "healthy", scenario_dir: Path | None = None) -> None:
        root = scenario_dir or Path(__file__).parents[4] / "mock" / "scenarios"
        path = root / f"{scenario}.json"
        if not path.exists():
            available = ", ".join(sorted(item.stem for item in root.glob("*.json")))
            raise ValueError(f"unknown mock scenario {scenario!r}; available: {available}")
        base = json.loads((root / "healthy.json").read_text())
        overlay = json.loads(path.read_text())
        self.state = _deep_merge(base, overlay)
        self._backups: dict[str, dict[str, Any]] = {}

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.state)

    def restore(self, state: dict[str, Any]) -> None:
        if state.get("system", {}).get("model") != self.state.get("system", {}).get("model"):
            raise ValueError("backup belongs to a different device model")
        self.state = copy.deepcopy(state)

    def execute_readonly(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool in self.mutation_tools:
            raise RuntimeError("mutation tool cannot use the read-only adapter path")
        return self._execute_registered(tool, arguments)

    def execute_mutation(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool not in self.mutation_tools:
            raise RuntimeError("read-only tool cannot use the mutation adapter path")
        return self._execute_registered(tool, arguments)

    def _execute_registered(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.state.get("faults", {}).get(f"error_{tool}"):
            raise RuntimeError(f"injected failure for {tool}")
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "get_system_info": lambda: self.state["system"],
            "get_cpu_temp": lambda: {"celsius": self.state["system"]["temperature_c"]},
            "get_memory": lambda: self.state["memory"],
            "get_storage": lambda: self.state["storage"],
            "get_uptime": lambda: {"seconds": self.state["system"]["uptime_seconds"]},
            "get_services": lambda: {
                "services": ["network", "firewall", "dnsmasq", "openclash", "dropbear"]
            },
            "get_uci_capability": lambda: {"uci": True, "ubus": True},
            "get_interfaces": lambda: {"interfaces": self.state["interfaces"]},
            "get_routes": lambda: {"routes": self.state["routes"]},
            "get_dns": lambda: self.state["dns"],
            "get_dhcp": lambda: self.state["dhcp"],
            "get_firewall": lambda: self.state["firewall"],
            "get_usb_devices": lambda: {"devices": self.state["usb"]["devices"]},
            "get_usb_logs": lambda: {"lines": self.state["usb"]["logs"]},
            "get_usb_network_devices": lambda: {"interfaces": self.state["usb"]["network_devices"]},
            "get_f50_status": lambda: self.state["f50"],
            "get_openclash_status": lambda: self.state["openclash"]["status"],
            "get_openclash_version": lambda: self.state["openclash"]["version"],
            "get_openclash_process": lambda: self.state["openclash"]["process"],
            "get_openclash_logs": lambda: {"lines": self.state["openclash"]["logs"]},
            "get_openclash_config": lambda: self.state["openclash"]["config"],
            "test_openclash": lambda: self.state["openclash"]["test"],
            "get_vps_status": lambda: self.state["vps"],
            "get_security_status": lambda: self.state["security"],
            "ping": lambda: self._probe("ping", arguments),
            "traceroute": lambda: self._probe("traceroute", arguments),
            "curl_test": lambda: self._probe("curl", arguments),
            "uci_get": lambda: self._uci_get(arguments),
            "uci_show": lambda: {"config": copy.deepcopy(self.state["uci"])},
            "uci_export": lambda: {"config": copy.deepcopy(self.state["uci"])},
            "uci_diff": lambda: {"changes": copy.deepcopy(self.state.get("uci_diff", []))},
            "uci_set": lambda: self._uci_set(arguments),
            "backup_config": lambda: self._backup(arguments),
            "list_backups": lambda: {"backups": sorted(self._backups)},
            "restore_backup": lambda: self._restore_backup(arguments),
            "restart_openclash": lambda: self._restart("openclash"),
            "restart_dns": lambda: self._restart("dns"),
            "restart_network": lambda: self._restart("network"),
        }
        if tool not in handlers:
            raise ValueError(f"mock backend does not implement registered tool {tool}")
        return copy.deepcopy(handlers[tool]())

    def _probe(self, kind: str, arguments: dict[str, Any]) -> dict[str, Any]:
        target = str(arguments.get("target", ""))
        probes = self.state.get("probes", {})
        probe = probes.get(target, probes.get("default"))
        return {"probe": kind, "target": target, **(probe or {"success": False})}

    def _uci_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        package = str(arguments["package"])
        section = str(arguments.get("section", ""))
        option = str(arguments.get("option", ""))
        current: Any = self.state["uci"].get(package)
        if section and isinstance(current, dict):
            current = current.get(section)
        if option and isinstance(current, dict):
            current = current.get(option)
        if (
            self.state.get("faults", {}).get("verify_fail")
            and package == "dhcp"
            and option == "cachesize"
            and current == "800"
        ):
            current = "verification-mismatch"
        return {"value": current}

    def _uci_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
        package = str(arguments["package"])
        section = str(arguments["section"])
        option = str(arguments["option"])
        value = str(arguments["value"])
        before = self.state["uci"].setdefault(package, {}).setdefault(section, {}).get(option)
        self.state["uci"][package][section][option] = value
        self.state.setdefault("uci_diff", []).append(
            {"path": f"{package}.{section}.{option}", "before": before, "after": value}
        )
        return {"changed": True, "before": before, "after": value}

    def _backup(self, arguments: dict[str, Any]) -> dict[str, Any]:
        backup_id = str(arguments["backup_id"])
        self._backups[backup_id] = self.snapshot()
        return {"backup_id": backup_id, "created": True}

    def _restore_backup(self, arguments: dict[str, Any]) -> dict[str, Any]:
        backup_id = str(arguments["backup_id"])
        if backup_id not in self._backups:
            raise ValueError("backup not found")
        self.restore(self._backups[backup_id])
        return {"backup_id": backup_id, "restored": True}

    def _restart(self, service: str) -> dict[str, Any]:
        if service == "openclash":
            self.state["openclash"]["status"]["running"] = True
        self.state.setdefault("service_restarts", []).append(service)
        return {"service": service, "restarted": True}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result

