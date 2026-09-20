import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from routerops.observability.redaction import redact


@dataclass(frozen=True, repr=False)
class RawObservation:
    tool: str
    stdout: str
    stderr: str
    exit_code: int


class ObservationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SystemObservation(ObservationModel):
    model: str
    firmware: str
    kernel: str
    architecture: str
    platform: str
    cpu: str


class MemoryObservation(ObservationModel):
    total_mb: int
    available_mb: int
    swap_total_mb: int
    swap_free_mb: int
    oom_events: list[str] = Field(default_factory=list)


class StorageObservation(ObservationModel):
    filesystems: list[dict[str, Any]]


class InterfacesObservation(ObservationModel):
    interfaces: list[dict[str, Any]]


class RoutesObservation(ObservationModel):
    routes: list[dict[str, Any]]


class DNSObservation(ObservationModel):
    service: str
    listeners: list[str]
    upstreams: list[str]
    resolution_ok: bool
    ipv6_enabled: bool


class USBObservation(ObservationModel):
    devices: list[dict[str, Any]]


class NormalizationError(RuntimeError):
    pass


def normalize_observation(raw: RawObservation) -> dict[str, Any]:
    stdout = str(redact(raw.stdout))
    stderr = str(redact(raw.stderr))
    parsers = {
        "get_system_info": _system,
        "get_cpu_temp": _temperature,
        "get_memory": _memory,
        "get_storage": _storage,
        "get_uptime": _uptime,
        "get_interfaces": _interfaces,
        "get_routes": _routes,
        "get_dns": _dns,
        "get_dhcp": _dhcp,
        "get_firewall": _firewall,
        "get_usb_devices": _usb_devices,
        "get_usb_logs": lambda text, _err, _code: {"lines": text.splitlines()},
        "get_usb_network_devices": _usb_network,
        "get_f50_status": _f50_status,
        "get_openclash_status": _openclash_status,
        "get_openclash_version": _openclash_version,
        "get_openclash_process": _openclash_process,
        "get_openclash_logs": lambda text, _err, _code: {"lines": text.splitlines()},
        "get_openclash_config": _openclash_config,
        "test_openclash": _openclash_test,
        "get_vps_status": _vps,
        "get_security_status": _security,
        "get_services": _services,
        "get_uci_capability": _uci_capability,
        "ping": _probe,
        "traceroute": _probe,
        "curl_test": _probe,
    }
    parser = parsers.get(raw.tool)
    if parser is None:
        raise NormalizationError("no normalizer for read-only tool")
    result = parser(stdout, stderr, raw.exit_code)
    return dict(redact(result))


def _json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NormalizationError("device returned invalid structured output") from exc
    if not isinstance(value, dict):
        raise NormalizationError("device output must be a JSON object")
    return value


def _system(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    value = _json(text)
    release = value.get("release", {})
    if not isinstance(release, dict):
        release = {}
    system = SystemObservation(
        model=str(value.get("model", "unknown")),
        firmware=str(release.get("description", release.get("version", "unknown"))),
        kernel=str(value.get("kernel", "unknown")),
        architecture=str(value.get("system", "unknown")),
        platform=str(release.get("target", value.get("board_name", "unknown"))),
        cpu=str(value.get("system", "unknown")),
    )
    return system.model_dump()


def _temperature(text: str, _stderr: str, code: int) -> dict[str, Any]:
    values = []
    for line in text.splitlines():
        match = re.search(r"=(-?\d+)", line)
        if match:
            value = float(match.group(1))
            values.append(value / 1000 if abs(value) > 1000 else value)
    return {"celsius": max(values) if values else None, "available": bool(values) and code == 0}


def _meminfo(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.split("--SWAPS--", 1)[0].splitlines():
        match = re.match(r"^(\w+):\s+(\d+)", line)
        if match:
            result[match.group(1)] = int(match.group(2))
    return result


def _memory(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    values = _meminfo(text)
    observation = MemoryObservation(
        total_mb=values.get("MemTotal", 0) // 1024,
        available_mb=values.get("MemAvailable", values.get("MemFree", 0)) // 1024,
        swap_total_mb=values.get("SwapTotal", 0) // 1024,
        swap_free_mb=values.get("SwapFree", 0) // 1024,
    )
    return observation.model_dump()


def _storage(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    filesystems: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6 and fields[1].isdigit():
            filesystems.append(
                {
                    "filesystem": fields[0],
                    "total_kb": int(fields[1]),
                    "available_kb": int(fields[3]),
                    "mountpoint": fields[-1],
                }
            )
    return StorageObservation(filesystems=filesystems).model_dump()


def _uptime(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    try:
        seconds = int(float(text.split()[0]))
    except (IndexError, ValueError):
        seconds = 0
    return {"seconds": seconds}


def _interface_rows(text: str) -> list[dict[str, Any]]:
    value = _json(text.split("--LEASES--", 1)[0].strip())
    rows = value.get("interface", [])
    if not isinstance(rows, list):
        return []
    interfaces: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ipv4 = [
            f"{item.get('address')}/{item.get('mask')}"
            for item in row.get("ipv4-address", [])
            if isinstance(item, dict) and item.get("address")
        ]
        ipv6 = [
            f"{item.get('address')}/{item.get('mask')}"
            for item in row.get("ipv6-address", [])
            if isinstance(item, dict) and item.get("address")
        ]
        interfaces.append(
            {
                "name": str(row.get("l3_device") or row.get("device") or row.get("interface")),
                "logical_name": str(row.get("interface", "")),
                "up": bool(row.get("up", False)),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "proto": str(row.get("proto", "")),
            }
        )
    return interfaces


def _interfaces(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    return InterfacesObservation(interfaces=_interface_rows(text)).model_dump()


def _routes(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    family = "ipv4"
    routes: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line == "--IPV4--":
            family = "ipv4"
            continue
        if line == "--IPV6--":
            family = "ipv6"
            continue
        fields = line.split()
        if not fields:
            continue
        default = fields[0] == "default"
        interface = fields[fields.index("dev") + 1] if "dev" in fields else None
        gateway = fields[fields.index("via") + 1] if "via" in fields else None
        routes.append(
            {
                "destination": fields[0],
                "default": default,
                "interface": interface,
                "gateway": gateway,
                "family": family,
            }
        )
    return RoutesObservation(routes=routes).model_dump()


def _dns(text: str, _stderr: str, code: int) -> dict[str, Any]:
    resolv, _, lookup = text.partition("--LOOKUP--")
    upstreams = re.findall(r"^nameserver\s+(\S+)", resolv, re.M)
    success = code == 0 and bool(re.search(r"(?im)^Address(?: \d+)?:\s+\S+", lookup))
    return DNSObservation(
        service="discovered",
        listeners=["127.0.0.1:53"],
        upstreams=upstreams,
        resolution_ok=success,
        ipv6_enabled=bool(re.search(r"(?i)(?:AAAA|[0-9a-f]{0,4}:){2,}", lookup)),
    ).model_dump()


def _dhcp(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    interfaces = _interface_rows(text)
    wan = next(
        (
            item
            for item in interfaces
            if item["logical_name"] in {"wan", "wwan"} or item["proto"] == "dhcp"
        ),
        None,
    )
    return {
        "lan_server": "--LEASES--" in text,
        "wan_client": wan is not None,
        "wan_lease": wan["ipv4"][0].split("/", 1)[0] if wan and wan["ipv4"] else None,
        "interfaces": interfaces,
    }


def _firewall(text: str, _stderr: str, code: int) -> dict[str, Any]:
    implementation = "nftables" if "nft" in text.splitlines()[:1] else "iptables"
    return {
        "implementation": implementation,
        "masquerade": bool(re.search(r"\.masq='?1'?", text)),
        "forwarding": code == 0,
        "summary": text.splitlines()[1:],
    }


def _usb_devices(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    devices = []
    for line in text.splitlines():
        lower = line.lower()
        devices.append(
            {
                "description": line,
                "is_f50": "f50" in lower or "zte" in lower or "19d2:" in lower,
            }
        )
    return USBObservation(devices=devices).model_dump()


def _usb_network(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    interfaces = []
    for line in text.splitlines():
        name, _, path = line.partition("|")
        if name:
            driver_match = re.search(r"/drivers/([^/]+)", path)
            interfaces.append(
                {
                    "name": name,
                    "driver": driver_match.group(1) if driver_match else "discovered-usb",
                    "up": True,
                }
            )
    return {"interfaces": interfaces}


def _f50_status(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    usb, _, remainder = text.partition("--NET--")
    net, _, routes = remainder.partition("--ROUTE--")
    usb_present = bool(re.search(r"(?i)f50|zte|19d2:", usb))
    address_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", net)
    route_match = re.search(r"default via (\S+) dev (\S+)", routes)
    return {
        "usb_present": usb_present,
        "driver": None,
        "interface": route_match.group(2) if route_match else None,
        "address": address_match.group(1) if address_match else None,
        "gateway": route_match.group(1) if route_match else None,
    }


def _openclash_status(text: str, _stderr: str, code: int) -> dict[str, Any]:
    lower = text.lower()
    return {
        "installed": "openclash" in lower,
        "running": bool(re.search(r"(?i)\b(mihomo|clash)\b", text.partition("--PROCESSES--")[2])),
        "mode": "discovered",
        "raw_available": code == 0,
    }


def _openclash_version(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    packages = [line for line in text.splitlines() if re.search(r"(?i)openclash|mihomo|clash", line)]
    return {"plugin": packages[0] if packages else None, "core": packages[1] if len(packages) > 1 else None}


def _openclash_process(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    lines = [line for line in text.splitlines() if line.strip()]
    return {
        "name": "mihomo" if any("mihomo" in line.lower() for line in lines) else "clash",
        "running": bool(lines),
        "processes": lines,
    }


def _openclash_config(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    process, _, after_process = text.partition("--UCI--")
    uci_text, _, runtime = after_process.partition("--RUNTIME-SAFE--")
    values: dict[str, str] = {}
    for line in uci_text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.rsplit(".", 1)[-1]] = value.strip("'\"")
    runtime_values: dict[str, str] = {}
    for line in runtime.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            runtime_values[key.strip()] = value.strip()
    mode = (
        runtime_values.get("mode")
        or values.get("en_mode")
        or values.get("proxy_mode")
        or "unknown"
    )
    location_match = re.search(r"(?:-f|--config)\s+(\S+)", process)
    return {
        "source": "discovered-uci-filtered",
        "config_location": location_match.group(1) if location_match else None,
        "run_mode": mode,
        "tun": "tun" in mode.lower() or "tun" in runtime_values,
        "redir": "redir" in mode.lower(),
        "fake_ip": "fake" in mode.lower(),
        "dns": values.get("enable_redirect_dns") == "1" or "dns" in runtime_values,
        "ipv4": True,
        "ipv6": values.get("ipv6_enable") == "1"
        or runtime_values.get("ipv6") == "true",
        "rule_providers": "present" if "rule-providers" in runtime_values else None,
        "geo": {
            key: value for key, value in runtime_values.items() if key.startswith("geo")
        },
        "proxy_groups": "present" if "proxy-groups" in runtime_values else None,
        "safe_options": values,
    }


def _openclash_test(text: str, _stderr: str, code: int) -> dict[str, Any]:
    process = text.partition("--SOCKETS--")[0]
    sockets = text.partition("--SOCKETS--")[2]
    running = bool(re.search(r"(?i)mihomo|clash", process))
    return {
        "success": code == 0 and running,
        "controller": bool(sockets.strip()),
        "dns": None,
        "rules": None,
    }


def _vps(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    return {"configured": "not_configured" not in text, "status": text.strip()}


def _security(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    listeners, _, dropbear = text.partition("--DROPBEAR--")
    return {
        "ssh_wan_exposed": bool(re.search(r"(?m)^(?:tcp\S*\s+){3,}0\.0\.0\.0:22", listeners)),
        "password_auth": "PasswordAuth='on'" in dropbear,
        "listeners": listeners.splitlines()[1:],
        "dropbear": dropbear.splitlines(),
    }


def _services(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    return {"services": [line for line in text.splitlines() if line.strip()]}


def _uci_capability(text: str, _stderr: str, _code: int) -> dict[str, Any]:
    return {
        "uci": "uci=available" in text,
        "ubus": "ubus=available" in text,
    }


def _probe(text: str, stderr: str, code: int) -> dict[str, Any]:
    latency = re.search(r"(?:time[=<])\s*([\d.]+)\s*ms", text)
    status = re.search(r"HTTP/\S+\s+(\d+)", text)
    return {
        "success": code == 0,
        "latency_ms": float(latency.group(1)) if latency else None,
        "status_code": int(status.group(1)) if status else None,
        "summary": text.splitlines()[-5:],
        "error": stderr.strip() or None,
    }

