from dataclasses import dataclass
from typing import Any


class ReadonlyCommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReadonlyCommand:
    tool: str
    command: str


_NO_ARGUMENT_COMMANDS = {
    "get_system_info": "ubus call system board",
    "get_cpu_temp": (
        "for f in /sys/class/thermal/thermal_zone*/temp; do "
        "[ -r \"$f\" ] && printf '%s=' \"$f\" && cat \"$f\"; done"
    ),
    "get_memory": "cat /proc/meminfo; printf '\\n--SWAPS--\\n'; cat /proc/swaps",
    "get_storage": "df -Pk / /tmp 2>/dev/null",
    "get_uptime": "cat /proc/uptime",
    "get_interfaces": "ubus call network.interface dump",
    "get_routes": (
        "printf '%s\\n' '--IPV4--'; ip -4 route show table all; "
        "printf '%s\\n' '--IPV6--'; ip -6 route show table all"
    ),
    "get_dns": (
        "printf '%s\\n' '--RESOLV--'; "
        "(cat /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null || cat /etc/resolv.conf); "
        "printf '%s\\n' '--LOOKUP--'; nslookup connectivitycheck.gstatic.com 127.0.0.1"
    ),
    "get_dhcp": (
        "ubus call network.interface dump; printf '\\n--LEASES--\\n'; "
        "cat /tmp/dhcp.leases 2>/dev/null"
    ),
    "get_firewall": (
        "command -v nft 2>/dev/null || command -v iptables 2>/dev/null; "
        "uci -q show firewall | "
        "grep -E '\\.(name|input|output|forward|masq|network)='"
    ),
    "get_usb_devices": "lsusb 2>/dev/null || cat /sys/kernel/debug/usb/devices 2>/dev/null",
    "get_usb_logs": "dmesg | grep -Ei 'usb|rndis|cdc|qmi|mbim' | tail -n 200",
    "get_usb_network_devices": (
        "for n in /sys/class/net/*; do "
        "p=$(readlink -f \"$n/device\" 2>/dev/null); "
        "case \"$p\" in *usb*) printf '%s|%s\\n' \"${n##*/}\" \"$p\";; esac; done"
    ),
    "get_f50_status": (
        "printf '%s\\n' '--USB--'; (lsusb 2>/dev/null || true); "
        "printf '%s\\n' '--NET--'; ip -o addr show; "
        "printf '%s\\n' '--ROUTE--'; ip route show"
    ),
    "get_openclash_status": (
        "printf '%s\\n' '--PACKAGES--'; "
        "(opkg list-installed 2>/dev/null || apk info 2>/dev/null) | grep -Ei 'openclash|mihomo|clash'; "
        "printf '%s\\n' '--PROCESSES--'; ps w | grep -Ei '[m]ihomo|[c]lash'"
    ),
    "get_openclash_version": (
        "(opkg list-installed 2>/dev/null || apk info -v 2>/dev/null) | "
        "grep -Ei 'openclash|mihomo|clash'; ps w | grep -Ei '[m]ihomo|[c]lash'"
    ),
    "get_openclash_process": "ps w | grep -Ei '[m]ihomo|[c]lash'",
    "get_openclash_logs": (
        "logread | grep -Ei 'openclash|mihomo|clash|fake-ip|tun' | tail -n 300"
    ),
    "get_openclash_config": (
        "printf '%s\\n' '--PROCESS--'; ps w | grep -Ei '[m]ihomo|[c]lash'; "
        "printf '%s\\n' '--UCI--'; uci -q show | grep -Ei 'openclash' | "
        "grep -E '\\.(enable|en_mode|proxy_mode|network_type|ipv6_enable|"
        "enable_redirect_dns|enable_custom_dns|small_flash_memory|core_type)='; "
        "printf '%s\\n' '--RUNTIME-SAFE--'; "
        "cfg=$(ps w | grep -Ei '[m]ihomo|[c]lash' | "
        "sed -n 's/.* \\(-f\\|--config\\) \\([^ ]*\\).*/\\2/p' | head -n 1); "
        "case \"$cfg\" in /*) [ -r \"$cfg\" ] && "
        "grep -E '^(mode|ipv6|geodata-mode|geo-auto-update|rule-providers|"
        "proxy-groups|tun|dns):' \"$cfg\";; esac"
    ),
    "test_openclash": (
        "printf '%s\\n' '--PROCESS--'; ps w | grep -Ei '[m]ihomo|[c]lash'; "
        "printf '%s\\n' '--SOCKETS--'; "
        "(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null) | "
        "grep -Ei 'mihomo|clash|789|9090'"
    ),
    "get_vps_status": "printf '%s\\n' 'not_configured'",
    "get_security_status": (
        "printf '%s\\n' '--LISTENERS--'; "
        "(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null); "
        "printf '%s\\n' '--DROPBEAR--'; "
        "uci -q show dropbear | grep -E '\\.(Interface|Port|PasswordAuth|RootPasswordAuth)='"
    ),
    "get_services": (
        "for f in /etc/init.d/*; do [ -x \"$f\" ] && basename \"$f\"; done | sort"
    ),
    "get_uci_capability": (
        "command -v uci >/dev/null 2>&1 && printf '%s\\n' 'uci=available' || "
        "printf '%s\\n' 'uci=missing'; "
        "command -v ubus >/dev/null 2>&1 && printf '%s\\n' 'ubus=available' || "
        "printf '%s\\n' 'ubus=missing'"
    ),
}

_TARGET_COMMANDS = {
    "ping": {
        "1.1.1.1": "ping -c 3 -W 2 1.1.1.1",
        "www.cloudflare.com": "ping -c 3 -W 2 www.cloudflare.com",
        "connectivitycheck.gstatic.com": (
            "ping -c 3 -W 2 connectivitycheck.gstatic.com"
        ),
    },
    "traceroute": {
        "1.1.1.1": "traceroute -m 12 -w 2 1.1.1.1",
        "www.cloudflare.com": "traceroute -m 12 -w 2 www.cloudflare.com",
        "connectivitycheck.gstatic.com": (
            "traceroute -m 12 -w 2 connectivitycheck.gstatic.com"
        ),
    },
    "curl_test": {
        "1.1.1.1": "curl -fsSI --max-time 8 https://1.1.1.1/",
        "www.cloudflare.com": "curl -fsSI --max-time 8 https://www.cloudflare.com/",
        "connectivitycheck.gstatic.com": (
            "curl -fsSI --max-time 8 https://connectivitycheck.gstatic.com/generate_204"
        ),
    },
}


class ReadonlyCommandRegistry:
    def tools(self) -> frozenset[str]:
        return frozenset(_NO_ARGUMENT_COMMANDS) | frozenset(_TARGET_COMMANDS)

    def resolve(self, tool: str, arguments: dict[str, Any]) -> ReadonlyCommand:
        if tool in _NO_ARGUMENT_COMMANDS:
            if arguments:
                raise ReadonlyCommandError("read-only command takes no arguments")
            return ReadonlyCommand(tool=tool, command=_NO_ARGUMENT_COMMANDS[tool])
        if tool in _TARGET_COMMANDS:
            if set(arguments) != {"target"}:
                raise ReadonlyCommandError("probe requires exactly one allowlisted target")
            command = _TARGET_COMMANDS[tool].get(str(arguments["target"]))
            if command is None:
                raise ReadonlyCommandError("probe target is not allowlisted")
            return ReadonlyCommand(tool=tool, command=command)
        raise ReadonlyCommandError("tool is not in the real-device read-only allowlist")

