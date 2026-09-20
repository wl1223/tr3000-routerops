from dataclasses import dataclass
from typing import Any


class ReadonlyCommandError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReadonlyCommand:
    tool: str
    command: str


_NO_ARGUMENT_COMMANDS = {
    "get_system_info": (
        "printf '%s\\n' '--BOARD--'; ubus call system board; "
        "printf '%s\\n' '--UNAME-M--'; uname -m 2>/dev/null || true; exit 0"
    ),
    "get_cpu_temp": (
        "for f in /sys/class/thermal/thermal_zone*/temp; do "
        "[ -r \"$f\" ] && printf '%s=' \"$f\" && cat \"$f\"; done; exit 0"
    ),
    "get_memory": (
        "cat /proc/meminfo; printf '\\n--SWAPS--\\n'; "
        "cat /proc/swaps 2>/dev/null || true"
    ),
    "get_storage": "df -Pk / /tmp 2>/dev/null",
    "get_uptime": "cat /proc/uptime",
    "get_interfaces": "ubus call network.interface dump",
    "get_routes": (
        "printf '%s\\n' '--IPV4--'; "
        "ip -4 route show table all 2>/dev/null || printf '%s\\n' '--IPV4-UNAVAILABLE--'; "
        "printf '%s\\n' '--IPV6--'; "
        "ip -6 route show table all 2>/dev/null || printf '%s\\n' '--IPV6-UNAVAILABLE--'; "
        "exit 0"
    ),
    "get_dns": (
        "printf '%s\\n' '--RESOLV--'; "
        "if [ -s /tmp/resolv.conf.d/resolv.conf.auto ]; then "
        "cat /tmp/resolv.conf.d/resolv.conf.auto; else cat /etc/resolv.conf 2>/dev/null; fi; "
        "printf '%s\\n' '--LOOKUP--'; "
        "nslookup connectivitycheck.gstatic.com 127.0.0.1 2>&1 || "
        "printf '%s\\n' '--LOOKUP-FAILED--'; exit 0"
    ),
    "get_dhcp": (
        "ubus call network.interface dump; printf '\\n--LEASES--\\n'; "
        "if [ -r /tmp/dhcp.leases ]; then printf '%s\\n' '--LEASES-PRESENT--'; "
        "cat /tmp/dhcp.leases; else printf '%s\\n' '--LEASES-UNAVAILABLE--'; fi; exit 0"
    ),
    "get_firewall": (
        "if command -v nft >/dev/null 2>&1; then printf '%s\\n' 'implementation=nftables'; "
        "elif command -v iptables >/dev/null 2>&1; then "
        "printf '%s\\n' 'implementation=iptables'; else "
        "printf '%s\\n' 'implementation=unknown'; fi; "
        "uci -q show firewall | "
        "grep -E '\\.(name|input|output|forward|masq|network)=' || true"
    ),
    "get_usb_devices": (
        "if command -v lsusb >/dev/null 2>&1; then lsusb; "
        "elif [ -r /sys/kernel/debug/usb/devices ]; then "
        "cat /sys/kernel/debug/usb/devices; else "
        "for d in /sys/bus/usb/devices/*; do "
        "[ -r \"$d/idVendor\" ] || continue; "
        "v=$(cat \"$d/idVendor\"); p=$(cat \"$d/idProduct\" 2>/dev/null); "
        "m=$(cat \"$d/manufacturer\" 2>/dev/null); n=$(cat \"$d/product\" 2>/dev/null); "
        "printf 'SYSFS|%s|%s|%s|%s\\n' \"$v\" \"$p\" \"$m\" \"$n\"; done; fi; exit 0"
    ),
    "get_usb_logs": (
        "if command -v dmesg >/dev/null 2>&1; then "
        "dmesg 2>&1 | grep -Ei 'usb|rndis|cdc|qmi|mbim' | tail -n 200 || true; "
        "else printf '%s\\n' '--DMESG-UNAVAILABLE--'; fi; exit 0"
    ),
    "get_usb_network_devices": (
        "for n in /sys/class/net/*; do "
        "p=$(readlink -f \"$n/device\" 2>/dev/null); "
        "case \"$p\" in *usb*) "
        "drv=$(basename \"$(readlink -f \"$n/device/driver\" 2>/dev/null)\" 2>/dev/null); "
        "state=$(cat \"$n/operstate\" 2>/dev/null); "
        "printf '%s|%s|%s|%s\\n' \"${n##*/}\" \"$p\" \"$drv\" \"$state\";; esac; "
        "done; exit 0"
    ),
    "get_f50_status": (
        "printf '%s\\n' '--USB--'; "
        "(lsusb 2>/dev/null || for d in /sys/bus/usb/devices/*; do "
        "[ -r \"$d/idVendor\" ] || continue; "
        "printf 'SYSFS|%s|%s|%s|%s\\n' \"$(cat \"$d/idVendor\")\" "
        "\"$(cat \"$d/idProduct\" 2>/dev/null)\" "
        "\"$(cat \"$d/manufacturer\" 2>/dev/null)\" "
        "\"$(cat \"$d/product\" 2>/dev/null)\"; done); "
        "printf '%s\\n' '--NET--'; ip addr show 2>/dev/null; "
        "printf '%s\\n' '--ROUTE--'; ip route show 2>/dev/null; exit 0"
    ),
    "get_openclash_status": (
        "printf '%s\\n' '--PACKAGES--'; "
        "(opkg list-installed 2>/dev/null || apk info 2>/dev/null) | "
        "grep -Ei 'openclash|mihomo|clash' || true; "
        "printf '%s\\n' '--PROCESSES--'; "
        "ps w | grep -Ei '[m]ihomo|[c]lash' || true; exit 0"
    ),
    "get_openclash_version": (
        "printf '%s\\n' '--PACKAGES--'; "
        "(opkg list-installed 2>/dev/null || apk info -v 2>/dev/null) | "
        "grep -Ei 'openclash|mihomo|clash' || true; "
        "printf '%s\\n' '--PROCESSES--'; "
        "ps w | grep -Ei '[m]ihomo|[c]lash' || true; exit 0"
    ),
    "get_openclash_process": "ps w | grep -Ei '[m]ihomo|[c]lash' || true; exit 0",
    "get_openclash_logs": (
        "if command -v logread >/dev/null 2>&1; then "
        "logread | grep -Ei 'openclash|mihomo|clash|fake-ip' | tail -n 300 || true; "
        "else printf '%s\\n' '--LOGREAD-UNAVAILABLE--'; fi; exit 0"
    ),
    "get_openclash_config": (
        "printf '%s\\n' '--PROCESS--'; ps w | grep -Ei '[m]ihomo|[c]lash'; "
        "printf '%s\\n' '--UCI--'; uci -q show | grep -Ei 'openclash' | "
        "grep -E '\\.(enable|en_mode|proxy_mode|network_type|ipv6_enable|"
        "enable_redirect_dns|enable_custom_dns|small_flash_memory|core_type)='; "
        "printf '%s\\n' '--RUNTIME-SAFE--'; "
        "cfg=$(ps w | grep -Ei '[m]ihomo|[c]lash' | "
        "sed -n -e 's/.* \\(-f\\|--config\\) \\([^ ]*\\).*/\\2/p' "
        "-e 's/.*--config=\\([^ ]*\\).*/\\1/p' -e 's/.*-f=\\([^ ]*\\).*/\\1/p' | "
        "head -n 1); "
        "case \"$cfg\" in /*) [ -r \"$cfg\" ] && "
        "grep -E '^(mode|ipv6|geodata-mode|geo-auto-update|rule-providers|"
        "proxy-groups|tun|dns):' \"$cfg\" || true;; esac; exit 0"
    ),
    "test_openclash": (
        "printf '%s\\n' '--PROCESS--'; ps w | grep -Ei '[m]ihomo|[c]lash'; "
        "printf '%s\\n' '--SOCKETS--'; "
        "(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null) | "
        "grep -Ei 'mihomo|clash|:(7890|7891|9090)([^0-9]|$)' || true; exit 0"
    ),
    "get_vps_status": "printf '%s\\n' 'not_configured'",
    "get_security_status": (
        "printf '%s\\n' '--LISTENERS--'; "
        "(ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null); "
        "printf '%s\\n' '--DROPBEAR--'; "
        "uci -q show dropbear | "
        "grep -E '\\.(Interface|Port|PasswordAuth|RootPasswordAuth)=' || true; exit 0"
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
        "1.1.1.1": "command -v ping >/dev/null 2>&1 && ping -c 3 -W 2 1.1.1.1",
        "www.cloudflare.com": (
            "command -v ping >/dev/null 2>&1 && "
            "ping -c 3 -W 2 www.cloudflare.com"
        ),
        "connectivitycheck.gstatic.com": (
            "command -v ping >/dev/null 2>&1 && "
            "ping -c 3 -W 2 connectivitycheck.gstatic.com"
        ),
    },
    "traceroute": {
        "1.1.1.1": (
            "command -v traceroute >/dev/null 2>&1 && traceroute -m 12 -w 2 1.1.1.1"
        ),
        "www.cloudflare.com": (
            "command -v traceroute >/dev/null 2>&1 && "
            "traceroute -m 12 -w 2 www.cloudflare.com"
        ),
        "connectivitycheck.gstatic.com": (
            "command -v traceroute >/dev/null 2>&1 && "
            "traceroute -m 12 -w 2 connectivitycheck.gstatic.com"
        ),
    },
    "curl_test": {
        "1.1.1.1": (
            "if command -v curl >/dev/null 2>&1; then "
            "curl -fsSI --max-time 8 https://1.1.1.1/; "
            "elif command -v wget >/dev/null 2>&1; then "
            "wget -q -T 8 -O /dev/null https://1.1.1.1/; "
            "else uclient-fetch -q -T 8 -O /dev/null https://1.1.1.1/; fi"
        ),
        "www.cloudflare.com": (
            "if command -v curl >/dev/null 2>&1; then "
            "curl -fsSI --max-time 8 https://www.cloudflare.com/; "
            "elif command -v wget >/dev/null 2>&1; then "
            "wget -q -T 8 -O /dev/null https://www.cloudflare.com/; "
            "else uclient-fetch -q -T 8 -O /dev/null https://www.cloudflare.com/; fi"
        ),
        "connectivitycheck.gstatic.com": (
            "if command -v curl >/dev/null 2>&1; then "
            "curl -fsSI --max-time 8 "
            "https://connectivitycheck.gstatic.com/generate_204; "
            "elif command -v wget >/dev/null 2>&1; then "
            "wget -q -T 8 -O /dev/null "
            "https://connectivitycheck.gstatic.com/generate_204; "
            "else uclient-fetch -q -T 8 -O /dev/null "
            "https://connectivitycheck.gstatic.com/generate_204; fi"
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

