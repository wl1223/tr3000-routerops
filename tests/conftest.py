import io
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from routerops.device import DeviceConnectionProfile
from routerops.evidence import EvidenceStore
from routerops.models import RunMode
from routerops.safety import SafetyPolicy
from routerops.tools import ToolFacade, build_registry
from routerops.tools.backends import MockRouterBackend, ParamikoSSHAdapter
from routerops.tools.backends.ssh_commands import ReadonlyCommandRegistry


@pytest.fixture
def make_facade(tmp_path: Path):
    def factory(scenario: str = "healthy", mode: RunMode = RunMode.DIAGNOSE):
        backend = MockRouterBackend(scenario)
        facade = ToolFacade(
            backend,
            build_registry(),
            SafetyPolicy(),
            EvidenceStore(tmp_path / "evidence"),
            mode,
        )
        return backend, facade

    return factory


class _Channel:
    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code

    def recv_exit_status(self) -> int:
        return self.exit_code


class _Stream(io.BytesIO):
    def __init__(self, value: str, exit_code: int = 0) -> None:
        super().__init__(value.encode())
        self.channel = _Channel(exit_code)


class FakeSSHClient:
    def __init__(self, responses: dict[str, tuple[str, str, int]]) -> None:
        self.responses = responses
        self.commands: list[str] = []

    def exec_command(
        self, command: str, timeout: int, get_pty: bool
    ) -> tuple[_Stream, _Stream, _Stream]:
        assert timeout > 0
        assert get_pty is False
        self.commands.append(command)
        stdout, stderr, code = self.responses[command]
        return _Stream(""), _Stream(stdout, code), _Stream(stderr, code)

    def close(self) -> None:
        return None


@pytest.fixture
def ssh_outputs() -> dict[str, tuple[str, str, int]]:
    interfaces = {
        "interface": [
            {
                "interface": "lan",
                "up": True,
                "device": "br-lan",
                "proto": "static",
                "ipv4-address": [{"address": "192.168.10.1", "mask": 24}],
                "ipv6-address": [],
            },
            {
                "interface": "wan",
                "up": True,
                "l3_device": "usb0",
                "proto": "dhcp",
                "ipv4-address": [{"address": "192.168.0.2", "mask": 24}],
                "ipv6-address": [],
            },
        ]
    }
    return {
        "get_system_info": (
            '{"kernel":"6.6.121","hostname":"TR3000","system":"ARMv8 Processor x 2",'
            '"model":"Cudy TR3000 v1","board_name":"cudy,tr3000-v1",'
            '"release":{"description":"QWRT R26.1.1","target":"mediatek/mt798x"}}',
            "",
            0,
        ),
        "get_cpu_temp": ("/sys/class/thermal/thermal_zone0/temp=53000\n", "", 0),
        "get_memory": (
            "MemTotal: 262144 kB\nMemAvailable: 114688 kB\n"
            "SwapTotal: 0 kB\nSwapFree: 0 kB\n--SWAPS--\n",
            "",
            0,
        ),
        "get_storage": (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/root 98304 50000 48304 51% /\n"
            "tmpfs 131072 2048 129024 2% /tmp\n",
            "",
            0,
        ),
        "get_uptime": ("86400.00 120000.00\n", "", 0),
        "get_interfaces": (json_dumps(interfaces), "", 0),
        "get_routes": (
            "--IPV4--\ndefault via 192.168.0.1 dev usb0\n"
            "192.168.0.0/24 dev usb0\n--IPV6--\n",
            "",
            0,
        ),
        "get_dns": (
            "--RESOLV--\nnameserver 127.0.0.1\n--LOOKUP--\n"
            "Name: connectivitycheck.gstatic.com\nAddress: 142.250.1.1\n",
            "",
            0,
        ),
        "get_dhcp": (json_dumps(interfaces) + "\n--LEASES--\n", "", 0),
        "get_firewall": (
            "/usr/sbin/nft\nfirewall.@zone[1].name='wan'\n"
            "firewall.@zone[1].masq='1'\n",
            "",
            0,
        ),
        "get_usb_devices": (
            "Bus 002 Device 002: ID 19d2:1476 ZTE F50 5G CPE\n",
            "",
            0,
        ),
        "get_usb_logs": ("rndis_host usb0: register\n", "", 0),
        "get_usb_network_devices": (
            "usb0|/sys/devices/platform/usb/drivers/rndis_host/2-1\n",
            "",
            0,
        ),
        "get_f50_status": (
            "--USB--\nID 19d2:1476 ZTE F50\n--NET--\n"
            "3: usb0 inet 192.168.0.2/24 scope global usb0\n"
            "--ROUTE--\ndefault via 192.168.0.1 dev usb0\n",
            "",
            0,
        ),
        "get_openclash_status": (
            "--PACKAGES--\nluci-app-openclash - 0.46.079\n"
            "--PROCESSES--\n1234 root /tmp/mihomo -d /tmp/run\n",
            "",
            0,
        ),
        "get_openclash_version": (
            "luci-app-openclash - 0.46.079\nmihomo discovered process\n",
            "",
            0,
        ),
        "get_openclash_process": ("1234 root /tmp/mihomo -d /tmp/run\n", "", 0),
        "get_openclash_logs": ("OpenClash core started in fake-ip mode\n", "", 0),
        "get_openclash_config": (
            "--PROCESS--\n1234 root /tmp/mihomo -f /tmp/runtime.yaml\n--UCI--\n"
            "openclash.config.enable='1'\nopenclash.config.en_mode='fake-ip-tun'\n"
            "openclash.config.ipv6_enable='1'\n"
            "openclash.config.enable_redirect_dns='1'\n--RUNTIME-SAFE--\n"
            "mode: fake-ip-tun\nipv6: true\nrule-providers:\nproxy-groups:\n"
            "geodata-mode: true\ntun:\ndns:\n",
            "",
            0,
        ),
        "test_openclash": (
            "--PROCESS--\n1234 root mihomo\n--SOCKETS--\ntcp 127.0.0.1:9090 mihomo\n",
            "",
            0,
        ),
        "get_vps_status": ("not_configured\n", "", 0),
        "get_security_status": (
            "--LISTENERS--\ntcp 0 0 192.168.10.1:22 LISTEN dropbear\n"
            "--DROPBEAR--\ndropbear.main.PasswordAuth='off'\n",
            "",
            0,
        ),
        "get_services": ("dnsmasq\ndropbear\nfirewall\nnetwork\nopenclash\n", "", 0),
        "get_uci_capability": ("uci=available\nubus=available\n", "", 0),
        "ping": ("64 bytes from 1.1.1.1: time=31.2 ms\n", "", 0),
        "traceroute": ("1 192.168.0.1 1.0 ms\n", "", 0),
        "curl_test": ("HTTP/2 204\n", "", 0),
    }


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value)


@pytest.fixture
def make_ssh_adapter(ssh_outputs):
    def factory(overrides: dict[str, tuple[str, str, int]] | None = None):
        outputs = {**ssh_outputs, **(overrides or {})}
        registry = ReadonlyCommandRegistry()
        responses: dict[str, tuple[str, str, int]] = {}
        for tool, response in outputs.items():
            arguments = {"target": "1.1.1.1"} if tool in {"ping", "traceroute", "curl_test"} else {}
            responses[registry.resolve(tool, arguments).command] = response
        client = FakeSSHClient(responses)
        profile = DeviceConnectionProfile(
            host="192.0.2.1",
            host_key_sha256=SecretStr("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        return ParamikoSSHAdapter(profile, client=client), client

    return factory

