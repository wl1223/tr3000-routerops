import uuid
from dataclasses import dataclass
from typing import Any

from routerops.models import DiagnosticReport, FaultLayer, ToolCall, ToolResult, ToolStatus
from routerops.tools.facade import ToolFacade


@dataclass
class AgentContext:
    facade: ToolFacade
    workflow_id: str

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        return self.facade.invoke(
            ToolCall(name=name, arguments=arguments or {}, workflow_id=self.workflow_id)
        )


class SpecialistAgent:
    tools: tuple[str, ...] = ()

    def collect(self, facade: ToolFacade) -> dict[str, ToolResult]:
        context = AgentContext(facade, f"collect-{uuid.uuid4().hex[:12]}")
        return {name: context.call(name) for name in self.tools}


class SystemAgent(SpecialistAgent):
    tools = ("get_system_info", "get_cpu_temp", "get_memory", "get_storage", "get_uptime")


class NetworkDiagnosticAgent(SpecialistAgent):
    tools = ("get_interfaces", "get_routes", "get_dns", "get_dhcp", "get_firewall")


class OpenClashAgent(SpecialistAgent):
    tools = (
        "get_memory",
        "get_storage",
        "get_openclash_status",
        "get_openclash_version",
        "get_openclash_process",
        "get_openclash_config",
        "get_openclash_logs",
        "test_openclash",
    )

    def diagnose(self, facade: ToolFacade, problem: str) -> DiagnosticReport:
        context = AgentContext(facade, f"openclash-{uuid.uuid4().hex[:12]}")
        results = {name: context.call(name) for name in self.tools}
        evidence = [
            f"{name}: {result.evidence_ref or result.error}"
            for name, result in results.items()
        ]
        memory = results["get_memory"].data
        status = results["get_openclash_status"].data
        process = results["get_openclash_process"].data
        test = results["test_openclash"].data
        logs = results["get_openclash_logs"].data.get("lines", [])
        oom = memory.get("oom_events", [])
        if (
            results["get_openclash_status"].status != ToolStatus.OK
            or not status.get("_meta", {}).get("available", True)
        ):
            cause = "OpenClash 只读发现命令在当前固件上不可用或输出无法解析"
            recommendation = "保存脱敏 fixture，确认 QWRT 实际包管理器、进程和服务输出"
            confidence = 0.98
        elif oom or any("out of memory" in str(line).lower() for line in logs):
            cause = "256MB 内存压力触发 OOM，OpenClash/Mihomo 进程被终止"
            recommendation = "减少规则/Provider/并发核心，先评估内存与 swap；本阶段不执行修改"
            confidence = 0.96
        elif not status.get("installed"):
            cause = "未发现 OpenClash 安装证据"
            recommendation = "核对固件包清单和实际服务名称"
            confidence = 0.9
        elif not process.get("running"):
            cause = "OpenClash 已安装，但未发现 Mihomo/Clash 核心进程"
            recommendation = "检查插件日志、核心路径发现结果和启动错误"
            confidence = 0.92
        elif not test.get("success"):
            cause = "核心进程存在，但只读运行链路检查未通过"
            recommendation = "检查实际模式、DNS、TUN/Redir、监听端口和规则日志"
            confidence = 0.84
        else:
            cause = "当前只读采样显示 OpenClash 核心与运行链路正常"
            recommendation = "保存当前状态并与故障时快照比较"
            confidence = 0.82
        return DiagnosticReport(
            problem=problem,
            current_status=f"installed={status.get('installed')}, running={process.get('running')}",
            evidence=evidence,
            fault_layer=FaultLayer.L6_OPENCLASH,
            cause=cause,
            confidence=confidence,
            risk="真实设备仅执行 Level 0 只读发现；Phase 2 禁止任何修复",
            recommendations=[recommendation],
            required_tools=list(self.tools),
            expected_result="获得版本、核心、进程、过滤后的配置、日志和链路状态",
        )


class VPSDiagnosticAgent(SpecialistAgent):
    tools = ("get_vps_status",)


class MonitoringAgent(SpecialistAgent):
    tools = ("get_system_info", "get_memory", "get_interfaces", "get_routes")


class SecurityAgent(SpecialistAgent):
    tools = ("get_security_status", "get_firewall")


class RecoveryAgent(SpecialistAgent):
    tools = ("list_backups", "uci_diff")


class F50Agent:
    def diagnose(self, facade: ToolFacade, problem: str) -> DiagnosticReport:
        context = AgentContext(facade, f"diag-{uuid.uuid4().hex[:12]}")
        evidence: list[str] = []

        def observe(name: str) -> dict[str, Any]:
            result = context.call(name)
            if result.status != ToolStatus.OK:
                evidence.append(f"{name}: 工具失败 ({result.error})")
                return {
                    "_meta": {
                        "available": False,
                        "reason": result.error or "tool_error",
                        "source": "tool_facade",
                        "command": name,
                    }
                }
            evidence.append(f"{name}: {result.evidence_ref}")
            return result.data

        usb = observe("get_usb_devices")
        if not usb.get("_meta", {}).get("available", True):
            return self._report(
                problem,
                "无法获得可靠的 USB 枚举 Observation",
                evidence,
                FaultLayer.L2_LINUX,
                "当前 QWRT 环境缺少兼容的只读 USB 枚举能力或输出无法解析",
                0.98,
                ["记录脱敏 fixture 并适配实际 lsusb/sysfs 输出"],
                ["get_usb_devices"],
                "获得 available=true 的 USB 枚举 Observation",
            )
        devices = usb.get("devices", [])
        if not any(device.get("is_f50") for device in devices):
            logs = observe("get_usb_logs")
            return self._report(
                problem,
                "系统没有枚举到中兴 F50 USB 设备",
                evidence,
                FaultLayer.L1_USB_DRIVER,
                "USB 设备不存在、供电/线缆异常，或枚举失败",
                0.95,
                ["检查 F50 供电、USB 线缆与端口", f"检查内核 USB 日志：{bool(logs)}"],
                ["get_usb_devices", "get_usb_logs"],
                "F50 出现在 USB 枚举结果中",
            )

        usb_network = observe("get_usb_network_devices")
        network_devices = usb_network.get("interfaces", [])
        if not network_devices:
            logs = observe("get_usb_logs")
            return self._report(
                problem,
                "F50 已被 USB 枚举，但没有对应网络接口",
                evidence,
                FaultLayer.L1_USB_DRIVER,
                "RNDIS/CDC/USB 网络驱动未绑定或初始化失败",
                0.93,
                ["核对设备 USB class 与已加载的 RNDIS/CDC 驱动", f"保留日志证据：{bool(logs)}"],
                ["get_usb_devices", "get_usb_network_devices", "get_usb_logs"],
                "出现与 F50 对应且状态为 UP 的网络接口",
            )

        interface_observation = observe("get_interfaces")
        if not interface_observation.get("_meta", {}).get("available", True):
            return self._report(
                problem,
                "USB 网络设备已发现，但接口 Observation 不可用",
                evidence,
                FaultLayer.L2_LINUX,
                "ubus network.interface 输出在当前固件上不可用或无法解析",
                0.98,
                ["记录脱敏 fixture 并适配实际 ubus 接口输出"],
                ["get_interfaces"],
                "获得 available=true 的接口 Observation",
            )
        interfaces = interface_observation.get("interfaces", [])
        names = {item.get("name") for item in network_devices}
        f50_interfaces = [item for item in interfaces if item.get("name") in names]
        if not f50_interfaces:
            return self._report(
                problem,
                "USB 网络设备已报告，但 Linux 网络接口缺失",
                evidence,
                FaultLayer.L2_LINUX,
                "USB 网络设备与内核 netdev 注册状态不一致",
                0.86,
                ["检查 netdev 注册、驱动重置与内核错误"],
                ["get_usb_network_devices", "get_interfaces", "get_usb_logs"],
                "Linux ip link 中出现 F50 对应接口",
            )
        dhcp = observe("get_dhcp")
        if not any(item.get("ipv4") for item in f50_interfaces):
            return self._report(
                problem,
                "F50 网络接口存在，但没有 IPv4 地址",
                evidence,
                FaultLayer.L4_DHCP_NAT_FIREWALL,
                "F50 上行接口未成功获取 DHCP 租约",
                0.92,
                [f"检查 DHCP 客户端状态与租约：{dhcp.get('wan_lease', 'missing')}"],
                ["get_interfaces", "get_dhcp"],
                "F50 接口获得地址、网关和有效租约",
            )

        routes = observe("get_routes").get("routes", [])
        if not any(route.get("default") and route.get("interface") in names for route in routes):
            return self._report(
                problem,
                "F50 接口有地址，但没有对应默认路由",
                evidence,
                FaultLayer.L3_NETWORK,
                "上行默认路由未安装或路由优先级异常",
                0.9,
                ["检查 DHCP 下发网关、路由表和策略路由"],
                ["get_interfaces", "get_routes", "get_dhcp"],
                "路由表出现经 F50 接口的可用默认路由",
            )

        internet = context.call("ping", {"target": "1.1.1.1"})
        evidence.append(f"ping: {internet.evidence_ref or internet.error}")
        if internet.status != ToolStatus.OK or not internet.data.get("success"):
            firewall = observe("get_firewall")
            return self._report(
                problem,
                "F50 地址和路由正常，但 IPv4 Internet 探针失败",
                evidence,
                FaultLayer.L4_DHCP_NAT_FIREWALL,
                "上游链路、NAT 或防火墙接管异常",
                0.82,
                [f"检查 WAN zone、转发和 masquerade：{firewall.get('masquerade')}"],
                ["ping", "get_firewall", "get_routes"],
                "IP 探针成功且防火墙计数器正常增长",
            )

        dns = observe("get_dns")
        if not dns.get("resolution_ok"):
            return self._report(
                problem,
                "IP 连通正常，但 DNS 解析失败",
                evidence,
                FaultLayer.L5_DNS,
                "DNS 上游、劫持链或本地解析服务异常",
                0.94,
                ["核对实际监听、上游 DNS 和 OpenClash DNS 接管"],
                ["get_dns", "ping"],
                "受控域名 A/AAAA 查询按当前策略返回",
            )

        clash = observe("test_openclash")
        if not clash.get("success"):
            return self._report(
                problem,
                "底层网络和 DNS 正常，OpenClash 运行链路测试失败",
                evidence,
                FaultLayer.L6_OPENCLASH,
                "OpenClash 核心、TUN/Redir、规则或节点链路异常",
                0.88,
                ["读取实际 OpenClash 版本、最终配置、核心日志和控制 API 状态"],
                [
                    "get_openclash_status",
                    "get_openclash_version",
                    "get_openclash_config",
                    "get_openclash_logs",
                ],
                "核心、接管、规则命中和代理探针均成功",
            )
        vps = observe("get_vps_status")
        if vps.get("configured", True) and vps.get("service") is False:
            return self._report(
                problem,
                "F50、Internet、DNS 和 OpenClash 正常，但 VPS 服务探针失败",
                evidence,
                FaultLayer.L7_VPS,
                "VPS TCP/TLS/服务不可用",
                0.88,
                ["检查 VPS DNS、端口、TLS 证书和服务监听；本阶段不执行修改"],
                ["get_vps_status"],
                "VPS DNS、TCP、TLS 和服务探针恢复",
            )
        return self._report(
            problem,
            "F50、USB、接口、DHCP、路由、Internet、DNS 和 OpenClash 均正常",
            evidence,
            FaultLayer.L8_INTERNET,
            "当前采样未复现故障",
            0.8,
            ["建立按需健康检查并在故障发生时保存 snapshot"],
            ["get_f50_status", "get_openclash_status"],
            "后续状态与健康基线持续一致",
        )

    @staticmethod
    def _report(
        problem: str,
        status: str,
        evidence: list[str],
        layer: FaultLayer,
        cause: str,
        confidence: float,
        recommendations: list[str],
        tools: list[str],
        expected: str,
    ) -> DiagnosticReport:
        return DiagnosticReport(
            problem=problem,
            current_status=status,
            evidence=evidence,
            fault_layer=layer,
            cause=cause,
            confidence=confidence,
            risk="当前仅执行只读采集；未修改路由器配置",
            recommendations=recommendations,
            required_tools=tools,
            expected_result=expected,
        )

