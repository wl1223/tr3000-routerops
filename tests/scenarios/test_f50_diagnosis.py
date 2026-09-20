import pytest

from routerops.agents import F50Agent
from routerops.models import FaultLayer


@pytest.mark.parametrize(
    ("scenario", "layer"),
    [
        ("f50_absent", FaultLayer.L1_USB_DRIVER),
        ("f50_no_driver", FaultLayer.L1_USB_DRIVER),
        ("f50_no_dhcp", FaultLayer.L4_DHCP_NAT_FIREWALL),
        ("f50_no_route", FaultLayer.L4_DHCP_NAT_FIREWALL),
        ("internet_failure", FaultLayer.L4_DHCP_NAT_FIREWALL),
        ("dns_failure", FaultLayer.L5_DNS),
        ("openclash_failure", FaultLayer.L6_OPENCLASH),
        ("healthy", FaultLayer.L8_INTERNET),
    ],
)
def test_f50_diagnostic_layer(make_facade, scenario, layer):
    _, facade = make_facade(scenario)
    report = F50Agent().diagnose(facade, "F50启动后TR3000无法自动识别")
    assert report.fault_layer == layer
    assert report.evidence
    assert "只读" in report.risk


def test_absent_f50_never_queries_openclash(make_facade):
    _, facade = make_facade("f50_absent")
    report = F50Agent().diagnose(facade, "F50无法联网")
    assert all("openclash" not in item for item in report.evidence)
    assert "OpenClash" not in report.cause

