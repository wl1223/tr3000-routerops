from routerops.llm import FakeLLM
from routerops.models import RunMode


def test_fake_llm_cannot_invoke_unregistered_tool(make_facade):
    _, facade = make_facade()
    result = FakeLLM(facade).call_tool("shell", {"command": "id"})
    assert result["status"] == "error"


def test_fake_llm_cannot_raise_mode_or_write(make_facade):
    _, facade = make_facade(mode=RunMode.DIAGNOSE)
    llm = FakeLLM(facade)
    escalation = llm.call_tool("get_system_info", {"mode": 4})
    write = llm.call_tool(
        "uci_set",
        {
            "package": "network",
            "section": "wan",
            "option": "proto",
            "value": "static",
        },
    )
    assert escalation["status"] in {"error", "denied"}
    assert write["status"] == "denied"
    assert facade.mode == RunMode.DIAGNOSE

