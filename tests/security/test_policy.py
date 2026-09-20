from routerops.models import RunMode, ToolCall, ToolStatus


def test_mode_one_denies_service_restart(make_facade):
    _, facade = make_facade()
    result = facade.invoke(ToolCall(name="restart_dns", workflow_id="wf"))
    assert result.status == ToolStatus.DENIED


def test_level_one_requires_notification(make_facade):
    _, facade = make_facade(mode=RunMode.SEMI_AUTO)
    denied = facade.invoke(ToolCall(name="restart_dns", workflow_id="wf"))
    allowed = facade.invoke(
        ToolCall(name="restart_dns", workflow_id="wf", user_notified=True)
    )
    assert denied.status == ToolStatus.DENIED
    assert allowed.status == ToolStatus.OK


def test_arbitrary_probe_target_is_denied(make_facade):
    _, facade = make_facade()
    result = facade.invoke(
        ToolCall(name="curl_test", arguments={"target": "169.254.169.254"}, workflow_id="wf")
    )
    assert result.status == ToolStatus.DENIED


def test_uci_set_needs_maintenance_and_approval(make_facade):
    _, facade = make_facade(mode=RunMode.MAINTENANCE)
    result = facade.invoke(
        ToolCall(
            name="uci_set",
            arguments={
                "package": "network",
                "section": "wan",
                "option": "proto",
                "value": "static",
            },
            workflow_id="wf",
        )
    )
    assert result.status == ToolStatus.DENIED
    assert "approval" in (result.error or "")


def test_unknown_tool_is_closed(make_facade):
    _, facade = make_facade()
    result = facade.invoke(ToolCall(name="shell", arguments={"command": "id"}, workflow_id="wf"))
    assert result.status == ToolStatus.ERROR

