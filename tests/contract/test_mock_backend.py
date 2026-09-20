from routerops.models import RiskLevel
from routerops.tools import build_registry
from routerops.tools.backends import MockRouterBackend


def test_mock_implements_all_read_tools():
    backend = MockRouterBackend()
    exceptions = {
        "ping": {"target": "1.1.1.1"},
        "traceroute": {"target": "1.1.1.1"},
        "curl_test": {"target": "www.cloudflare.com"},
        "uci_get": {"package": "network"},
    }
    for spec in build_registry().specs():
        if spec.risk == RiskLevel.READ_ONLY and spec.name != "backup_config":
            result = backend.execute_readonly(spec.name, exceptions.get(spec.name, {}))
            assert isinstance(result, dict), spec.name


def test_tool_schemas_are_closed():
    for spec in build_registry().specs():
        assert spec.input_schema["type"] == "object"
        assert spec.input_schema["additionalProperties"] is False

