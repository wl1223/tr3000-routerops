import json
import uuid
from typing import Any, cast

from openai import OpenAI

from routerops.models import ToolCall
from routerops.observability.redaction import redact
from routerops.tools.facade import ToolFacade
from routerops.tools.registry import ToolRegistry

SYSTEM_PROMPT = """You are TR3000 RouterOps Planner.
Default to read-only diagnosis. Follow layers L0 hardware, L1 USB/driver, L2 Linux,
L3 network, L4 DHCP/NAT/firewall, L5 DNS, L6 OpenClash, L7 VPS, L8 Internet.
Never invent device state. Never request shell commands. Use only registered tools.
Do not expose secrets. Return concise evidence-based conclusions.
"""


class RulePlanner:
    """Deterministic offline planner used for tests and no-key operation."""

    def classify(self, text: str) -> str:
        lowered = text.lower()
        if "f50" in lowered or "usb" in lowered or "识别" in text:
            return "f50"
        if "openclash" in lowered or "clash" in lowered:
            return "openclash"
        return "network"


class FakeLLM:
    """Offline deterministic tool caller for safety and scenario tests."""

    def __init__(self, facade: ToolFacade) -> None:
        self.facade = facade

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self.facade.invoke(
            ToolCall(
                name=name,
                arguments=arguments or {},
                workflow_id=f"fake-llm-{uuid.uuid4().hex[:12]}",
            )
        )
        return result.model_dump(mode="json")


class OpenAICompatiblePlanner:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        registry: ToolRegistry,
        facade: ToolFacade,
        max_iterations: int = 8,
    ) -> None:
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.registry = registry
        self.facade = facade
        self.max_iterations = max_iterations

    def run(self, user_message: str) -> str:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": str(redact(user_message))},
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.input_schema,
                    "strict": True,
                },
            }
            for spec in self.registry.specs()
        ]
        workflow_id = f"llm-{uuid.uuid4().hex[:12]}"
        for _ in range(self.max_iterations):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=cast(Any, messages),
                tools=cast(Any, tools),
                tool_choice="auto",
                temperature=0,
            )
            message = response.choices[0].message
            if not message.tool_calls:
                return message.content or ""
            messages.append(message.model_dump(exclude_none=True))
            for call in message.tool_calls:
                if call.type != "function":
                    raise RuntimeError("model requested an unsupported custom tool")
                try:
                    arguments = json.loads(call.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}
                result = self.facade.invoke(
                    ToolCall(
                        name=call.function.name,
                        arguments=arguments,
                        workflow_id=workflow_id,
                    )
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(
                            redact(result.model_dump(mode="json")), ensure_ascii=False
                        ),
                    }
                )
        raise RuntimeError("LLM tool budget exhausted")

