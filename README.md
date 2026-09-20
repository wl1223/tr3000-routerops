# TR3000 RouterOps

Safety-first AI network operations agent for a Cudy TR3000 v1 running QWRT.

Phase one is deliberately isolated from real hardware. It runs only against a stateful
Mock Router and proves the diagnostic, permission, approval, backup, verification, and
rollback paths before SSH support is enabled.

## Safety boundary

- Default: `MODE 1` (read-only diagnosis) and `mock` backend.
- No arbitrary shell tool exists.
- Real SSH is disabled in code; SSH settings are reserved for phase two.
- High-risk writes require MODE 4, an immutable backup, exact diff, unexpired approval
  bound to the plan and baseline hashes, deterministic verification, and automatic rollback.
- Firmware flashing, factory reset, package installation, config deletion, and unrestricted
  root commands are not tools.
- Secrets are redacted before logs, evidence, SQLite memory, or LLM context.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
cp .env.example .env

routerops status
routerops baseline
routerops diagnose-f50 "F50启动后TR3000无法自动识别。"
routerops current-state
routerops state-diff
```

Select a mock failure:

```bash
ROUTEROPS_SCENARIO=f50_absent routerops diagnose-f50 "F50无法联网"
ROUTEROPS_SCENARIO=f50_no_driver routerops diagnose-f50 "F50无法联网"
ROUTEROPS_SCENARIO=f50_no_dhcp routerops diagnose-f50 "F50无法联网"
ROUTEROPS_SCENARIO=openclash_failure routerops diagnose-f50 "F50无法联网"
```

Exercise an approved mock change:

```bash
# Preview creates a backup but executes no change.
ROUTEROPS_MODE=4 routerops change-demo

# This approves only the exact plan printed during this invocation.
ROUTEROPS_MODE=4 routerops change-demo --approve

# Verification failure triggers automatic rollback.
ROUTEROPS_MODE=4 ROUTEROPS_SCENARIO=rollback_required \
  routerops change-demo --approve
```

## Architecture

The LLM is an optional bounded planner. A deterministic supervisor owns workflow state;
the safety layer independently validates every tool call; tools pass through a single
facade to the selected backend. The first phase includes an OpenAI-compatible adapter
and an offline rule planner, so all tests and demos run without an API key.

Specialists cover:

1. system health;
2. network diagnostics;
3. USB/ZTE F50;
4. OpenClash/Mihomo;
5. VPS diagnostics;
6. monitoring and state comparison;
7. security checks;
8. backup and recovery.

F50 diagnosis always proceeds from hardware and USB enumeration through driver, Linux
interface, DHCP, route/NAT/firewall, DNS, OpenClash, VPS, and Internet layers. It cannot
diagnose OpenClash when the USB device is absent.

## Knowledge and evidence

Durable knowledge under `knowledge/` records its source, source version, retrieval date,
device/firmware applicability, confidence, limitations, review date, and content hash.
Generic OpenWrt guidance is not treated as directly applicable to QWRT R26.1.1.

Runtime output is excluded from Git:

- `data/devices/tr3000/TR3000_BASELINE.json`
- `data/devices/tr3000/CURRENT_STATE.json`
- immutable tool evidence and backups
- SQLite workflow and incident memory

## Quality checks

```bash
ruff check .
mypy src
pytest
```

## Referenced architecture research

- [Oasis](https://github.com/utakamo/oasis): OpenWrt-native tool manifests and rollback.
- [agentWRT](https://github.com/fabricio3g/agentWRT): bounded ReAct and low-resource patterns.
- [AI agentic network automation](https://github.com/AIKUSAN/ai-agentic-network-automation):
  specialist roles and human-in-the-loop concepts.
- [Packt network operations agents](https://github.com/PacktPublishing/Building-AI-Agents-for-Network-Operations):
  tool/back-end separation and MCP patterns.
- [OpenClash diagnostics](https://github.com/vernesong/OpenClash/blob/dev/.github/skills/openclash-user-guide/14-diagnostics.md):
  plugin/core/runtime diagnostic boundaries.

These projects are design references, not trusted runtime dependencies.