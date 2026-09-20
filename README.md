# TR3000 RouterOps

Safety-first AI network operations agent for a Cudy TR3000 v1 running QWRT.

Phase two supports both the stateful Mock Router and a strictly read-only Paramiko SSH
adapter. The real adapter has no generic command method and no mutation method. It maps
registered tools to fixed command templates, normalizes and redacts raw observations,
then passes typed data to diagnostics.

## Safety boundary

- Default: `MODE 1` (read-only diagnosis) and `mock` backend.
- Real SSH is accepted only in MODE 1 with a pinned SHA-256 host key.
- Real-device writes always return `REAL_DEVICE_WRITE_DISABLED_IN_PHASE2`.
- No arbitrary shell tool exists.
- High-risk writes require MODE 4, an immutable backup, exact diff, unexpired approval
  bound to one-time exact calls and baseline hashes. This path remains Mock-only.
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
routerops device baseline
routerops diagnose f50 "F50启动后TR3000无法自动识别。"
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

## Read-only TR3000 connection

Do not copy a host key fingerprint from an untrusted network. Verify it through the
router UI, console, or another trusted channel first:

```bash
ssh-keyscan -p 22 192.168.10.1 2>/dev/null | ssh-keygen -lf - -E sha256
cp .env.example .env
chmod 600 .env
```

Configure `.env` without committing it:

```dotenv
ROUTEROPS_MODE=1
ROUTEROPS_BACKEND=ssh
ROUTEROPS_SSH_HOST=192.168.10.1
ROUTEROPS_SSH_PORT=22
ROUTEROPS_SSH_USERNAME=root
ROUTEROPS_SSH_AUTH_METHOD=agent
ROUTEROPS_SSH_HOST_KEY_SHA256=SHA256:verified-fingerprint
```

Use an SSH agent or a dedicated read-only key where QWRT permits it. Password and private
key-path settings use `SecretStr` and are never persisted in baseline, evidence, audit,
exceptions, or LLM context.

```bash
routerops device probe
routerops device baseline
routerops device status
routerops state-diff
routerops diagnose f50 "F50启动后TR3000无法自动识别。"
routerops diagnose openclash
```

The first baseline writes:

- `var/devices/tr3000/TR3000_BASELINE.json`
- `var/devices/tr3000/CURRENT_STATE.json`
- `var/devices/tr3000/current.json`
- `var/devices/tr3000/capabilities.json`

All commands above are read-only. Phase 2 does not implement real restart, UCI mutation,
restore, firewall change, OpenClash change, reboot, sysupgrade, or automatic healing.

The fixed commands target common OpenWrt 24.x/BusyBox interfaces. QWRT R26.1.1 output
must still be verified on the physical router. Missing optional commands such as `lsusb`,
`curl`, or `ss` use read-only sysfs/`wget`/`uclient-fetch`/`netstat` fallbacks. Failed or
unparseable commands produce an unavailable typed observation instead of terminating the
diagnostic workflow.

### Redacted fixture capture and replay

To capture normalized observations from a real read-only session:

```dotenv
ROUTEROPS_BACKEND=ssh
ROUTEROPS_MODE=1
ROUTEROPS_FIXTURE_CAPTURE_DIR=var/fixtures/tr3000-readonly
```

After manually reviewing the files, replay the exact tool calls without SSH:

```dotenv
ROUTEROPS_BACKEND=replay
ROUTEROPS_MODE=1
ROUTEROPS_FIXTURE_REPLAY_DIR=var/fixtures/tr3000-readonly
```

Raw SSH output is never stored by this mechanism. No fabricated QWRT capture is included
in the repository; see `fixtures/README.md`.

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

Runtime output under `var/` is excluded from Git:

- `var/devices/tr3000/TR3000_BASELINE.json`
- `var/devices/tr3000/CURRENT_STATE.json`
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