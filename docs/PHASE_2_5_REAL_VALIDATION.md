# Phase 2.5 — Real TR3000 / QWRT read-only validation

Current status:

```text
REAL_DEVICE_CONNECTED=false
REAL_DEVICE_VALIDATED=false
PHASE_3=NOT_STARTED
```

This workflow validates observations only. It does not authorize UCI writes, service
restart/reload, reboot, restore, sysupgrade, configuration replacement, or automatic
repair.

## 1. Environment preparation

Use Python 3.12 on Windows/WSL/Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e ".[dev]"
cp .env.example .env
chmod 600 .env
```

Prefer SSH-agent authentication with a dedicated key. Do not send credentials, private
keys, tokens, cookies, or OpenClash subscription URLs to RouterOps logs or support
channels.

## 2. Obtain and verify the host key

Obtain the router fingerprint on a trusted local network:

```bash
ssh-keyscan -p 22 ROUTER_IP 2>/dev/null | ssh-keygen -lf - -E sha256
```

Verify that fingerprint through a second trusted path such as the router console or UI.
RouterOps never auto-accepts an unknown key. A mismatch stops before discovery with:

```text
HOST_KEY_MISMATCH
```

## 3. Configure `.env`

```dotenv
ROUTEROPS_MODE=1
ROUTEROPS_BACKEND=ssh
ROUTEROPS_SSH_HOST=ROUTER_IP
ROUTEROPS_SSH_PORT=22
ROUTEROPS_SSH_USERNAME=root
ROUTEROPS_SSH_AUTH_METHOD=agent
ROUTEROPS_SSH_HOST_KEY_SHA256=SHA256:VERIFIED_FINGERPRINT
ROUTEROPS_DATA_DIR=var
ROUTEROPS_FIXTURE_CAPTURE_DIR=var/fixtures/tr3000-readonly
```

`password`, `private_key`, and host-key fields use `SecretStr`. They are not written to
baseline, SQLite, evidence, fixtures, audit output, exceptions, or LLM context.

## 4. Device probe

```bash
routerops device probe
```

Probe performs host-key verification followed by fixed read-only observations for system,
kernel, architecture, CPU, memory, storage, interfaces, routes, DNS, DHCP, firewall, USB,
USB netdev, services, UCI/ubus, OpenClash, and its core process.

Capability values are tri-state:

- `available=true, confidence=observed`
- `available=false, confidence=observed` only when unsupported is directly observed
- `available=null, confidence=unknown` when evidence is insufficient

No-match is not treated as “not installed.”

## 5. Baseline

```bash
routerops device baseline
```

Generated under `var/devices/tr3000/`:

- `TR3000_BASELINE.json`
- `capabilities.json`
- `CURRENT_STATE.json`
- `current.json`

The baseline source records `type=real_device`, actual observed model/firmware or
`unknown`, `mode=readonly`, and `real_device_validated=false`. It never substitutes the
expected QWRT version for an unknown real value.

## 6. Current status

```bash
routerops device status
```

Individual unsupported commands produce an observation such as:

```json
{
  "_meta": {
    "available": false,
    "reason": "command_unavailable_or_unsupported",
    "source": "real_ssh",
    "command": "get_usb_devices",
    "fallback": "lsusb -> debugfs -> sysfs"
  }
}
```

Raw stdout/stderr exists only for the in-memory normalization call.

## 7. State diff

```bash
routerops state-diff
```

Diff compares normalized, redacted baseline and current observations. A missing optional
command is represented as unavailable metadata, not as an automatic device fault.

## 8. F50 diagnosis

```bash
routerops diagnose f50
```

Order is fixed:

```text
USB device → enumeration/driver → USB netdev → Linux interface → IP → DHCP
→ default route → Internet probe → DNS → OpenClash → VPS → Internet
```

The report always contains problem, current status, evidence, fault layer, cause, risk,
recommendations, required read-only tools, and expected result. It never proposes an
automatic restart or write.

## 9. OpenClash diagnosis

```bash
routerops diagnose openclash
```

Discovery uses package listings, service enumeration, process arguments, filtered UCI,
safe top-level runtime keys, and listener state. It does not hardcode `/etc/openclash`, a
service name, core name, or configuration path. Unknown values remain `unknown`/`null`.

## 10. Fixture capture

With `ROUTEROPS_FIXTURE_CAPTURE_DIR` configured, every successful tool call stores only:

- normalized and redacted observation
- structured real-device source metadata
- timestamp and schema version
- exact tool identity and arguments
- device profile identifier
- integrity hashes

No raw SSH output is persisted. Review `var/fixtures/tr3000-readonly/` locally before
sharing any data.

## 11. Replay validation

Change only environment configuration:

```dotenv
ROUTEROPS_MODE=1
ROUTEROPS_BACKEND=replay
ROUTEROPS_FIXTURE_REPLAY_DIR=var/fixtures/tr3000-readonly
```

Then run:

```bash
routerops device probe
routerops device baseline
routerops device status
routerops state-diff
routerops diagnose f50
routerops diagnose openclash
```

Replay validates schema, source labels, observation hashes, and exact call hashes. It has
no SSH connection method, generic executor, or mutation method.

## 12. Safety checks

```bash
routerops status
ruff check .
mypy src
pytest -q
```

For SSH/replay, required invariants are:

```text
MODE=1
mutation_tools=0
write_capability=false
generic_shell=false
auto_repair=false
restart=false
reboot=false
uci_write=false
sysupgrade=false
restore=false
```

## 13. Failure handling

- `HOST_KEY_MISMATCH`: stop; verify the fingerprint through a trusted path.
- `SSH_CONNECTION_FAILED`: check reachability, port, username, and local SSH agent.
- `_meta.available=false`: retain the observation and capture fixture evidence; do not
  install packages or modify the router during Phase 2.5.
- parser failure: record the normalized unavailable observation and adapt parsers offline
  using the reviewed replay fixture.
- fixture integrity/source failure: reject replay; do not bypass validation.

## 14. Acceptance criteria

- Real SSH connects only after host-key pinning and remains MODE 1.
- All six CLI entries complete or degrade per observation without device mutation.
- Real model, firmware, kernel, architecture, and capabilities are observed, not assumed.
- F50 and OpenClash reports preserve diagnostic layer order.
- Fixture is redacted, normalized, source-labelled, integrity-checked, and exactly replayed.
- Ruff, mypy, pytest, security regressions, and CLI replay tests pass.
- `REAL_DEVICE_CONNECTED` and `REAL_DEVICE_VALIDATED` remain false until an authorized
  physical run actually occurs.
- Phase 3 remains not started.

