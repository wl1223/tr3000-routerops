# Real observation fixtures

No QWRT output is committed here until it has been captured from a real device and
reviewed. RouterOps records only normalized, redacted observations; raw SSH stdout and
stderr are never written by the fixture mechanism.

Capture to the Git-ignored `var/` directory:

```dotenv
ROUTEROPS_MODE=1
ROUTEROPS_BACKEND=ssh
ROUTEROPS_FIXTURE_CAPTURE_DIR=var/fixtures/tr3000-readonly
```

Run the desired read-only commands, then replay the exact calls without connecting:

```dotenv
ROUTEROPS_MODE=1
ROUTEROPS_BACKEND=replay
ROUTEROPS_FIXTURE_REPLAY_DIR=var/fixtures/tr3000-readonly
```

Every fixture includes `source`, `redacted=true`, hashes, capture time, exact tool
arguments, and normalized observation data. Test-generated fixtures are explicitly
labelled `test-generated-not-qwrt-evidence` and must not be treated as device evidence.

