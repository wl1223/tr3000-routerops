from pathlib import Path

from routerops.evidence import EvidenceStore
from routerops.memory import MemoryStore
from routerops.orchestration import Supervisor


def test_baseline_and_current_diff(make_facade, tmp_path: Path):
    backend, facade = make_facade()
    supervisor = Supervisor(
        facade,
        EvidenceStore(tmp_path / "evidence"),
        MemoryStore(tmp_path / "memory.sqlite3"),
        tmp_path / "device",
    )
    _, digest = supervisor.capture_state(baseline=True)
    assert len(digest) == 64
    backend.state["memory"]["available_mb"] = 80
    changes = supervisor.state_diff()
    assert changes["get_memory.available_mb"] == {"before": 112, "after": 80}

