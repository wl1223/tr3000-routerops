import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from routerops.observability.redaction import redact


class MemoryStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0
            )"""
        )
        self.connection.commit()

    def event(self, workflow_id: str, kind: str, payload: Any) -> None:
        safe = json.dumps(redact(payload), ensure_ascii=False, default=str)
        self.connection.execute(
            "INSERT INTO events(workflow_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
            (workflow_id, kind, safe, datetime.now(UTC).isoformat()),
        )
        self.connection.commit()

    def save_approval(self, approval_id: str, payload: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO approvals(approval_id, payload, approved) VALUES (?, ?, ?)",
            (
                approval_id,
                json.dumps(redact(payload), default=str),
                int(payload.get("approved", False)),
            ),
        )
        self.connection.commit()

