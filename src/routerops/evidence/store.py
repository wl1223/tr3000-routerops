import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from routerops.observability.redaction import redact


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, category: str, payload: Any) -> str:
        safe_payload = redact(payload)
        digest = content_hash(safe_payload)
        path = self.root / f"{category}-{digest[:16]}.json"
        envelope = {
            "id": digest,
            "observed_at": datetime.now(UTC).isoformat(),
            "payload": safe_payload,
        }
        path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2, default=str))
        return str(path)

    def snapshot(self, path: Path, payload: Any) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        safe_payload = redact(payload)
        path.write_text(json.dumps(safe_payload, ensure_ascii=False, indent=2, default=str))
        return content_hash(safe_payload)

    def diff(self, before: Any, after: Any) -> dict[str, dict[str, Any]]:
        changes: dict[str, dict[str, Any]] = {}

        def walk(left: Any, right: Any, prefix: str = "") -> None:
            if isinstance(left, dict) and isinstance(right, dict):
                for key in sorted(left.keys() | right.keys()):
                    walk(left.get(key), right.get(key), f"{prefix}.{key}".strip("."))
            elif left != right:
                changes[prefix] = {"before": redact(left), "after": redact(right)}

        walk(before, after)
        return changes

