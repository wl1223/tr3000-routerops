import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from routerops.evidence.store import content_hash
from routerops.observability.redaction import redact


class FixtureSource(StrEnum):
    REAL_DEVICE_REDACTED = "real_device"
    TEST_GENERATED = "test_generated"


class FixtureSourceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: FixtureSource
    is_device_evidence: bool
    mode: Literal["readonly"] = "readonly"
    device_profile_identifier: str

    @model_validator(mode="after")
    def validate_evidence_label(self) -> "FixtureSourceMetadata":
        expected = self.type == FixtureSource.REAL_DEVICE_REDACTED
        if self.is_device_evidence != expected:
            raise ValueError("fixture source evidence label is inconsistent")
        return self


class FixtureRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    source: FixtureSourceMetadata
    device_id: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    redacted: Literal[True] = True
    tool: str
    arguments: dict[str, Any]
    call_hash: str
    observation: dict[str, Any]
    observation_hash: str


class FixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    source: FixtureSourceMetadata
    device_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    redacted: Literal[True] = True
    records: list[str] = Field(default_factory=list)


class ObservationRecorder(Protocol):
    def record(
        self, tool: str, arguments: dict[str, Any], observation: dict[str, Any]
    ) -> None: ...


def fixture_call_hash(tool: str, arguments: dict[str, Any]) -> str:
    return content_hash({"tool": tool, "arguments": redact(arguments)})


class ObservationFixtureRecorder:
    """Stores only normalized and redacted observations, never raw SSH output."""

    def __init__(
        self,
        root: Path,
        device_id: str,
        source: FixtureSource = FixtureSource.REAL_DEVICE_REDACTED,
        device_profile_identifier: str | None = None,
    ) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.root / "manifest.json"
        if self.manifest_path.exists():
            self.manifest = FixtureManifest.model_validate_json(
                self.manifest_path.read_text()
            )
            if self.manifest.device_id != device_id:
                raise ValueError("fixture directory belongs to another device")
        else:
            self.manifest = FixtureManifest(
                source=FixtureSourceMetadata(
                    type=source,
                    is_device_evidence=source == FixtureSource.REAL_DEVICE_REDACTED,
                    device_profile_identifier=device_profile_identifier or device_id,
                ),
                device_id=device_id,
            )
            self._write_manifest()

    def record(
        self, tool: str, arguments: dict[str, Any], observation: dict[str, Any]
    ) -> None:
        self._reject_raw_output(observation)
        safe_arguments = dict(redact(arguments))
        safe_observation = dict(redact(observation))
        call_hash = fixture_call_hash(tool, safe_arguments)
        filename = f"{tool}-{call_hash[:16]}.json"
        record = FixtureRecord(
            source=self.manifest.source,
            device_id=self.manifest.device_id,
            tool=tool,
            arguments=safe_arguments,
            call_hash=call_hash,
            observation=safe_observation,
            observation_hash=content_hash(safe_observation),
        )
        self._atomic_write(
            self.root / filename,
            record.model_dump(mode="json"),
        )
        if filename not in self.manifest.records:
            self.manifest.records.append(filename)
            self.manifest.records.sort()
            self._write_manifest()

    @classmethod
    def _reject_raw_output(cls, value: Any) -> None:
        if isinstance(value, dict):
            forbidden = {"raw_stdout", "raw_stderr", "stdout", "stderr"}
            if forbidden & {str(key).lower() for key in value}:
                raise ValueError("raw SSH output cannot be persisted as a fixture")
            for item in value.values():
                cls._reject_raw_output(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                cls._reject_raw_output(item)

    def _write_manifest(self) -> None:
        self._atomic_write(
            self.manifest_path,
            self.manifest.model_dump(mode="json"),
        )

    @staticmethod
    def _atomic_write(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2))
        temporary.replace(path)


class ReplayRouterAdapter:
    """Read-only replay of previously normalized, redacted real observations."""

    readonly = True

    def __init__(self, root: Path) -> None:
        manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("fixture manifest does not exist")
        self.root = root
        self.manifest = FixtureManifest.model_validate_json(manifest_path.read_text())
        self.device_id = self.manifest.device_id
        self._records: dict[str, FixtureRecord] = {}
        for filename in self.manifest.records:
            path = root / filename
            record = FixtureRecord.model_validate_json(path.read_text())
            if record.device_id != self.device_id or not record.redacted:
                raise ValueError("fixture record is incompatible or not redacted")
            if record.source != self.manifest.source:
                raise ValueError("fixture source metadata does not match manifest")
            if content_hash(record.observation) != record.observation_hash:
                raise ValueError("fixture observation integrity check failed")
            self._records[record.call_hash] = record

    def execute_readonly(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        call_hash = fixture_call_hash(tool, arguments)
        record = self._records.get(call_hash)
        if record is None or record.tool != tool:
            raise RuntimeError("fixture does not contain this exact read-only call")
        return dict(redact(record.observation))

    @property
    def allowed_tools(self) -> frozenset[str]:
        return frozenset(record.tool for record in self._records.values())

