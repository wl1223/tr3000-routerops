import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Applicability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device: str
    model: str
    hardware: str
    firmware: str
    kernel: str


class KnowledgeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    source_url: str
    source_type: str
    source_version: str
    retrieved_at: str
    published_at: str | None
    applicability: Applicability
    confidence: float = Field(ge=0, le=1)
    limitations: list[str]
    review_after: str
    content_hash: str
    body: str


class KnowledgeLoader:
    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self) -> list[KnowledgeDocument]:
        documents: list[KnowledgeDocument] = []
        for path in sorted(self.root.glob("**/*.json")):
            if path.name == "schema.json":
                continue
            raw: dict[str, Any] = json.loads(path.read_text())
            document = KnowledgeDocument.model_validate(raw)
            digest = hashlib.sha256(document.body.encode()).hexdigest()
            if digest != document.content_hash:
                raise ValueError(f"knowledge content hash mismatch: {path}")
            documents.append(document)
        return documents

    def applicable(
        self, firmware: str, model: str = "Cudy TR3000 v1"
    ) -> list[KnowledgeDocument]:
        return [
            item
            for item in self.load()
            if item.applicability.model == model
            and item.applicability.firmware in {firmware, "unknown/read-only-reference"}
        ]

