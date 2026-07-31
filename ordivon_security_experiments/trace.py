"""Append-only JSONL traces with deterministic evidence digests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from .models import Decision, Observation, canonical_json


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    trial_id: str
    turn: int
    actor_id: str
    observation: Observation
    decision: Decision
    effect: Mapping[str, Any]
    world_truth_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TraceRecorder:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise FileExistsError(f"Trace evidence already exists: {self.path}")
        self.path.write_text("")
        self._hasher = sha256()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def append(self, event: TraceEvent) -> None:
        line = canonical_json(event.to_dict()) + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        self._hasher.update(line.encode("utf-8"))
        self._count += 1

    def digest(self) -> str:
        return "sha256:" + self._hasher.hexdigest()

    def verify(self) -> bool:
        hasher = sha256()
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                json.loads(line)
                hasher.update(line.encode("utf-8"))
                count += 1
        return count == self._count and "sha256:" + hasher.hexdigest() == self.digest()
