"""Immutable per-Trial evidence identity, sealing, and atomic commit."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from .models import (
    ActorIdentity,
    EvaluationIdentity,
    ExperimentSpec,
    WorldIdentity,
    digest_json,
    write_json,
)

TRIAL_FILES = (
    "trial-manifest.json",
    "trace.jsonl",
    "hidden-evaluation-record.json",
    "result.json",
)


@dataclass(frozen=True)
class TrialManifest:
    schema_version: int
    kind: str
    trial_id: str
    trial_key: str
    experiment_id: str
    experiment_spec_digest: str
    actor_identity_digest: str
    world_identity_digest: str
    evaluation_identity_digest: str
    seed: int
    opponent_policy: str
    max_turns: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrialSeal:
    schema_version: int
    kind: str
    trial_id: str
    trial_key: str
    files: tuple[dict[str, Any], ...]
    evidence_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_trial_manifest(
    *,
    spec: ExperimentSpec,
    actor: ActorIdentity,
    world: WorldIdentity,
    evaluation: EvaluationIdentity,
    seed: int,
    opponent_policy: str,
) -> TrialManifest:
    identity = {
        "schema_version": 1,
        "experiment_spec_digest": digest_json(spec.to_dict()),
        "actor_identity_digest": digest_json(asdict(actor)),
        "world_identity_digest": digest_json(asdict(world)),
        "evaluation_identity_digest": digest_json(asdict(evaluation)),
        "seed": seed,
        "opponent_policy": opponent_policy,
        "max_turns": spec.max_turns,
    }
    trial_key = digest_json(identity)
    short_key = trial_key.removeprefix("sha256:")[:16]
    trial_id = (
        f"{spec.experiment_id}:{actor.actor_id}:{opponent_policy}:"
        f"seed-{seed}:{short_key}"
    )
    return TrialManifest(
        schema_version=1,
        kind="ordivon.security.trial-manifest",
        trial_id=trial_id,
        trial_key=trial_key,
        experiment_id=spec.experiment_id,
        experiment_spec_digest=identity["experiment_spec_digest"],
        actor_identity_digest=identity["actor_identity_digest"],
        world_identity_digest=identity["world_identity_digest"],
        evaluation_identity_digest=identity["evaluation_identity_digest"],
        seed=seed,
        opponent_policy=opponent_policy,
        max_turns=spec.max_turns,
    )


def prepare_trial_staging(
    output_dir: Path,
    manifest: TrialManifest,
) -> tuple[Path, Path]:
    trials_root = output_dir / "trials"
    trials_root.mkdir(parents=True, exist_ok=True)
    final = trials_root / f"trial-{manifest.trial_key.removeprefix('sha256:')}"
    if final.exists():
        raise FileExistsError(
            f"immutable Trial evidence already exists: {final}"
        )
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{_safe_name(manifest.trial_id)}.staging-",
            dir=trials_root,
        )
    )
    write_json(staging / "trial-manifest.json", manifest.to_dict())
    return staging, final


def discard_trial_staging(staging: Path) -> None:
    shutil.rmtree(staging, ignore_errors=True)


def seal_and_commit_trial(
    staging: Path,
    final: Path,
    manifest: TrialManifest,
) -> TrialSeal:
    file_records: list[dict[str, Any]] = []
    for relative in TRIAL_FILES:
        path = staging / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Trial evidence file is missing or unsafe: {relative}")
        raw = path.read_bytes()
        file_records.append(
            {
                "path": relative,
                "byte_length": len(raw),
                "sha256": "sha256:" + sha256(raw).hexdigest(),
            }
        )
    material = {
        "schema_version": 1,
        "kind": "ordivon.security.trial-evidence",
        "trial_id": manifest.trial_id,
        "trial_key": manifest.trial_key,
        "files": file_records,
    }
    seal = TrialSeal(
        schema_version=1,
        kind="ordivon.security.trial-seal",
        trial_id=manifest.trial_id,
        trial_key=manifest.trial_key,
        files=tuple(file_records),
        evidence_digest=digest_json(material),
    )
    write_json(staging / "seal.json", seal.to_dict())
    _fsync_tree(staging)
    if final.exists():
        raise FileExistsError(f"immutable Trial evidence already exists: {final}")
    os.replace(staging, final)
    directory_fd = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return seal


def verify_trial_evidence(path: Path) -> TrialSeal:
    expected = {*TRIAL_FILES, "seal.json"}
    actual = {entry.name for entry in path.iterdir()}
    if actual != expected:
        raise ValueError(
            f"Trial evidence file set differs: expected {sorted(expected)!r}, "
            f"got {sorted(actual)!r}"
        )
    raw_seal = json.loads((path / "seal.json").read_text(encoding="utf-8"))
    seal = TrialSeal(
        schema_version=int(raw_seal["schema_version"]),
        kind=str(raw_seal["kind"]),
        trial_id=str(raw_seal["trial_id"]),
        trial_key=str(raw_seal["trial_key"]),
        files=tuple(dict(item) for item in raw_seal["files"]),
        evidence_digest=str(raw_seal["evidence_digest"]),
    )
    if seal.schema_version != 1 or seal.kind != "ordivon.security.trial-seal":
        raise ValueError("unsupported Trial seal")

    records: list[dict[str, Any]] = []
    for relative in TRIAL_FILES:
        raw = (path / relative).read_bytes()
        records.append(
            {
                "path": relative,
                "byte_length": len(raw),
                "sha256": "sha256:" + sha256(raw).hexdigest(),
            }
        )
    if tuple(records) != seal.files:
        raise ValueError("Trial evidence bytes differ from seal")
    material = {
        "schema_version": 1,
        "kind": "ordivon.security.trial-evidence",
        "trial_id": seal.trial_id,
        "trial_key": seal.trial_key,
        "files": records,
    }
    if digest_json(material) != seal.evidence_digest:
        raise ValueError("Trial evidence digest differs from seal")

    manifest = json.loads(
        (path / "trial-manifest.json").read_text(encoding="utf-8")
    )
    hidden = json.loads(
        (path / "hidden-evaluation-record.json").read_text(encoding="utf-8")
    )
    result = json.loads((path / "result.json").read_text(encoding="utf-8"))
    if manifest["trial_id"] != seal.trial_id or manifest["trial_key"] != seal.trial_key:
        raise ValueError("Trial seal identity differs from manifest")
    if result["trial_id"] != seal.trial_id or result["trial_key"] != seal.trial_key:
        raise ValueError("Trial Result identity differs from manifest")
    if result["manifest_digest"] != digest_json(manifest):
        raise ValueError("Trial Result manifest digest differs")
    if hidden["trial_id"] != seal.trial_id:
        raise ValueError("hidden evaluation identity differs from manifest")
    hidden_digest = digest_json(hidden["payload"])
    if hidden["payload_digest"] != hidden_digest:
        raise ValueError("hidden evaluation payload digest differs")
    if result["hidden_evaluation_digest"] != hidden_digest:
        raise ValueError("Trial Result hidden evaluation digest differs")
    trace_raw = (path / "trace.jsonl").read_bytes()
    for line in trace_raw.splitlines():
        json.loads(line)
    if result["trace_digest"] != "sha256:" + sha256(trace_raw).hexdigest():
        raise ValueError("Trial Result trace digest differs")
    return seal

def _fsync_tree(root: Path) -> None:
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"unexpected Trial staging entry: {path.name}")
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _safe_name(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in value
    )
