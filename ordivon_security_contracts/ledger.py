"""Append-only Campaign authority ledger with deterministic replay.

The ledger owns only Security-level lifecycle truth. Component-native journals
remain authoritative for Link, Edge, Runtime, Host, and Game details; Security
stores immutable bindings and evidence roots rather than copying their state.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from .bindings import ComponentBinding, ResidualReport
from .campaign import (
    ContractError,
    canonical_bytes,
    digest,
    load_json,
    validate_campaign,
)

LEDGER_SCHEMA_VERSION = 1
MAX_EVENTS = 10_000
MAX_EVENT_BYTES = 262_144
GENESIS_HASH = "sha256:" + "0" * 64
EVENT_KINDS = frozenset(
    {
        "campaign_admitted",
        "phase_changed",
        "component_bound",
        "operation_transition",
        "observer_unavailable",
        "evidence_exported",
        "residual_assessed",
        "outcome_recorded",
    }
)
CAMPAIGN_PHASES = frozenset(
    {"admitted", "preparing", "ready", "running", "frozen", "destroyed", "invalid"}
)
OPERATION_NAMES = frozenset(
    {"prepare", "start", "freeze", "export", "reset", "destroy", "reconstruct", "verify"}
)
OPERATION_STATES = frozenset(
    {"prepared", "dispatched", "unknown", "reconciling", "succeeded", "failed"}
)
OPERATION_TRANSITIONS: dict[str | None, frozenset[str]] = {
    None: frozenset({"prepared"}),
    "prepared": frozenset({"dispatched", "failed"}),
    "dispatched": frozenset({"succeeded", "failed", "unknown"}),
    "unknown": frozenset({"reconciling"}),
    "reconciling": frozenset({"succeeded", "failed", "unknown"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
}
PHASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "admitted": frozenset({"preparing", "destroyed", "invalid"}),
    "preparing": frozenset({"ready", "frozen", "destroyed", "invalid"}),
    "ready": frozenset({"running", "frozen", "destroyed", "invalid"}),
    "running": frozenset({"frozen", "destroyed", "invalid"}),
    "frozen": frozenset({"ready", "destroyed", "invalid"}),
    "destroyed": frozenset(),
    "invalid": frozenset({"destroyed"}),
}
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class LedgerError(ContractError):
    """Base error for Campaign ledger admission, integrity, or transition failures."""


class LedgerCorrupt(LedgerError):
    """Persisted ledger bytes do not match the committed event contract."""


class LedgerConflict(LedgerError):
    """A caller attempted to advance a stale or terminal ledger head."""


@dataclass(frozen=True, slots=True)
class CampaignEvent:
    schema_version: int
    campaign_id: str
    world_id: str
    sequence: int
    recorded_at: str
    actor_id: str
    kind: str
    operation_id: str | None
    data: dict[str, Any]
    previous_hash: str
    event_hash: str

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        world_id: str,
        sequence: int,
        recorded_at: str,
        actor_id: str,
        kind: str,
        operation_id: str | None,
        data: dict[str, Any],
        previous_hash: str,
    ) -> "CampaignEvent":
        material = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "world_id": world_id,
            "sequence": sequence,
            "recorded_at": recorded_at,
            "actor_id": actor_id,
            "kind": kind,
            "operation_id": operation_id,
            "data": data,
            "previous_hash": previous_hash,
        }
        event = cls(event_hash=digest(material), **material)
        event.validate()
        return event

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CampaignEvent":
        expected = {
            "schema_version",
            "campaign_id",
            "world_id",
            "sequence",
            "recorded_at",
            "actor_id",
            "kind",
            "operation_id",
            "data",
            "previous_hash",
            "event_hash",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise LedgerCorrupt(["event: must contain the exact v1 field set"])
        event = cls(**value)
        event.validate()
        return event

    def validate(self) -> None:
        errors: list[str] = []
        if self.schema_version != LEDGER_SCHEMA_VERSION:
            errors.append("event.schema_version: must equal 1")
        for field, value in (
            ("campaign_id", self.campaign_id),
            ("world_id", self.world_id),
            ("actor_id", self.actor_id),
        ):
            if not isinstance(value, str) or not value.startswith("urn:ordivon:"):
                errors.append(f"event.{field}: must be an Ordivon URN")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            errors.append("event.sequence: must be a positive integer")
        if not isinstance(self.recorded_at, str) or UTC_RE.fullmatch(self.recorded_at) is None:
            errors.append("event.recorded_at: must use YYYY-MM-DDTHH:MM:SSZ")
        else:
            try:
                datetime.strptime(self.recorded_at, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                errors.append("event.recorded_at: must be a real UTC calendar timestamp")
        if self.kind not in EVENT_KINDS:
            errors.append(f"event.kind: unsupported kind {self.kind!r}")
        if self.operation_id is not None and (
            not isinstance(self.operation_id, str)
            or not self.operation_id.startswith("urn:ordivon:security:operation:")
        ):
            errors.append("event.operation_id: must be a Security operation URN or null")
        if not isinstance(self.data, dict):
            errors.append("event.data: must be an object")
        else:
            try:
                canonical_bytes(self.data)
            except ContractError as exc:
                errors.extend(f"event.data: {error}" for error in exc.errors)
        if SHA256_RE.fullmatch(self.previous_hash) is None:
            errors.append("event.previous_hash: must be a SHA-256 digest")
        if SHA256_RE.fullmatch(self.event_hash) is None:
            errors.append("event.event_hash: must be a SHA-256 digest")
        if not errors:
            material = self.to_dict()
            material.pop("event_hash")
            if digest(material) != self.event_hash:
                errors.append("event.event_hash: does not match canonical event material")
        if errors:
            raise LedgerCorrupt(errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "world_id": self.world_id,
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "actor_id": self.actor_id,
            "kind": self.kind,
            "operation_id": self.operation_id,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass(frozen=True, slots=True)
class CampaignProjection:
    campaign_id: str
    world_id: str
    manifest_digest: str
    phase: str
    revision: int
    head_hash: str
    operations: dict[str, dict[str, Any]]
    bindings: dict[str, dict[str, Any]]
    observer_status: str
    evidence_exports: tuple[dict[str, Any], ...]
    residual_report: dict[str, Any] | None
    outcome: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "campaign_id": self.campaign_id,
            "world_id": self.world_id,
            "manifest_digest": self.manifest_digest,
            "phase": self.phase,
            "revision": self.revision,
            "head_hash": self.head_hash,
            "operations": self.operations,
            "bindings": self.bindings,
            "observer_status": self.observer_status,
            "evidence_exports": list(self.evidence_exports),
            "residual_report": self.residual_report,
            "outcome": self.outcome,
        }


def _roles(manifest: dict[str, Any]) -> tuple[str, str, frozenset[str]]:
    authority = manifest["authority"]
    return (
        authority["lifecycle_actor_id"],
        authority["judge_actor_id"],
        frozenset(authority["observer_actor_ids"]),
    )


def _require_exact_data(data: dict[str, Any], required: set[str], label: str) -> None:
    if set(data) != required:
        raise LedgerCorrupt([f"{label}: must contain exact fields {sorted(required)!r}"])


def replay_campaign(
    manifest: dict[str, Any], events: Sequence[CampaignEvent | dict[str, Any]]
) -> CampaignProjection:
    """Rebuild one Campaign projection from its immutable event sequence."""

    validate_campaign(manifest)
    campaign_id = manifest["campaign"]["id"]
    world_id = manifest["world"]["id"]
    expected_manifest_digest = manifest["identity"]["manifest_digest"]
    lifecycle_actor, judge_actor, observer_actors = _roles(manifest)
    normalized = [
        item if isinstance(item, CampaignEvent) else CampaignEvent.from_dict(item)
        for item in events
    ]
    if not normalized:
        raise LedgerCorrupt(["ledger: Campaign has no admission event"])
    if len(normalized) > MAX_EVENTS:
        raise LedgerCorrupt([f"ledger: exceeds event limit {MAX_EVENTS}"])

    phase = "admitted"
    operations: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, Any]] = {}
    observer_status = "available"
    exports: list[dict[str, Any]] = []
    residual: dict[str, Any] | None = None
    outcome: dict[str, Any] | None = None
    previous_hash = GENESIS_HASH

    for index, event in enumerate(normalized, start=1):
        if event.sequence != index:
            raise LedgerCorrupt([f"event[{index}].sequence: ledger sequence is broken"])
        if event.campaign_id != campaign_id or event.world_id != world_id:
            raise LedgerCorrupt([f"event[{index}]: Campaign or World identity changed"])
        if event.previous_hash != previous_hash:
            raise LedgerCorrupt([f"event[{index}].previous_hash: hash chain is broken"])
        previous_hash = event.event_hash
        if outcome is not None:
            raise LedgerCorrupt([f"event[{index}]: final outcome prevents later events"])

        if index == 1:
            if event.kind != "campaign_admitted" or event.actor_id != lifecycle_actor:
                raise LedgerCorrupt(["event[1]: must be lifecycle-authority Campaign admission"])
            _require_exact_data(event.data, {"manifest_digest", "campaign_revision"}, "admission")
            if event.data["manifest_digest"] != expected_manifest_digest:
                raise LedgerCorrupt(["admission.manifest_digest: differs from admitted manifest"])
            if event.data["campaign_revision"] != manifest["campaign"]["revision"]:
                raise LedgerCorrupt(["admission.campaign_revision: differs from manifest"])
            continue

        if event.kind == "campaign_admitted":
            raise LedgerCorrupt([f"event[{index}]: Campaign admission may occur only once"])
        if event.kind in {
            "phase_changed",
            "component_bound",
            "operation_transition",
            "observer_unavailable",
            "evidence_exported",
            "residual_assessed",
        } and event.actor_id != lifecycle_actor:
            raise LedgerCorrupt([f"event[{index}]: lifecycle event uses another actor"])
        if event.kind == "outcome_recorded" and event.actor_id != judge_actor:
            raise LedgerCorrupt([f"event[{index}]: outcome must be recorded by the judge"])

        if event.kind == "phase_changed":
            _require_exact_data(event.data, {"phase", "reason"}, "phase change")
            target = event.data["phase"]
            if not isinstance(event.data["reason"], str) or not event.data["reason"]:
                raise LedgerCorrupt([f"event[{index}].reason: must be non-empty text"])
            if target not in CAMPAIGN_PHASES:
                raise LedgerCorrupt([f"event[{index}].phase: unsupported phase {target!r}"])
            if target not in PHASE_TRANSITIONS[phase]:
                raise LedgerCorrupt([f"event[{index}].phase: cannot transition {phase!r} to {target!r}"])
            phase = target
        elif event.kind == "component_bound":
            _require_exact_data(event.data, {"binding"}, "component binding")
            binding = ComponentBinding.from_dict(event.data["binding"])
            if binding.campaign_id != campaign_id or binding.world_id != world_id:
                raise LedgerCorrupt([f"event[{index}].binding: semantic identity differs"])
            current = bindings.get(binding.binding_id)
            if current is not None and current != binding.to_dict():
                raise LedgerCorrupt([f"event[{index}].binding: immutable binding changed"])
            bindings[binding.binding_id] = binding.to_dict()
        elif event.kind == "operation_transition":
            _require_exact_data(
                event.data,
                {"operation", "component", "state", "receipt", "detail"},
                "operation transition",
            )
            if event.operation_id is None:
                raise LedgerCorrupt([f"event[{index}].operation_id: is required"])
            operation = event.data["operation"]
            state = event.data["state"]
            component = event.data["component"]
            if operation not in OPERATION_NAMES:
                raise LedgerCorrupt([f"event[{index}].operation: unsupported operation"])
            if state not in OPERATION_STATES:
                raise LedgerCorrupt([f"event[{index}].state: unsupported operation state"])
            if not isinstance(component, str) or not component:
                raise LedgerCorrupt([f"event[{index}].component: must be non-empty"])
            if event.data["receipt"] is not None:
                if not isinstance(event.data["receipt"], dict):
                    raise LedgerCorrupt([f"event[{index}].receipt: must be an object or null"])
                canonical_bytes(event.data["receipt"])
            if not isinstance(event.data["detail"], str):
                raise LedgerCorrupt([f"event[{index}].detail: must be text"])
            existing = operations.get(event.operation_id)
            previous_state = None if existing is None else existing["state"]
            if existing is not None and (
                existing["operation"] != operation or existing["component"] != component
            ):
                raise LedgerCorrupt([f"event[{index}]: operation identity was rebound"])
            if state not in OPERATION_TRANSITIONS[previous_state]:
                raise LedgerCorrupt(
                    [f"event[{index}]: cannot transition operation {previous_state!r} to {state!r}"]
                )
            operations[event.operation_id] = {
                "operation": operation,
                "component": component,
                "state": state,
                "receipt": event.data["receipt"],
                "detail": event.data["detail"],
                "event_sequence": event.sequence,
            }
        elif event.kind == "observer_unavailable":
            _require_exact_data(
                event.data, {"observer_actor_id", "reason", "component"}, "observer loss"
            )
            if event.data["observer_actor_id"] not in observer_actors:
                raise LedgerCorrupt([f"event[{index}]: observer loss references another actor"])
            if not isinstance(event.data["reason"], str) or not event.data["reason"]:
                raise LedgerCorrupt([f"event[{index}].reason: must be non-empty text"])
            observer_status = "unavailable"
        elif event.kind == "evidence_exported":
            _require_exact_data(
                event.data,
                {"bundle_id", "bundle_digest", "file_count", "total_bytes"},
                "evidence export",
            )
            if SHA256_RE.fullmatch(event.data["bundle_digest"]) is None:
                raise LedgerCorrupt([f"event[{index}].bundle_digest: invalid digest"])
            for field in ("file_count", "total_bytes"):
                value = event.data[field]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise LedgerCorrupt([f"event[{index}].{field}: must be a non-negative integer"])
            exports.append(dict(event.data))
        elif event.kind == "residual_assessed":
            _require_exact_data(event.data, {"report"}, "residual assessment")
            residual = ResidualReport.from_dict(event.data["report"]).to_dict()
            if residual["campaign_id"] != campaign_id or residual["world_id"] != world_id:
                raise LedgerCorrupt([f"event[{index}].report: semantic identity differs"])
        elif event.kind == "outcome_recorded":
            if outcome is not None:
                raise LedgerCorrupt([f"event[{index}]: outcome may be recorded only once"])
            _require_exact_data(
                event.data,
                {"classification", "evidence_quality", "reason_codes", "evidence_refs"},
                "outcome",
            )
            if phase != "destroyed":
                raise LedgerCorrupt([f"event[{index}]: outcome requires destroyed Campaign phase"])
            classification = event.data["classification"]
            quality = event.data["evidence_quality"]
            reasons = event.data["reason_codes"]
            evidence_refs = event.data["evidence_refs"]
            if classification not in {
                "success",
                "partial_progress",
                "defense",
                "escape",
                "observer_loss",
                "invalid_run",
                "inconclusive_evidence",
                "containment_failure",
            }:
                raise LedgerCorrupt([f"event[{index}].classification: unsupported outcome"])
            expected_quality = {
                "observer_loss": "inconclusive",
                "inconclusive_evidence": "inconclusive",
                "invalid_run": "invalid",
                "containment_failure": "invalid",
            }.get(classification, "conclusive")
            if quality != expected_quality:
                raise LedgerCorrupt([f"event[{index}].evidence_quality: inconsistent outcome"])
            if classification == "observer_loss" and observer_status != "unavailable":
                raise LedgerCorrupt([f"event[{index}]: observer_loss lacks observer event"])
            if not isinstance(reasons, list) or any(
                not isinstance(item, str) or not item for item in reasons
            ):
                raise LedgerCorrupt([f"event[{index}].reason_codes: must be an array of text"])
            if classification in {
                "observer_loss",
                "invalid_run",
                "inconclusive_evidence",
                "containment_failure",
                "escape",
            } and not reasons:
                raise LedgerCorrupt([f"event[{index}].reason_codes: must explain outcome"])
            if not isinstance(evidence_refs, list) or any(
                not isinstance(item, str) or not item for item in evidence_refs
            ):
                raise LedgerCorrupt([f"event[{index}].evidence_refs: must be an array of text"])
            outcome = dict(event.data)

    return CampaignProjection(
        campaign_id=campaign_id,
        world_id=world_id,
        manifest_digest=expected_manifest_digest,
        phase=phase,
        revision=len(normalized),
        head_hash=normalized[-1].event_hash,
        operations=operations,
        bindings=bindings,
        observer_status=observer_status,
        evidence_exports=tuple(exports),
        residual_report=residual,
        outcome=outcome,
    )


class CampaignLedger:
    """File-backed single-Campaign ledger with atomic event admission."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.manifest_path = self.root / "manifest.json"
        self.events_root = self.root / "events"
        self.lock_path = self.root / ".ledger.lock"

    @classmethod
    def admit(
        cls,
        root: str | Path,
        manifest: dict[str, Any],
        *,
        recorded_at: str,
    ) -> "CampaignLedger":
        validate_campaign(manifest)
        ledger = cls(root)
        ledger.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        ledger.events_root.mkdir(exist_ok=True, mode=0o700)
        with ledger._locked():
            expected_bytes = canonical_bytes(manifest) + b"\n"
            if ledger.manifest_path.exists():
                actual = ledger.manifest_path.read_bytes()
                if actual != expected_bytes:
                    raise LedgerConflict(["manifest.json: Campaign identity is bound to other bytes"])
            else:
                ledger._atomic_write(ledger.manifest_path, expected_bytes)
            existing = ledger._read_events_unlocked()
            if not existing:
                lifecycle_actor = manifest["authority"]["lifecycle_actor_id"]
                event = CampaignEvent.create(
                    campaign_id=manifest["campaign"]["id"],
                    world_id=manifest["world"]["id"],
                    sequence=1,
                    recorded_at=recorded_at,
                    actor_id=lifecycle_actor,
                    kind="campaign_admitted",
                    operation_id=None,
                    data={
                        "manifest_digest": manifest["identity"]["manifest_digest"],
                        "campaign_revision": manifest["campaign"]["revision"],
                    },
                    previous_hash=GENESIS_HASH,
                )
                ledger._write_event_unlocked(event)
            replay_campaign(manifest, ledger._read_events_unlocked())
        return ledger

    def manifest(self) -> dict[str, Any]:
        if not self.manifest_path.is_file():
            raise LedgerCorrupt(["manifest.json: missing Campaign manifest"])
        return load_json(self.manifest_path)

    def events(self) -> tuple[CampaignEvent, ...]:
        with self._locked(shared=True):
            return tuple(self._read_events_unlocked())

    def projection(self) -> CampaignProjection:
        with self._locked(shared=True):
            return replay_campaign(self.manifest(), self._read_events_unlocked())

    def set_phase(self, phase: str, *, reason: str, recorded_at: str) -> CampaignProjection:
        if phase not in CAMPAIGN_PHASES:
            raise LedgerConflict([f"phase: unsupported Campaign phase {phase!r}"])
        return self._append_lifecycle(
            kind="phase_changed",
            operation_id=None,
            data={"phase": phase, "reason": reason},
            recorded_at=recorded_at,
        )

    def bind_component(
        self, binding: ComponentBinding, *, recorded_at: str
    ) -> CampaignProjection:
        current = self.projection()
        if binding.campaign_id != current.campaign_id or binding.world_id != current.world_id:
            raise LedgerConflict(["binding: Campaign or World identity differs"])
        if binding.binding_id in current.bindings:
            if current.bindings[binding.binding_id] == binding.to_dict():
                return current
            raise LedgerConflict(["binding: immutable binding identity was reused"])
        return self._append_lifecycle(
            kind="component_bound",
            operation_id=None,
            data={"binding": binding.to_dict()},
            recorded_at=recorded_at,
        )

    def transition_operation(
        self,
        *,
        operation_id: str,
        operation: str,
        component: str,
        state: str,
        recorded_at: str,
        receipt: dict[str, Any] | None = None,
        detail: str = "",
    ) -> CampaignProjection:
        if operation not in OPERATION_NAMES:
            raise LedgerConflict([f"operation: unsupported operation {operation!r}"])
        if state not in OPERATION_STATES:
            raise LedgerConflict([f"operation state: unsupported state {state!r}"])
        if not operation_id.startswith("urn:ordivon:security:operation:"):
            raise LedgerConflict(["operation_id: must be a Security operation URN"])
        current = self.projection()
        existing = current.operations.get(operation_id)
        candidate = {
            "operation": operation,
            "component": component,
            "state": state,
            "receipt": receipt,
            "detail": detail,
        }
        if existing is not None and all(existing[key] == value for key, value in candidate.items()):
            return current
        return self._append_lifecycle(
            kind="operation_transition",
            operation_id=operation_id,
            data=candidate,
            recorded_at=recorded_at,
        )

    def mark_observer_unavailable(
        self,
        *,
        observer_actor_id: str,
        component: str,
        reason: str,
        recorded_at: str,
    ) -> CampaignProjection:
        current = self.projection()
        if current.observer_status == "unavailable":
            return current
        return self._append_lifecycle(
            kind="observer_unavailable",
            operation_id=None,
            data={
                "observer_actor_id": observer_actor_id,
                "component": component,
                "reason": reason,
            },
            recorded_at=recorded_at,
        )

    def record_evidence_export(
        self,
        *,
        bundle_id: str,
        bundle_digest: str,
        file_count: int,
        total_bytes: int,
        recorded_at: str,
    ) -> CampaignProjection:
        current = self.projection()
        candidate = {
            "bundle_id": bundle_id,
            "bundle_digest": bundle_digest,
            "file_count": file_count,
            "total_bytes": total_bytes,
        }
        if candidate in current.evidence_exports:
            return current
        return self._append_lifecycle(
            kind="evidence_exported",
            operation_id=None,
            data=candidate,
            recorded_at=recorded_at,
        )

    def record_residual_report(
        self, report: ResidualReport, *, recorded_at: str
    ) -> CampaignProjection:
        current = self.projection()
        if report.campaign_id != current.campaign_id or report.world_id != current.world_id:
            raise LedgerConflict(["residual report: Campaign or World identity differs"])
        if current.residual_report == report.to_dict():
            return current
        return self._append_lifecycle(
            kind="residual_assessed",
            operation_id=None,
            data={"report": report.to_dict()},
            recorded_at=recorded_at,
        )

    def record_outcome(
        self,
        *,
        classification: str,
        evidence_quality: str,
        reason_codes: list[str],
        evidence_refs: list[str],
        recorded_at: str,
    ) -> CampaignProjection:
        current = self.projection()
        if current.phase != "destroyed":
            raise LedgerConflict(["outcome: Campaign must be destroyed before final classification"])
        data = {
            "classification": classification,
            "evidence_quality": evidence_quality,
            "reason_codes": reason_codes,
            "evidence_refs": evidence_refs,
        }
        if current.outcome is not None:
            if current.outcome == data:
                return current
            raise LedgerConflict(["outcome: Campaign already has a different outcome"])
        manifest = self.manifest()
        return self._append(
            actor_id=manifest["authority"]["judge_actor_id"],
            kind="outcome_recorded",
            operation_id=None,
            data=data,
            recorded_at=recorded_at,
        )

    def _append_lifecycle(
        self,
        *,
        kind: str,
        operation_id: str | None,
        data: dict[str, Any],
        recorded_at: str,
    ) -> CampaignProjection:
        manifest = self.manifest()
        return self._append(
            actor_id=manifest["authority"]["lifecycle_actor_id"],
            kind=kind,
            operation_id=operation_id,
            data=data,
            recorded_at=recorded_at,
        )

    def _append(
        self,
        *,
        actor_id: str,
        kind: str,
        operation_id: str | None,
        data: dict[str, Any],
        recorded_at: str,
    ) -> CampaignProjection:
        with self._locked():
            manifest = self.manifest()
            events = self._read_events_unlocked()
            before = replay_campaign(manifest, events)
            if before.outcome is not None:
                raise LedgerConflict(["ledger: final outcome prevents new events"])
            event = CampaignEvent.create(
                campaign_id=before.campaign_id,
                world_id=before.world_id,
                sequence=len(events) + 1,
                recorded_at=recorded_at,
                actor_id=actor_id,
                kind=kind,
                operation_id=operation_id,
                data=data,
                previous_hash=before.head_hash,
            )
            after = replay_campaign(manifest, [*events, event])
            self._write_event_unlocked(event)
            return after

    def _read_events_unlocked(self) -> list[CampaignEvent]:
        if not self.events_root.exists():
            return []
        entries = sorted(self.events_root.iterdir(), key=lambda path: path.name)
        unexpected = [path.name for path in entries if not re.fullmatch(r"[0-9]{20}\.json", path.name)]
        if unexpected:
            raise LedgerCorrupt([f"events: unexpected entries {unexpected[:5]!r}"])
        if len(entries) > MAX_EVENTS:
            raise LedgerCorrupt([f"events: exceeds event limit {MAX_EVENTS}"])
        result: list[CampaignEvent] = []
        for index, path in enumerate(entries, start=1):
            if not path.is_file() or path.is_symlink():
                raise LedgerCorrupt([f"events/{path.name}: must be a regular file"])
            raw = path.read_bytes()
            if not raw or len(raw) > MAX_EVENT_BYTES:
                raise LedgerCorrupt([f"events/{path.name}: invalid event byte length"])
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LedgerCorrupt([f"events/{path.name}: invalid JSON: {exc}"]) from exc
            event = CampaignEvent.from_dict(value)
            if path.name != f"{index:020d}.json":
                raise LedgerCorrupt([f"events/{path.name}: filename sequence is broken"])
            result.append(event)
        return result

    def _write_event_unlocked(self, event: CampaignEvent) -> None:
        if event.sequence > MAX_EVENTS:
            raise LedgerConflict([f"events: exceeds event limit {MAX_EVENTS}"])
        path = self.events_root / f"{event.sequence:020d}.json"
        payload = canonical_bytes(event.to_dict()) + b"\n"
        if len(payload) > MAX_EVENT_BYTES:
            raise LedgerConflict(["event: exceeds byte limit"])
        if path.exists():
            if path.read_bytes() == payload:
                return
            raise LedgerConflict([f"events/{path.name}: immutable event already exists"])
        self._atomic_write(path, payload)

    def _atomic_write(self, path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def _locked(self, *, shared: bool = False) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
