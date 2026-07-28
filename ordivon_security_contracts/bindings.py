"""Cross-component Campaign bindings and residual-state evidence.

Security owns the semantic Campaign and World identities. Link, Edge, Runtime,
Host, and Game retain their native identities. A binding joins those two layers
without pretending that one component's identifier is another component's
identifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .campaign import ContractError, canonical_bytes, digest

SUPPORTED_COMPONENTS = frozenset({"link", "edge", "runtime", "host", "game"})
RESIDUAL_STATUSES = frozenset(
    {
        "clean",
        "expected_retained",
        "unexpected_residual",
        "unknown",
        "observer_unavailable",
    }
)
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
URN_RE = re.compile(r"^urn:ordivon:[a-z][a-z0-9._-]*:[^\s]{1,220}$")


class BindingError(ContractError):
    """One or more component-binding violations."""


def _require_text(value: str, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BindingError([f"{label}: must be non-empty text without surrounding whitespace"])
    if len(value.encode("utf-8")) > maximum:
        raise BindingError([f"{label}: exceeds {maximum} UTF-8 bytes"])
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BindingError([f"{label}: contains control characters"])
    return value


def _require_urn(value: str, label: str) -> str:
    _require_text(value, label)
    if URN_RE.fullmatch(value) is None:
        raise BindingError([f"{label}: must be an Ordivon URN"])
    return value


def _require_digest(value: str, label: str) -> str:
    if SHA256_RE.fullmatch(value) is None:
        raise BindingError([f"{label}: must be a sha256:<64 lowercase hex> digest"])
    return value


def _require_json_object(value: dict[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BindingError([f"{label}: must be an object"])
    canonical_bytes(value)
    return value


@dataclass(frozen=True, slots=True)
class ComponentBinding:
    """Immutable binding from one Security Campaign to one native component object."""

    binding_id: str
    project: str
    campaign_id: str
    world_id: str
    native_id: str
    revision: str
    root_digest: str
    metadata: dict[str, Any]
    binding_digest: str

    @classmethod
    def create(
        cls,
        *,
        project: str,
        campaign_id: str,
        world_id: str,
        native_id: str,
        revision: str,
        root_digest: str,
        metadata: dict[str, Any] | None = None,
    ) -> "ComponentBinding":
        if project not in SUPPORTED_COMPONENTS:
            raise BindingError([f"project: unsupported component {project!r}"])
        _require_urn(campaign_id, "campaign_id")
        _require_urn(world_id, "world_id")
        _require_text(native_id, "native_id")
        _require_text(revision, "revision")
        _require_digest(root_digest, "root_digest")
        normalized_metadata = {} if metadata is None else dict(metadata)
        _require_json_object(normalized_metadata, "metadata")
        material = {
            "schema_version": 1,
            "project": project,
            "campaign_id": campaign_id,
            "world_id": world_id,
            "native_id": native_id,
            "revision": revision,
            "root_digest": root_digest,
            "metadata": normalized_metadata,
        }
        material_digest = digest(material)
        binding_id = (
            f"urn:ordivon:security:binding:{project}:{material_digest.removeprefix('sha256:')[:32]}"
        )
        return cls(
            binding_id=binding_id,
            project=project,
            campaign_id=campaign_id,
            world_id=world_id,
            native_id=native_id,
            revision=revision,
            root_digest=root_digest,
            metadata=normalized_metadata,
            binding_digest=material_digest,
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ComponentBinding":
        expected = {
            "schema_version",
            "binding_id",
            "project",
            "campaign_id",
            "world_id",
            "native_id",
            "revision",
            "root_digest",
            "metadata",
            "binding_digest",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise BindingError(["binding: must contain the exact v1 field set"])
        if value["schema_version"] != 1:
            raise BindingError(["binding.schema_version: must equal 1"])
        candidate = cls.create(
            project=value["project"],
            campaign_id=value["campaign_id"],
            world_id=value["world_id"],
            native_id=value["native_id"],
            revision=value["revision"],
            root_digest=value["root_digest"],
            metadata=value["metadata"],
        )
        if value["binding_id"] != candidate.binding_id:
            raise BindingError(["binding.binding_id: does not match binding material"])
        if value["binding_digest"] != candidate.binding_digest:
            raise BindingError(["binding.binding_digest: does not match binding material"])
        return candidate

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "binding_id": self.binding_id,
            "project": self.project,
            "campaign_id": self.campaign_id,
            "world_id": self.world_id,
            "native_id": self.native_id,
            "revision": self.revision,
            "root_digest": self.root_digest,
            "metadata": self.metadata,
            "binding_digest": self.binding_digest,
        }


@dataclass(frozen=True, slots=True)
class ResidualCheck:
    component: str
    subject_id: str
    status: str
    detail: str
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        if self.component not in SUPPORTED_COMPONENTS | {"security"}:
            raise BindingError([f"residual.component: unsupported component {self.component!r}"])
        _require_text(self.subject_id, "residual.subject_id")
        if self.status not in RESIDUAL_STATUSES:
            raise BindingError([f"residual.status: unsupported status {self.status!r}"])
        _require_text(self.detail, "residual.detail", maximum=2048)
        if self.evidence_ref is not None:
            _require_text(self.evidence_ref, "residual.evidence_ref", maximum=1024)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "subject_id": self.subject_id,
            "status": self.status,
            "detail": self.detail,
            "evidence_ref": self.evidence_ref,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResidualCheck":
        if not isinstance(value, dict) or set(value) != {
            "component",
            "subject_id",
            "status",
            "detail",
            "evidence_ref",
        }:
            raise BindingError(["residual check: must contain the exact v1 field set"])
        return cls(**value)


@dataclass(frozen=True, slots=True)
class ResidualReport:
    campaign_id: str
    world_id: str
    checks: tuple[ResidualCheck, ...]
    classification: str
    counts: dict[str, int]
    report_digest: str

    @classmethod
    def create(
        cls,
        *,
        campaign_id: str,
        world_id: str,
        checks: Iterable[ResidualCheck],
    ) -> "ResidualReport":
        _require_urn(campaign_id, "campaign_id")
        _require_urn(world_id, "world_id")
        normalized = tuple(checks)
        identities = [(item.component, item.subject_id) for item in normalized]
        if len(set(identities)) != len(identities):
            raise BindingError(["residual checks: component and subject identities must be unique"])
        counts = {status: 0 for status in sorted(RESIDUAL_STATUSES)}
        for check in normalized:
            counts[check.status] += 1
        if counts["unexpected_residual"]:
            classification = "residual_failure"
        elif counts["observer_unavailable"] or counts["unknown"]:
            classification = "inconclusive"
        else:
            classification = "clean"
        material = {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "world_id": world_id,
            "classification": classification,
            "counts": counts,
            "checks": [item.to_dict() for item in normalized],
        }
        return cls(
            campaign_id=campaign_id,
            world_id=world_id,
            checks=normalized,
            classification=classification,
            counts=counts,
            report_digest=digest(material),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "campaign_id": self.campaign_id,
            "world_id": self.world_id,
            "classification": self.classification,
            "counts": self.counts,
            "checks": [item.to_dict() for item in self.checks],
            "report_digest": self.report_digest,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResidualReport":
        expected = {
            "schema_version",
            "campaign_id",
            "world_id",
            "classification",
            "counts",
            "checks",
            "report_digest",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise BindingError(["residual report: must contain the exact v1 field set"])
        if value["schema_version"] != 1:
            raise BindingError(["residual report schema_version: must equal 1"])
        candidate = cls.create(
            campaign_id=value["campaign_id"],
            world_id=value["world_id"],
            checks=[ResidualCheck.from_dict(item) for item in value["checks"]],
        )
        if value["classification"] != candidate.classification:
            raise BindingError(["residual classification does not match checks"])
        if value["counts"] != candidate.counts:
            raise BindingError(["residual counts do not match checks"])
        if value["report_digest"] != candidate.report_digest:
            raise BindingError(["residual report digest does not match report material"])
        return candidate
