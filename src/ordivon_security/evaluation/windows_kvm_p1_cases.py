from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest

from .windows_kvm import _digest_path, _replace_private_json

_VM_SURFACE = "disposable-windows-kvm"
_HOST_BASELINE_SURFACE = "windows-host-read-only-baseline"


def _digest(value: str, label: str) -> str:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{label} digest is invalid")
    bytes.fromhex(value.removeprefix("sha256:"))
    if value.lower() != value:
        raise ValueError(f"{label} digest must be lowercase")
    return value


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or path == Path("."):
        raise ValueError("Derived component path must stay inside the payload root")
    return path


@dataclass(frozen=True, slots=True)
class CapabilityAdmission:
    deployment_authorized: bool
    evaluation_authorized: bool
    host_observation_authorized: bool
    host_modification_authorized: bool
    target_surface: str

    def __post_init__(self) -> None:
        if self.target_surface not in {_VM_SURFACE, _HOST_BASELINE_SURFACE}:
            raise ValueError("Capability Case target surface is unsupported")
        if self.deployment_authorized:
            raise ValueError("P1 capability Cases cannot authorize product deployment")
        if self.host_modification_authorized:
            raise ValueError("P1 capability Cases cannot authorize host modification")
        if not self.evaluation_authorized:
            raise ValueError("Capability Case must authorize bounded evaluation")
        if self.target_surface == _HOST_BASELINE_SURFACE and not self.host_observation_authorized:
            raise ValueError("Host baseline Case requires read-only host observation authority")
        if self.target_surface == _VM_SURFACE and self.host_observation_authorized:
            raise ValueError("Disposable VM Case must not claim host observation authority")

    @classmethod
    def from_dict(cls, value: JsonObject) -> CapabilityAdmission:
        return cls(
            deployment_authorized=value.get("deploymentAuthorized") is True,
            evaluation_authorized=value.get("evaluationAuthorized") is True,
            host_observation_authorized=value.get("hostObservationAuthorized") is True,
            host_modification_authorized=value.get("hostModificationAuthorized") is True,
            target_surface=str(value.get("targetSurface", "")),
        )

    def to_dict(self) -> JsonObject:
        return {
            "deploymentAuthorized": self.deployment_authorized,
            "evaluationAuthorized": self.evaluation_authorized,
            "hostObservationAuthorized": self.host_observation_authorized,
            "hostModificationAuthorized": self.host_modification_authorized,
            "targetSurface": self.target_surface,
        }


@dataclass(frozen=True, slots=True)
class DerivedComponent:
    logical_path: str
    digest: str
    byte_length: int
    role: str

    def __post_init__(self) -> None:
        _safe_relative(self.logical_path)
        _digest(self.digest, self.logical_path)
        if self.byte_length < 1 or not self.role:
            raise ValueError("Derived component identity is invalid")

    @classmethod
    def from_dict(cls, value: JsonObject) -> DerivedComponent:
        byte_length = value.get("byteLength")
        if not isinstance(byte_length, int) or isinstance(byte_length, bool):
            raise ValueError("Derived component byte length is invalid")
        return cls(
            logical_path=str(value.get("logicalPath", "")),
            digest=str(value.get("digest", "")),
            byte_length=byte_length,
            role=str(value.get("role", "")),
        )

    def to_dict(self) -> JsonObject:
        return {
            "logicalPath": self.logical_path,
            "digest": self.digest,
            "byteLength": self.byte_length,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class DerivedCaseManifest:
    manifest_id: str
    revision: str
    source_case_id: str
    source_case_digest: str
    transformations: tuple[str, ...]
    removed_components: tuple[JsonObject, ...]
    retained_components: tuple[DerivedComponent, ...]
    materialization_status: str
    resulting_tree_digest: str | None
    exportable_artifact: bool
    host_deployment: bool

    def __post_init__(self) -> None:
        if not self.manifest_id.startswith("transform:") or not self.revision:
            raise ValueError("Derived Case manifest identity is invalid")
        if not self.source_case_id.startswith("case:"):
            raise ValueError("Derived Case source identity is invalid")
        _digest(self.source_case_digest, "source Case")
        if not self.transformations or any(not item for item in self.transformations):
            raise ValueError("Derived Case transformations are missing")
        if not self.retained_components:
            raise ValueError("Derived Case retained components are missing")
        paths = [item.logical_path for item in self.retained_components]
        if len(paths) != len(set(paths)):
            raise ValueError("Derived Case retained component paths must be unique")
        if self.materialization_status not in {"planned", "materialized"}:
            raise ValueError("Derived Case materialization status is unsupported")
        if self.materialization_status == "materialized":
            if self.resulting_tree_digest is None:
                raise ValueError("Materialized derived Case requires a tree digest")
            _digest(self.resulting_tree_digest, "derived tree")
        elif self.resulting_tree_digest is not None:
            raise ValueError("Planned derived Case must not claim a tree digest")
        if self.exportable_artifact or self.host_deployment:
            raise ValueError("Derived P1 Case cannot be exportable or host-deployable")

    @classmethod
    def from_dict(cls, value: JsonObject) -> DerivedCaseManifest:
        if (
            value.get("schemaVersion") != 1
            or value.get("kind") != "ordivon.security.deweaponized-derived-case"
        ):
            raise ValueError("Derived Case manifest schema is unsupported")
        transformations = value.get("transformations")
        removed = value.get("removedComponents")
        retained = value.get("retainedComponents")
        if not isinstance(transformations, list) or not all(
            isinstance(item, str) for item in transformations
        ):
            raise ValueError("Derived Case transformations are invalid")
        if not isinstance(removed, list) or not all(isinstance(item, dict) for item in removed):
            raise ValueError("Derived Case removed components are invalid")
        if not isinstance(retained, list) or not all(isinstance(item, dict) for item in retained):
            raise ValueError("Derived Case retained components are invalid")
        return cls(
            manifest_id=str(value.get("manifestId", "")),
            revision=str(value.get("revision", "")),
            source_case_id=str(value.get("sourceCaseId", "")),
            source_case_digest=str(value.get("sourceCaseDigest", "")),
            transformations=tuple(cast(list[str], transformations)),
            removed_components=tuple(cast(list[JsonObject], removed)),
            retained_components=tuple(
                DerivedComponent.from_dict(cast(JsonObject, item)) for item in retained
            ),
            materialization_status=str(value.get("materializationStatus", "")),
            resulting_tree_digest=str(value["resultingTreeDigest"])
            if value.get("resultingTreeDigest") is not None
            else None,
            exportable_artifact=value.get("exportableArtifact") is True,
            host_deployment=value.get("hostDeployment") is True,
        )

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.deweaponized-derived-case",
            "manifestId": self.manifest_id,
            "revision": self.revision,
            "sourceCaseId": self.source_case_id,
            "sourceCaseDigest": self.source_case_digest,
            "transformations": list(self.transformations),
            "removedComponents": list(self.removed_components),
            "retainedComponents": [item.to_dict() for item in self.retained_components],
            "materializationStatus": self.materialization_status,
            "resultingTreeDigest": self.resulting_tree_digest,
            "exportableArtifact": self.exportable_artifact,
            "hostDeployment": self.host_deployment,
        }


@dataclass(frozen=True, slots=True)
class CapabilityCase:
    case_id: str
    revision: str
    role: str
    admission: CapabilityAdmission
    source: JsonObject
    observation_profile: str
    network_mode: str
    status: str
    controls: JsonObject

    def __post_init__(self) -> None:
        if not self.case_id.startswith("case:") or not self.revision:
            raise ValueError("Capability Case identity is invalid")
        if self.role not in {"control-free", "original-repack", "deweaponized-derived"}:
            raise ValueError("Capability Case role is unsupported")
        if not self.observation_profile or self.network_mode not in {"deny-all", "host-existing"}:
            raise ValueError("Capability Case observation or network mode is invalid")
        if self.role == "control-free" and self.admission.target_surface != _HOST_BASELINE_SURFACE:
            raise ValueError("Free control Case must use the read-only host baseline surface")
        if self.role != "control-free" and self.admission.target_surface != _VM_SURFACE:
            raise ValueError("Executable capability Cases require disposable Windows KVM")
        if self.controls.get("realC2") is True or self.controls.get("exportableArtifact") is True:
            raise ValueError("Capability Case control surface is unsafe")

    @classmethod
    def from_dict(cls, value: JsonObject) -> CapabilityCase:
        if (
            value.get("schemaVersion") != 1
            or value.get("kind") != "ordivon.security.capability-case"
        ):
            raise ValueError("Capability Case schema is unsupported")
        admission = value.get("admission")
        source = value.get("source")
        controls = value.get("controls")
        if (
            not isinstance(admission, dict)
            or not isinstance(source, dict)
            or not isinstance(controls, dict)
        ):
            raise ValueError("Capability Case admission, source, or controls are missing")
        return cls(
            case_id=str(value.get("caseId", "")),
            revision=str(value.get("revision", "")),
            role=str(value.get("role", "")),
            admission=CapabilityAdmission.from_dict(admission),
            source=source,
            observation_profile=str(value.get("observationProfile", "")),
            network_mode=str(value.get("networkMode", "")),
            status=str(value.get("status", "")),
            controls=controls,
        )

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.capability-case",
            "caseId": self.case_id,
            "revision": self.revision,
            "role": self.role,
            "admission": self.admission.to_dict(),
            "source": self.source,
            "observationProfile": self.observation_profile,
            "networkMode": self.network_mode,
            "status": self.status,
            "controls": self.controls,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


def materialize_derived_case(
    manifest: DerivedCaseManifest, component_sources: dict[str, Path], output_root: Path
) -> JsonObject:
    if manifest.materialization_status != "planned":
        raise ValueError("Only a planned derived Case may be materialized")
    if output_root.exists():
        raise FileExistsError(f"Derived Case output already exists: {output_root}")
    payload_root = output_root / "payload"
    payload_root.mkdir(parents=True, mode=0o700)
    try:
        entries: list[JsonObject] = []
        for component in manifest.retained_components:
            source = component_sources.get(component.logical_path)
            if source is None or source.is_symlink() or not source.is_file():
                raise ValueError(f"Derived component source is missing: {component.logical_path}")
            digest, byte_length = _digest_path(source)
            if digest != component.digest or byte_length != component.byte_length:
                raise ValueError(
                    f"Derived component differs from manifest: {component.logical_path}"
                )
            destination = payload_root / _safe_relative(component.logical_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.parent.chmod(0o700)
            shutil.copyfile(source, destination)
            destination.chmod(0o600)
            copied_digest, copied_length = _digest_path(destination)
            if copied_digest != digest or copied_length != byte_length:
                raise ValueError(
                    f"Derived component changed while copying: {component.logical_path}"
                )
            entries.append(
                {
                    "logicalPath": component.logical_path,
                    "digest": copied_digest,
                    "byteLength": copied_length,
                    "role": component.role,
                }
            )
        sorted_entries = sorted(entries, key=lambda item: str(item["logicalPath"]))
        tree_identity: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.derived-case-tree",
            "entries": cast(list[JsonValue], sorted_entries),
        }
        tree_digest = canonical_digest(tree_identity)
        materialized = DerivedCaseManifest(
            manifest_id=manifest.manifest_id,
            revision=manifest.revision,
            source_case_id=manifest.source_case_id,
            source_case_digest=manifest.source_case_digest,
            transformations=manifest.transformations,
            removed_components=manifest.removed_components,
            retained_components=manifest.retained_components,
            materialization_status="materialized",
            resulting_tree_digest=tree_digest,
            exportable_artifact=False,
            host_deployment=False,
        )
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.deweaponized-derived-case-materialization",
            "status": "materialized-private-evaluation-input",
            "manifest": materialized.to_dict(),
            "manifestDigest": canonical_digest(materialized.to_dict()),
            "treeIdentity": tree_identity,
            "treeDigest": tree_digest,
            "payloadRoot": str(payload_root),
            "exportableArtifact": False,
            "hostDeployment": False,
        }
        _replace_private_json(output_root / "manifest.json", receipt)
        return receipt
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
