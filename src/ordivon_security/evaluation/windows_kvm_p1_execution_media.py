from __future__ import annotations

import contextlib
import json
import math
import os
import shutil
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest
from ordivon_security.identity import security_source_identity

from .windows_kvm import _digest_path, _replace_private_json, _run_checked
from .windows_kvm_p1_cases import CapabilityCase, EnvironmentTransformationManifest

_EXECUTION_LABEL = "ORDIVON_P1_EXEC"
_EXECUTION_SERIAL = "ORDIVON_P1_EXEC"
_REQUIRED_TRANSFORMATIONS = frozenset(
    {
        "attach-source-read-only",
        "host-materialize-read-only-execution-tree",
        "deny-external-network-at-hypervisor",
        "provide-local-record-only-fake-network-boundary",
        "block-unknown-secondary-executable-launch",
        "use-disposable-overlay-and-destroy-after-run",
    }
)
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{value}" for value in range(1, 10)}
    | {f"LPT{value}" for value in range(1, 10)}
)


def _digest(value: str, label: str) -> str:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"Windows KVM P1 {label} digest is invalid")
    bytes.fromhex(value.removeprefix("sha256:"))
    if value.lower() != value:
        raise ValueError(f"Windows KVM P1 {label} digest must be lowercase")
    return value


def _integer(value: JsonValue | None, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Windows KVM P1 {label} must be an integer")
    return value


def _safe_windows_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path == PurePosixPath(".")
        or ".." in path.parts
        or "\\" in value
    ):
        raise ValueError("Execution-tree path must be a normalized relative POSIX path")
    for component in path.parts:
        if (
            component in {"", ".", ".."}
            or component.endswith((" ", "."))
            or ":" in component
            or any(ord(character) < 32 for character in component)
        ):
            raise ValueError(f"Execution-tree path is not safe on Windows: {value}")
        stem = component.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError(f"Execution-tree path uses a reserved Windows name: {value}")
    return path


def _tool_identity(path: Path) -> JsonObject:
    digest, byte_length = _digest_path(path)
    return {"path": str(path), "digest": digest, "byteLength": byte_length}


@dataclass(frozen=True, slots=True)
class WindowsKvmP1ExecutionContract:
    contract_id: str
    revision: str
    case_id: str
    case_manifest_digest: str
    transformation_manifest_id: str
    transformation_manifest_digest: str
    source_archive_digest: str
    source_archive_byte_length: int
    source_archive_name: str
    installer_relative_path: str
    installer_digest: str
    installer_byte_length: int
    installer_arguments: tuple[str, ...]
    observation_profile: str
    required_transformations: tuple[str, ...]
    materialization_authorized: bool
    controller_admitted: bool
    execution_authorized: bool
    host_modification_authorized: bool
    exportable_artifact: bool
    source_read_only: bool
    execution_media_read_only: bool
    network_mode: str
    known_destination_boundary: str
    unknown_secondary_execution: str
    disposable_overlay: bool
    destroy_overlay_after_run: bool
    operator_directed_execution: bool = False
    operator_direction: str = ""

    def __post_init__(self) -> None:
        if not self.contract_id.startswith("contract:") or not self.revision:
            raise ValueError("Windows KVM P1 execution contract identity is invalid")
        if not self.case_id.startswith("case:"):
            raise ValueError("Windows KVM P1 execution contract Case identity is invalid")
        if not self.transformation_manifest_id.startswith("transform:"):
            raise ValueError("Windows KVM P1 transformation identity is invalid")
        _digest(self.case_manifest_digest, "Case manifest")
        _digest(self.transformation_manifest_digest, "transformation manifest")
        _digest(self.source_archive_digest, "source archive")
        _digest(self.installer_digest, "installer")
        if (
            self.source_archive_byte_length < 1
            or not self.source_archive_name
            or Path(self.source_archive_name).name != self.source_archive_name
        ):
            raise ValueError("Windows KVM P1 source archive identity is invalid")
        _safe_windows_relative(self.installer_relative_path)
        if self.installer_byte_length < 1:
            raise ValueError("Windows KVM P1 installer byte length is invalid")
        if any(not argument or chr(0) in argument for argument in self.installer_arguments):
            raise ValueError("Windows KVM P1 installer arguments are invalid")
        if not self.observation_profile:
            raise ValueError("Windows KVM P1 observation profile is missing")
        if len(self.required_transformations) != len(set(self.required_transformations)):
            raise ValueError("Windows KVM P1 required transformations must be unique")
        missing = _REQUIRED_TRANSFORMATIONS - set(self.required_transformations)
        if missing:
            raise ValueError(
                f"Windows KVM P1 execution transformations are incomplete: {sorted(missing)}"
            )
        if not self.materialization_authorized:
            raise ValueError("Windows KVM P1 execution-media materialization must be explicit")
        if self.operator_directed_execution and not self.operator_direction.strip():
            raise ValueError("Operator-directed execution requires a bound operator direction")
        if not self.operator_directed_execution and self.operator_direction:
            raise ValueError("Operator direction requires the operator-directed-execution flag")
        if (self.controller_admitted or self.execution_authorized) and not (
            self.operator_directed_execution
        ):
            raise ValueError("This P1 contract cannot admit a Controller or installer execution")
        if self.host_modification_authorized or self.exportable_artifact:
            raise ValueError(
                "Windows KVM P1 execution input cannot modify the host or be exportable"
            )
        if not self.source_read_only or not self.execution_media_read_only:
            raise ValueError("Windows KVM P1 source and execution media must remain read-only")
        if self.network_mode != "deny-all-at-hypervisor":
            raise ValueError("Windows KVM P1 execution contract requires hypervisor deny-all")
        if self.known_destination_boundary != "loopback-record-only":
            raise ValueError("Windows KVM P1 known destinations require a record-only boundary")
        if self.unknown_secondary_execution != "block-by-admitted-policy":
            raise ValueError("Windows KVM P1 secondary execution requires an admitted policy")
        if (
            not self.disposable_overlay or not self.destroy_overlay_after_run
        ) and not self.operator_directed_execution:
            raise ValueError("Windows KVM P1 execution contract requires disposable closure")

    @classmethod
    def from_dict(cls, value: JsonObject) -> WindowsKvmP1ExecutionContract:
        if (
            value.get("schemaVersion") != 1
            or value.get("kind") != "ordivon.security.windows-kvm-p1-execution-contract"
        ):
            raise ValueError("Windows KVM P1 execution contract schema is unsupported")
        source = value.get("sourceArchive")
        installer = value.get("installer")
        controls = value.get("controls")
        authorization = value.get("authorization")
        required = value.get("requiredTransformations")
        arguments = installer.get("arguments") if isinstance(installer, dict) else None
        if (
            not isinstance(source, dict)
            or not isinstance(installer, dict)
            or not isinstance(controls, dict)
            or not isinstance(authorization, dict)
            or not isinstance(required, list)
            or not all(isinstance(item, str) for item in required)
            or not isinstance(arguments, list)
            or not all(isinstance(item, str) for item in arguments)
        ):
            raise ValueError("Windows KVM P1 execution contract sections are invalid")
        return cls(
            contract_id=str(value.get("contractId", "")),
            revision=str(value.get("revision", "")),
            case_id=str(value.get("caseId", "")),
            case_manifest_digest=str(value.get("caseManifestDigest", "")),
            transformation_manifest_id=str(value.get("transformationManifestId", "")),
            transformation_manifest_digest=str(value.get("transformationManifestDigest", "")),
            source_archive_digest=str(source.get("digest", "")),
            source_archive_byte_length=_integer(source.get("byteLength"), "archive byte length"),
            source_archive_name=str(source.get("name", "")),
            installer_relative_path=str(installer.get("relativePath", "")),
            installer_digest=str(installer.get("digest", "")),
            installer_byte_length=_integer(installer.get("byteLength"), "installer byte length"),
            installer_arguments=tuple(cast(list[str], arguments)),
            observation_profile=str(value.get("observationProfile", "")),
            required_transformations=tuple(cast(list[str], required)),
            materialization_authorized=authorization.get("materializationAuthorized") is True,
            controller_admitted=authorization.get("controllerAdmitted") is True,
            execution_authorized=authorization.get("executionAuthorized") is True,
            host_modification_authorized=authorization.get("hostModificationAuthorized") is True,
            exportable_artifact=authorization.get("exportableArtifact") is True,
            source_read_only=controls.get("sourceReadOnly") is True,
            execution_media_read_only=controls.get("executionMediaReadOnly") is True,
            network_mode=str(controls.get("networkMode", "")),
            known_destination_boundary=str(controls.get("knownDestinationBoundary", "")),
            unknown_secondary_execution=str(controls.get("unknownSecondaryExecution", "")),
            disposable_overlay=controls.get("disposableOverlay") is True,
            destroy_overlay_after_run=controls.get("destroyOverlayAfterRun") is True,
            operator_directed_execution=authorization.get("operatorDirectedExecution") is True,
            operator_direction=str(authorization.get("operatorDirection", "")),
        )

    def validate_authority(
        self,
        case_manifest_value: JsonObject,
        case: CapabilityCase,
        transformation: EnvironmentTransformationManifest,
    ) -> None:
        if case.role != "original-repack" or case.case_id != self.case_id:
            raise ValueError("Execution contract does not bind the Case A original repack")
        if canonical_digest(case_manifest_value) != self.case_manifest_digest:
            raise ValueError("Execution contract differs from the exact Case manifest")
        if case.transformation_manifest_digest != self.transformation_manifest_digest:
            raise ValueError("Execution contract differs from the Case transformation binding")
        if transformation.manifest_id != self.transformation_manifest_id:
            raise ValueError("Execution contract transformation identity differs")
        if transformation.digest != self.transformation_manifest_digest:
            raise ValueError("Execution contract transformation digest differs")
        if set(self.required_transformations) - set(transformation.transformations):
            raise ValueError("Execution contract transformations differ from the manifest")
        if (
            transformation.retained_sample_digest != self.source_archive_digest
            or transformation.retained_sample_byte_length != self.source_archive_byte_length
        ):
            raise ValueError("Execution contract retained Sample differs")
        if (
            case.source.get("archiveDigest") != self.source_archive_digest
            or case.source.get("archiveByteLength") != self.source_archive_byte_length
            or case.source.get("archiveName") != self.source_archive_name
        ):
            raise ValueError("Execution contract source archive differs from Case A")
        if case.observation_profile != self.observation_profile or case.network_mode != "deny-all":
            raise ValueError("Execution contract observation or network authority differs")
        if (
            case.controls.get("sampleBytesChanged") is not False
            or case.controls.get("fakeNetworkService") != "local-record-only"
            or case.controls.get("unknownSecondaryExecution") != "block"
        ):
            raise ValueError("Execution contract differs from Case A controls")
        if (
            case.controls.get("destroyOverlayAfterRun") is not True
            and not self.operator_directed_execution
        ):
            raise ValueError("Execution contract differs from Case A controls")

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-execution-contract",
            "contractId": self.contract_id,
            "revision": self.revision,
            "caseId": self.case_id,
            "caseManifestDigest": self.case_manifest_digest,
            "transformationManifestId": self.transformation_manifest_id,
            "transformationManifestDigest": self.transformation_manifest_digest,
            "sourceArchive": {
                "digest": self.source_archive_digest,
                "byteLength": self.source_archive_byte_length,
                "name": self.source_archive_name,
            },
            "installer": {
                "relativePath": self.installer_relative_path,
                "digest": self.installer_digest,
                "byteLength": self.installer_byte_length,
                "arguments": list(self.installer_arguments),
            },
            "observationProfile": self.observation_profile,
            "requiredTransformations": list(self.required_transformations),
            "controls": {
                "sourceReadOnly": self.source_read_only,
                "executionMediaReadOnly": self.execution_media_read_only,
                "networkMode": self.network_mode,
                "knownDestinationBoundary": self.known_destination_boundary,
                "unknownSecondaryExecution": self.unknown_secondary_execution,
                "disposableOverlay": self.disposable_overlay,
                "destroyOverlayAfterRun": self.destroy_overlay_after_run,
            },
            "authorization": {
                "materializationAuthorized": self.materialization_authorized,
                "controllerAdmitted": self.controller_admitted,
                "executionAuthorized": self.execution_authorized,
                "hostModificationAuthorized": self.host_modification_authorized,
                "exportableArtifact": self.exportable_artifact,
                "operatorDirectedExecution": self.operator_directed_execution,
                "operatorDirection": self.operator_direction,
            },
        }


@dataclass(frozen=True, slots=True)
class WindowsKvmP1ExecutionTreeEntry:
    logical_path: str
    digest: str
    byte_length: int

    def __post_init__(self) -> None:
        _safe_windows_relative(self.logical_path)
        _digest(self.digest, self.logical_path)
        if self.byte_length < 0:
            raise ValueError("Windows KVM P1 execution-tree byte length is invalid")

    def to_dict(self) -> JsonObject:
        return {
            "logicalPath": self.logical_path,
            "digest": self.digest,
            "byteLength": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class WindowsKvmP1ExecutionTree:
    directories: tuple[str, ...]
    files: tuple[WindowsKvmP1ExecutionTreeEntry, ...]
    total_file_bytes: int

    def __post_init__(self) -> None:
        if self.total_file_bytes < 0:
            raise ValueError("Windows KVM P1 execution-tree size is invalid")
        paths = [*self.directories, *(entry.logical_path for entry in self.files)]
        if len(paths) != len(set(paths)):
            raise ValueError("Windows KVM P1 execution-tree paths must be unique")
        casefolded = [path.casefold() for path in paths]
        if len(casefolded) != len(set(casefolded)):
            raise ValueError("Windows KVM P1 execution-tree paths collide on Windows")
        for path in self.directories:
            _safe_windows_relative(path)
        if sum(entry.byte_length for entry in self.files) != self.total_file_bytes:
            raise ValueError("Windows KVM P1 execution-tree total does not match entries")

    def to_dict(self) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-execution-tree",
            "directories": list(self.directories),
            "files": [entry.to_dict() for entry in self.files],
            "fileCount": len(self.files),
            "directoryCount": len(self.directories),
            "totalFileBytes": self.total_file_bytes,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class WindowsKvmP1ExecutionMediaConfig:
    state_root: Path
    seven_zip_path: Path = Path("/usr/sbin/7z")
    mkntfs_path: Path = Path("/usr/bin/mkntfs")
    ntfs_3g_path: Path = Path("/usr/bin/ntfs-3g")
    umount_path: Path = Path("/usr/bin/umount")
    mountpoint_path: Path = Path("/usr/bin/mountpoint")
    sync_path: Path = Path("/usr/bin/sync")
    overhead_mib: int = 512
    max_entries: int = 100_000
    max_total_file_bytes: int = 64 * 1024**3
    max_listing_bytes: int = 32 * 1024**2

    def __post_init__(self) -> None:
        if str(self.state_root.resolve(strict=False)).startswith("/mnt/"):
            raise ValueError("Execution media cannot be materialized on a mounted Windows volume")
        if self.overhead_mib < 128 or self.max_entries < 1 or self.max_total_file_bytes < 1:
            raise ValueError("Windows KVM P1 execution-media limits are invalid")
        if self.max_listing_bytes < 1024:
            raise ValueError("Windows KVM P1 archive-listing bound is invalid")
        for path in (
            self.seven_zip_path,
            self.mkntfs_path,
            self.ntfs_3g_path,
            self.umount_path,
            self.mountpoint_path,
            self.sync_path,
        ):
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    f"Windows KVM P1 execution-media tool is missing or unsafe: {path}"
                )


def windows_kvm_p1_execution_media_arguments(image_path: Path) -> list[str]:
    return [
        "-drive",
        f"file={image_path},if=none,format=raw,readonly=on,cache=none,aio=threads,id=execdisk",
        "-device",
        f"usb-storage,drive=execdisk,removable=on,serial={_EXECUTION_SERIAL}",
    ]


def _archive_members(
    source_path: Path, config: WindowsKvmP1ExecutionMediaConfig
) -> tuple[str, ...]:
    completed = subprocess.run(
        [str(config.seven_zip_path), "l", "-slt", "-sccUTF-8", "--", str(source_path)],
        check=False,
        capture_output=True,
        timeout=600,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"7-Zip archive listing failed ({completed.returncode}): {completed.stderr[:4096]!r}"
        )
    if len(completed.stdout) > config.max_listing_bytes:
        raise ValueError("Windows KVM P1 archive listing exceeds the admitted bound")
    text = completed.stdout.decode("utf-8", errors="strict")
    separator_seen = False
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not separator_seen:
            if line.startswith("----------"):
                separator_seen = True
            continue
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, separator, field_value = line.partition(" = ")
        if separator:
            current[key] = field_value
    if current:
        blocks.append(current)
    if not separator_seen:
        raise ValueError("Windows KVM P1 archive listing is malformed")
    files: list[str] = []
    for block in blocks:
        path_value = block.get("Path")
        if path_value is None:
            continue
        normalized = _safe_windows_relative(path_value).as_posix()
        attributes = block.get("Attributes", "")
        attribute_tokens = attributes.split()
        if (
            "Symbolic Link" in block
            or "Hard Link" in block
            or "Reparse" in block
            or any(token.startswith("l") for token in attribute_tokens)
        ):
            raise ValueError(
                f"Windows KVM P1 archive contains a link or reparse entry: {normalized}"
            )
        is_directory = block.get("Folder") == "+" or attributes.startswith("D")
        if not is_directory:
            files.append(normalized)
    if not files:
        raise ValueError("Windows KVM P1 archive contains no regular file entries")
    if len(files) > config.max_entries:
        raise ValueError("Windows KVM P1 archive entry count exceeds the admitted bound")
    casefolded = [path.casefold() for path in files]
    if len(casefolded) != len(set(casefolded)):
        raise ValueError("Windows KVM P1 archive paths collide on Windows")
    return tuple(sorted(files))


def _extract_archive(
    source_path: Path, destination: Path, config: WindowsKvmP1ExecutionMediaConfig
) -> None:
    _run_checked(
        [str(config.seven_zip_path), "t", "-bd", "-bb0", "--", str(source_path)],
        timeout_seconds=3600,
    )
    _run_checked(
        [
            str(config.seven_zip_path),
            "x",
            "-y",
            "-bd",
            "-bb0",
            "-sccUTF-8",
            f"-o{destination}",
            "--",
            str(source_path),
        ],
        timeout_seconds=7200,
    )


def _scan_execution_tree(
    root: Path,
    *,
    max_entries: int,
    max_total_file_bytes: int,
    normalize_permissions: bool = True,
) -> WindowsKvmP1ExecutionTree:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Windows KVM P1 execution-tree root is missing or unsafe")
    directories: list[str] = []
    files: list[WindowsKvmP1ExecutionTreeEntry] = []
    casefolded: set[str] = set()
    total = 0
    for current_root, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        for name in sorted(directory_names):
            path = current / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
                raise ValueError(f"Execution tree contains a non-directory link: {path}")
            logical = _safe_windows_relative(path.relative_to(root).as_posix()).as_posix()
            folded = logical.casefold()
            if folded in casefolded:
                raise ValueError("Windows KVM P1 execution-tree paths collide on Windows")
            casefolded.add(folded)
            directories.append(logical)
            if normalize_permissions:
                path.chmod(0o700)
        for name in sorted(file_names):
            path = current / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
                raise ValueError(f"Execution tree contains a link or special file: {path}")
            logical = _safe_windows_relative(path.relative_to(root).as_posix()).as_posix()
            folded = logical.casefold()
            if folded in casefolded:
                raise ValueError("Windows KVM P1 execution-tree paths collide on Windows")
            casefolded.add(folded)
            digest, byte_length = _digest_path(path)
            total += byte_length
            if total > max_total_file_bytes:
                raise ValueError("Windows KVM P1 execution-tree size exceeds the admitted bound")
            files.append(
                WindowsKvmP1ExecutionTreeEntry(
                    logical_path=logical,
                    digest=digest,
                    byte_length=byte_length,
                )
            )
            if normalize_permissions:
                path.chmod(0o600)
            if len(files) + len(directories) > max_entries:
                raise ValueError("Windows KVM P1 execution-tree entry count exceeds the bound")
    return WindowsKvmP1ExecutionTree(
        directories=tuple(sorted(directories)),
        files=tuple(sorted(files, key=lambda entry: entry.logical_path)),
        total_file_bytes=total,
    )


def _copy_execution_tree(source: Path, destination: Path, tree: WindowsKvmP1ExecutionTree) -> None:
    destination.mkdir(parents=True, mode=0o700)
    for logical in tree.directories:
        target = destination / _safe_windows_relative(logical)
        target.mkdir(parents=True, exist_ok=False)
        target.chmod(0o700)
    for entry in tree.files:
        source_path = source / _safe_windows_relative(entry.logical_path)
        target = destination / _safe_windows_relative(entry.logical_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        target.chmod(0o600)
        digest, byte_length = _digest_path(target)
        if digest != entry.digest or byte_length != entry.byte_length:
            raise ValueError(f"Execution-tree file changed while copying: {entry.logical_path}")


def _format_ntfs_image(
    image_path: Path, size_bytes: int, config: WindowsKvmP1ExecutionMediaConfig
) -> None:
    with image_path.open("xb") as handle:
        handle.truncate(size_bytes)
    image_path.chmod(0o600)
    _run_checked(
        [str(config.mkntfs_path), "-F", "-Q", "-L", _EXECUTION_LABEL, str(image_path)],
        timeout_seconds=600,
    )


def _is_mountpoint(path: Path, config: WindowsKvmP1ExecutionMediaConfig) -> bool:
    return (
        subprocess.run(
            [str(config.mountpoint_path), "-q", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        ).returncode
        == 0
    )


@contextmanager
def _mounted_ntfs(
    image_path: Path,
    mount_path: Path,
    config: WindowsKvmP1ExecutionMediaConfig,
    *,
    read_only: bool,
) -> Iterator[Path]:
    mount_path.mkdir(parents=True, exist_ok=False, mode=0o700)
    options = (
        "ro,nodev,nosuid,noexec,uid=0,gid=0,umask=077"
        if read_only
        else "rw,nodev,nosuid,noexec,uid=0,gid=0,umask=077"
    )
    _run_checked(
        [str(config.ntfs_3g_path), str(image_path), str(mount_path), "-o", options],
        timeout_seconds=120,
    )
    try:
        yield mount_path
    finally:
        _run_checked([str(config.umount_path), str(mount_path)], timeout_seconds=120)
        if _is_mountpoint(mount_path, config):
            raise RuntimeError("Windows KVM P1 execution-media mount remained after unmount")
        with contextlib.suppress(OSError):
            mount_path.rmdir()


def materialize_windows_kvm_p1_execution_media(
    contract: WindowsKvmP1ExecutionContract,
    case_manifest_value: JsonObject,
    case: CapabilityCase,
    transformation: EnvironmentTransformationManifest,
    source_path: Path,
    config: WindowsKvmP1ExecutionMediaConfig,
) -> JsonObject:
    contract.validate_authority(case_manifest_value, case, transformation)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("Windows KVM P1 source archive is missing or unsafe")
    source_digest, source_length = _digest_path(source_path)
    if (
        source_digest != contract.source_archive_digest
        or source_length != contract.source_archive_byte_length
    ):
        raise ValueError("Windows KVM P1 source differs from the execution contract")
    security_identity = security_source_identity()
    tools: JsonObject = {
        "sevenZip": _tool_identity(config.seven_zip_path),
        "mkntfs": _tool_identity(config.mkntfs_path),
        "ntfs3g": _tool_identity(config.ntfs_3g_path),
        "umount": _tool_identity(config.umount_path),
        "mountpoint": _tool_identity(config.mountpoint_path),
        "sync": _tool_identity(config.sync_path),
    }
    identity: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-kvm-p1-execution-media-identity",
        "implementation": security_identity,
        "contractDigest": contract.digest,
        "transformationManifestDigest": transformation.digest,
        "tools": tools,
        "filesystem": "ntfs",
        "volumeLabel": _EXECUTION_LABEL,
        "declaredAttachment": {
            "readOnly": True,
            "removable": True,
            "serial": _EXECUTION_SERIAL,
        },
    }
    media_root = config.state_root / "execution-media" / contract.digest[-16:]
    if media_root.exists():
        raise FileExistsError(f"Windows KVM P1 execution media already exists: {media_root}")
    media_root.mkdir(parents=True, mode=0o700)
    staging_root = media_root / "extracted.staging"
    image_path = media_root / "execution.ntfs.img"
    manifest_path = media_root / "manifest.json"
    try:
        listed_files = _archive_members(source_path, config)
        staging_root.mkdir(mode=0o700)
        _extract_archive(source_path, staging_root, config)
        tree = _scan_execution_tree(
            staging_root,
            max_entries=config.max_entries,
            max_total_file_bytes=config.max_total_file_bytes,
        )
        extracted_files = tuple(entry.logical_path for entry in tree.files)
        if extracted_files != listed_files:
            raise ValueError("Extracted execution tree differs from the archive file inventory")
        installer = next(
            (
                entry
                for entry in tree.files
                if entry.logical_path == contract.installer_relative_path
            ),
            None,
        )
        if (
            installer is None
            or installer.digest != contract.installer_digest
            or installer.byte_length != contract.installer_byte_length
        ):
            raise ValueError("Execution-tree installer differs from the exact contract")
        tree_value = tree.to_dict()
        tree_bytes = (json.dumps(tree_value, ensure_ascii=False, sort_keys=True) + "\n").encode()
        required_bytes = tree.total_file_bytes + len(tree_bytes) + config.overhead_mib * 1024**2
        size_bytes = max(1024**3, math.ceil(required_bytes / 1024**3) * 1024**3)
        _format_ntfs_image(image_path, size_bytes, config)
        with _mounted_ntfs(image_path, media_root / "mount-rw", config, read_only=False) as mount:
            payload_root = mount / "payload"
            _copy_execution_tree(staging_root, payload_root, tree)
            tree_path = mount / "execution-tree.json"
            tree_path.write_bytes(tree_bytes)
            tree_path.chmod(0o600)
            _run_checked([str(config.sync_path), "-f", str(mount)], timeout_seconds=120)
        with _mounted_ntfs(image_path, media_root / "mount-ro", config, read_only=True) as mount:
            verified_tree = _scan_execution_tree(
                mount / "payload",
                max_entries=config.max_entries,
                max_total_file_bytes=config.max_total_file_bytes,
                normalize_permissions=False,
            )
            if verified_tree.to_dict() != tree_value:
                raise ValueError("Read-only NTFS execution tree differs after staging")
            retained_tree_value = json.loads(
                (mount / "execution-tree.json").read_text(encoding="utf-8")
            )
            if retained_tree_value != tree_value:
                raise ValueError("Read-only NTFS tree manifest differs after staging")
        source_digest_after, source_length_after = _digest_path(source_path)
        if source_digest_after != source_digest or source_length_after != source_length:
            raise ValueError("Windows KVM P1 source archive changed during materialization")
        image_digest, image_length = _digest_path(image_path)
        payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-execution-media",
            "status": "materialized-not-admitted",
            "contract": contract.to_dict(),
            "contractDigest": contract.digest,
            "caseManifestDigest": contract.case_manifest_digest,
            "transformationManifestDigest": transformation.digest,
            "implementation": security_identity,
            "tools": tools,
            "materializationIdentity": identity,
            "materializationIdentityDigest": canonical_digest(identity),
            "source": {
                "digest": source_digest,
                "byteLength": source_length,
                "name": contract.source_archive_name,
                "readOnly": True,
                "bytesChanged": False,
            },
            "tree": tree_value,
            "treeDigest": tree.digest,
            "installer": installer.to_dict(),
            "media": {
                "path": str(image_path),
                "digest": image_digest,
                "byteLength": image_length,
                "allocatedBytes": image_path.stat().st_blocks * 512,
                "filesystem": "ntfs",
                "volumeLabel": _EXECUTION_LABEL,
                "guestPayloadRoot": "/payload",
                "guestTreeManifest": "/execution-tree.json",
                "readOnly": True,
                "removable": True,
                "serial": _EXECUTION_SERIAL,
                "qemuArguments": cast(
                    list[JsonValue], windows_kvm_p1_execution_media_arguments(image_path)
                ),
            },
            "authorization": {
                "materializationAuthorized": True,
                "qemuAttachmentAuthorized": False,
                "controllerAdmitted": False,
                "executionAuthorized": False,
                "hostModificationAuthorized": False,
                "exportableArtifact": False,
            },
        }
        shutil.rmtree(staging_root)
        _replace_private_json(manifest_path, payload)
        return payload
    except BaseException:
        for mount_name in ("mount-rw", "mount-ro"):
            mount_path = media_root / mount_name
            if mount_path.exists() and _is_mountpoint(mount_path, config):
                with contextlib.suppress(Exception):
                    _run_checked([str(config.umount_path), str(mount_path)], timeout_seconds=120)
        shutil.rmtree(media_root, ignore_errors=True)
        raise
