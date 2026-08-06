from __future__ import annotations

import contextlib
import hashlib
import json
import math
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest
from ordivon_security.identity import security_source_identity

from .windows_kvm import _digest_path, _replace_private_json, _run_checked

_P1_PREPARE_ACTION = "prepare-authorized-windows-installer-media"
_P1_INSPECT_ACTION = "inspect-authorized-windows-installer"
_P1_LABEL = "ORDIVON_P1"
_P1_SERIAL = "ORDIVON_P1"
_P1_VM_SURFACE = "disposable-windows-kvm"


def _integer(value: JsonValue | None, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _tool_identity(path: Path) -> JsonObject:
    digest, byte_length = _digest_path(path)
    return {"path": str(path), "digest": digest, "byteLength": byte_length}


def _digest_stream(arguments: list[str]) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_length = 0
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr = b""
    code = -1
    try:
        assert process.stdout is not None
        while chunk := process.stdout.read(4 * 1024 * 1024):
            digest.update(chunk)
            byte_length += len(chunk)
        stderr = b"" if process.stderr is None else process.stderr.read()
        code = process.wait(timeout=300)
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if code != 0:
        raise RuntimeError(f"NTFS verification command failed ({code}): {stderr[:4096]!r}")
    return "sha256:" + digest.hexdigest(), byte_length


@dataclass(frozen=True, slots=True)
class WindowsKvmInstallerProfile:
    profile_id: str
    revision: str
    case_id: str
    archive_digest: str
    archive_byte_length: int
    archive_name: str
    deployment_authorized: bool = False
    evaluation_authorized: bool = False
    host_modification_authorized: bool = False
    target_surface: str = _P1_VM_SURFACE
    network_mode: str = "deny-all"
    allow_restart: bool = False
    max_runtime_ms: int = 45 * 60 * 1000
    expected_publisher: str | None = None
    installer_relative_path: str | None = None
    arguments: tuple[str, ...] = ()
    observation_profile: str = "windows-installer-p1"

    def __post_init__(self) -> None:
        if (
            not self.profile_id.startswith("profile:")
            or not self.case_id.startswith("case:")
            or not self.revision
        ):
            raise ValueError("Windows KVM P1 profile or Case identity is invalid")
        if len(self.archive_digest) != 71 or not self.archive_digest.startswith("sha256:"):
            raise ValueError("Windows KVM P1 archive digest is invalid")
        bytes.fromhex(self.archive_digest.removeprefix("sha256:"))
        if self.archive_digest.lower() != self.archive_digest:
            raise ValueError("Windows KVM P1 archive digest must be lowercase")
        if (
            self.archive_byte_length < 1
            or not self.archive_name
            or Path(self.archive_name).name != self.archive_name
        ):
            raise ValueError("Windows KVM P1 archive identity is invalid")
        if self.target_surface != _P1_VM_SURFACE:
            raise ValueError("Windows KVM P1 installer evaluation requires a disposable VM surface")
        if self.deployment_authorized:
            raise ValueError("Windows KVM P1 cannot authorize product deployment")
        if self.host_modification_authorized:
            raise ValueError("Windows KVM P1 cannot authorize host modification")
        if self.network_mode != "deny-all" or self.allow_restart:
            raise ValueError("Windows KVM P1 first gate requires deny-all and no restart")
        if self.max_runtime_ms < 1 or not self.observation_profile:
            raise ValueError("Windows KVM P1 limits are invalid")
        if self.installer_relative_path is not None:
            installer_path = Path(self.installer_relative_path)
            if installer_path.is_absolute() or ".." in installer_path.parts:
                raise ValueError("Windows KVM P1 installer path must stay within the input disk")
        if any(not argument or "\x00" in argument for argument in self.arguments):
            raise ValueError("Windows KVM P1 installer arguments are invalid")
        if self.evaluation_authorized and self.installer_relative_path is None:
            raise ValueError("Evaluation-authorized P1 profile must bind the installer path")

    @property
    def execution_authorized(self) -> bool:
        """Legacy alias: execution means isolated evaluation, never deployment."""
        return self.evaluation_authorized

    @classmethod
    def from_dict(cls, value: JsonObject) -> WindowsKvmInstallerProfile:
        if (
            value.get("schemaVersion") not in {1, 2}
            or value.get("kind") != "ordivon.security.windows-kvm-installer-profile"
        ):
            raise ValueError("Windows KVM P1 profile schema is unsupported")
        arguments_value = value.get("arguments", [])
        if not isinstance(arguments_value, list) or not all(
            isinstance(item, str) for item in arguments_value
        ):
            raise ValueError("Windows KVM P1 arguments are invalid")
        arguments = cast(list[str], arguments_value)
        evaluation_authorized = (
            value.get("evaluationAuthorized") is True or value.get("executionAuthorized") is True
        )
        return cls(
            profile_id=str(value.get("profileId", "")),
            revision=str(value.get("revision", "")),
            case_id=str(value.get("caseId", "")),
            archive_digest=str(value.get("archiveDigest", "")),
            archive_byte_length=_integer(value.get("archiveByteLength"), "Archive byte length"),
            archive_name=str(value.get("archiveName", "")),
            deployment_authorized=value.get("deploymentAuthorized") is True,
            evaluation_authorized=evaluation_authorized,
            host_modification_authorized=value.get("hostModificationAuthorized") is True,
            target_surface=str(value.get("targetSurface", _P1_VM_SURFACE)),
            network_mode=str(value.get("networkMode", "")),
            allow_restart=value.get("allowRestart") is True,
            max_runtime_ms=_integer(value.get("maxRuntimeMs"), "Maximum runtime"),
            expected_publisher=str(value["expectedPublisher"])
            if value.get("expectedPublisher") is not None
            else None,
            installer_relative_path=str(value["installerRelativePath"])
            if value.get("installerRelativePath") is not None
            else None,
            arguments=tuple(arguments),
            observation_profile=str(value.get("observationProfile", "")),
        )

    def to_dict(self) -> JsonObject:
        permitted = [_P1_PREPARE_ACTION]
        if self.evaluation_authorized:
            permitted.append(_P1_INSPECT_ACTION)
        return {
            "schemaVersion": 2,
            "kind": "ordivon.security.windows-kvm-installer-profile",
            "profileId": self.profile_id,
            "revision": self.revision,
            "caseId": self.case_id,
            "archiveDigest": self.archive_digest,
            "archiveByteLength": self.archive_byte_length,
            "archiveName": self.archive_name,
            "permittedActions": cast(list[JsonValue], permitted),
            "deploymentAuthorized": self.deployment_authorized,
            "evaluationAuthorized": self.evaluation_authorized,
            "hostModificationAuthorized": self.host_modification_authorized,
            "targetSurface": self.target_surface,
            "executionAuthorized": self.evaluation_authorized,
            "networkMode": self.network_mode,
            "allowRestart": self.allow_restart,
            "maxRuntimeMs": self.max_runtime_ms,
            "expectedPublisher": self.expected_publisher,
            "installerRelativePath": self.installer_relative_path,
            "arguments": list(self.arguments),
            "observationProfile": self.observation_profile,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class WindowsKvmP1MediaConfig:
    state_root: Path
    mkntfs_path: Path = Path("/usr/bin/mkntfs")
    ntfscp_path: Path = Path("/usr/bin/ntfscp")
    ntfscat_path: Path = Path("/usr/bin/ntfscat")
    overhead_mib: int = 512

    def __post_init__(self) -> None:
        if self.overhead_mib < 128:
            raise ValueError("Windows KVM P1 media overhead is too small")
        for path in (self.mkntfs_path, self.ntfscp_path, self.ntfscat_path):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Windows KVM P1 media tool is missing or unsafe: {path}")


def windows_kvm_p1_sample_disk_arguments(image_path: Path) -> list[str]:
    return [
        "-drive",
        f"file={image_path},if=none,format=raw,readonly=on,cache=none,aio=threads,id=sampledisk",
        "-device",
        f"usb-storage,drive=sampledisk,removable=on,serial={_P1_SERIAL}",
    ]


def prepare_windows_kvm_installer_media(
    profile: WindowsKvmInstallerProfile, source_path: Path, config: WindowsKvmP1MediaConfig
) -> JsonObject:
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("Windows KVM P1 source is missing or unsafe")
    source_digest, source_length = _digest_path(source_path)
    if source_digest != profile.archive_digest or source_length != profile.archive_byte_length:
        raise ValueError("Windows KVM P1 source differs from the authorized archive identity")
    security_identity = security_source_identity()
    tool_identities: JsonObject = {
        "mkntfs": _tool_identity(config.mkntfs_path),
        "ntfscp": _tool_identity(config.ntfscp_path),
        "ntfscat": _tool_identity(config.ntfscat_path),
    }
    preparation_identity: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-kvm-p1-media-preparation-identity",
        "implementation": security_identity,
        "profileDigest": profile.digest,
        "tools": tool_identities,
        "filesystem": "ntfs",
        "volumeLabel": _P1_LABEL,
        "attachment": {"readOnly": True, "removable": True, "serial": _P1_SERIAL},
    }
    media_root = config.state_root / "sample-media" / source_digest[-16:]
    if media_root.exists():
        raise FileExistsError(f"Windows KVM P1 media already exists: {media_root}")
    media_root.mkdir(parents=True, mode=0o700)
    image_path = media_root / "installer.ntfs.img"
    manifest_path = media_root / "manifest.json"
    size_bytes = math.ceil((source_length + config.overhead_mib * 1024 * 1024) / (1024**3)) * (
        1024**3
    )
    try:
        with image_path.open("xb") as handle:
            handle.truncate(size_bytes)
        image_path.chmod(0o600)
        _run_checked(
            [str(config.mkntfs_path), "-F", "-Q", "-L", _P1_LABEL, str(image_path)],
            timeout_seconds=300,
        )
        guest_path = "/" + profile.archive_name
        _run_checked(
            [str(config.ntfscp_path), "-f", str(image_path), str(source_path), guest_path],
            timeout_seconds=3600,
        )
        embedded_digest, embedded_length = _digest_stream(
            [str(config.ntfscat_path), str(image_path), guest_path]
        )
        if embedded_digest != source_digest or embedded_length != source_length:
            raise ValueError("Windows KVM P1 NTFS media content differs after staging")
        source_digest_after, source_length_after = _digest_path(source_path)
        if source_digest_after != source_digest or source_length_after != source_length:
            raise ValueError("Windows KVM P1 source changed during media preparation")
        image_digest, image_length = _digest_path(image_path)
        payload: JsonObject = {
            "schemaVersion": 2,
            "kind": "ordivon.security.windows-kvm-p1-sample-media",
            "status": "prepared-evaluation-candidate"
            if profile.evaluation_authorized
            else "prepared-not-executable",
            "profile": profile.to_dict(),
            "profileDigest": profile.digest,
            "implementation": security_identity,
            "tools": tool_identities,
            "preparationIdentity": preparation_identity,
            "preparationIdentityDigest": canonical_digest(preparation_identity),
            "source": {
                "digest": source_digest,
                "byteLength": source_length,
                "logicalName": profile.archive_name,
            },
            "media": {
                "path": str(image_path),
                "digest": image_digest,
                "byteLength": image_length,
                "allocatedBytes": image_path.stat().st_blocks * 512,
                "filesystem": "ntfs",
                "volumeLabel": _P1_LABEL,
                "guestPath": guest_path,
                "readOnly": True,
                "removable": True,
                "serial": _P1_SERIAL,
                "qemuArguments": cast(
                    list[JsonValue], windows_kvm_p1_sample_disk_arguments(image_path)
                ),
            },
            "deploymentAuthorized": False,
            "evaluationAuthorized": profile.evaluation_authorized,
            "hostModificationAuthorized": False,
            "executionAuthorized": profile.evaluation_authorized,
        }
        _replace_private_json(manifest_path, payload)
        return payload
    except BaseException:
        shutil.rmtree(media_root, ignore_errors=True)
        raise


def reconcile_windows_kvm_p1_non_executable_media(
    state_root: Path, receipts_root: Path
) -> tuple[JsonObject, ...]:
    """Remove only manifest-verified P1 media that has no evaluation authority."""
    sample_root = state_root / "sample-media"
    if not sample_root.exists():
        return ()
    receipts_root.mkdir(parents=True, exist_ok=True)
    receipts_root.chmod(0o700)
    receipts: list[JsonObject] = []
    for media_root in sorted(sample_root.iterdir()):
        if media_root.is_symlink() or not media_root.is_dir():
            continue
        manifest_path = media_root / "manifest.json"
        image_path = media_root / "installer.ntfs.img"
        if not manifest_path.is_file() or not image_path.is_file():
            continue
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("kind") != "ordivon.security.windows-kvm-p1-sample-media"
        ):
            continue
        profile = value.get("profile")
        media = value.get("media")
        if not isinstance(profile, dict) or not isinstance(media, dict):
            continue
        evaluation_authorized = any(
            item is True
            for item in (
                profile.get("evaluationAuthorized"),
                profile.get("executionAuthorized"),
                value.get("evaluationAuthorized"),
                value.get("executionAuthorized"),
            )
        )
        if evaluation_authorized:
            continue
        if media.get("path") != str(image_path):
            raise ValueError("P1 media manifest path differs from the state-root image")
        actual_digest, actual_length = _digest_path(image_path)
        if actual_digest != media.get("digest") or actual_length != media.get("byteLength"):
            raise ValueError("P1 media differs from its retained manifest")
        manifest_digest, manifest_length = _digest_path(manifest_path)
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-residual-closure-correction",
            "status": "removed",
            "reason": "prepared non-executable media remained after an earlier closeout claim",
            "correctedAtMs": time.time_ns() // 1_000_000,
            "media": {
                "digest": actual_digest,
                "byteLength": actual_length,
                "allocatedBytes": image_path.stat().st_blocks * 512,
            },
            "manifest": {"digest": manifest_digest, "byteLength": manifest_length},
            "evaluationAuthorized": False,
            "hostModificationAuthorized": False,
            "removed": True,
        }
        receipt_path = receipts_root / f"windows-kvm-p1-residual-correction-{media_root.name}.json"
        shutil.rmtree(media_root)
        _replace_private_json(receipt_path, receipt)
        receipts.append(receipt)
    with contextlib.suppress(OSError):
        sample_root.rmdir()
    return tuple(receipts)
