from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.identity import security_source_identity
from ordivon_security.providers.windows_kvm import (
    WindowsKvmBaseImage,
    _digest_path,
    _load_object,
    _replace_private_json,
    _run_checked,
)

from .models import SampleIdentity
from .vault import SampleVault

_RESOURCE_PATHS: dict[str, PurePosixPath] = {
    "generic-controller": PurePosixPath("ProgramData/Ordivon/p1-controller.exe"),
    "execution-control-canary": PurePosixPath(
        "ProgramData/Ordivon/acceptance/p1-execution-control-canary.exe"
    ),
    "orchestrator": PurePosixPath("ProgramData/Ordivon/p1-orchestrator.ps1"),
}


@dataclass(frozen=True, slots=True)
class WindowsKvmP1SealedResource:
    slot: str
    sample: SampleIdentity

    def __post_init__(self) -> None:
        if self.slot not in _RESOURCE_PATHS:
            raise ValueError(f"Unsupported P1 sealed-resource slot: {self.slot}")

    @property
    def guest_path(self) -> str:
        return "/" + _RESOURCE_PATHS[self.slot].as_posix()

    def to_dict(self) -> JsonObject:
        return {
            "slot": self.slot,
            "guestPath": self.guest_path,
            "sample": self.sample.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class WindowsKvmP1DerivedBaseConfig:
    state_root: Path
    qemu_img_path: Path = Path("/usr/bin/qemu-img")
    qemu_nbd_path: Path = Path("/usr/bin/qemu-nbd")
    modprobe_path: Path = Path("/usr/bin/modprobe")
    partx_path: Path = Path("/usr/bin/partx")
    ntfsls_path: Path = Path("/usr/bin/ntfsls")
    ntfs_3g_path: Path = Path("/usr/bin/ntfs-3g")
    umount_path: Path = Path("/usr/bin/umount")
    mountpoint_path: Path = Path("/usr/bin/mountpoint")
    sync_path: Path = Path("/usr/bin/sync")
    sys_block_root: Path = Path("/sys/block")
    device_root: Path = Path("/dev")
    max_nbd_devices: int = 16
    run_group: str = "qemu"

    def __post_init__(self) -> None:
        if str(self.state_root.resolve(strict=False)).startswith("/mnt/"):
            raise ValueError("Derived Windows base cannot be sealed on a mounted Windows volume")
        if self.max_nbd_devices < 1 or self.max_nbd_devices > 64:
            raise ValueError("Derived Windows base NBD device bound is invalid")
        for path in (
            self.qemu_img_path,
            self.qemu_nbd_path,
            self.modprobe_path,
            self.partx_path,
            self.ntfsls_path,
            self.ntfs_3g_path,
            self.umount_path,
            self.mountpoint_path,
            self.sync_path,
        ):
            if not path.exists() or not path.resolve().is_file():
                raise ValueError(f"Derived Windows base tool is missing or unsafe: {path}")
        if not self.run_group or self.run_group != self.run_group.strip():
            raise ValueError("Derived Windows base run group is invalid")


def _tool_identity(path: Path) -> JsonObject:
    resolved = path.resolve()
    digest, byte_length = _digest_path(resolved)
    return {
        "path": str(path),
        "resolvedPath": str(resolved),
        "digest": digest,
        "byteLength": byte_length,
    }


def _resource_identity(resources: Sequence[WindowsKvmP1SealedResource]) -> list[JsonObject]:
    if not resources:
        raise ValueError("Derived Windows base requires at least one sealed resource")
    slots = [resource.slot for resource in resources]
    if len(slots) != len(set(slots)):
        raise ValueError("Derived Windows base resource slots must be unique")
    return [resource.to_dict() for resource in sorted(resources, key=lambda item: item.slot)]


def _resolve_resources(
    resources: Sequence[WindowsKvmP1SealedResource], vault: SampleVault
) -> dict[str, Path]:
    resolved: dict[str, Path] = {}
    for resource in resources:
        path = vault.resolve(resource.sample)
        digest, byte_length = _digest_path(path)
        if digest != resource.sample.sha256 or byte_length != resource.sample.byte_length:
            raise ValueError(f"Vault resource changed during resolve: {resource.slot}")
        resolved[resource.slot] = path
    return resolved


def _nbd_sys_root(device: Path, config: WindowsKvmP1DerivedBaseConfig) -> Path:
    return config.sys_block_root / device.name


def _ensure_nbd_devices(config: WindowsKvmP1DerivedBaseConfig) -> bool:
    if any(
        (config.device_root / f"nbd{index}").exists()
        for index in range(config.max_nbd_devices)
    ):
        return False
    _run_checked(
        [str(config.modprobe_path), "nbd", f"max_part={config.max_nbd_devices}"],
        timeout_seconds=30,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if any(
            (config.device_root / f"nbd{index}").exists()
            for index in range(config.max_nbd_devices)
        ):
            return True
        time.sleep(0.1)
    raise RuntimeError("NBD devices did not appear after loading the nbd kernel module")


def _free_nbd(config: WindowsKvmP1DerivedBaseConfig) -> Path:
    for index in range(config.max_nbd_devices):
        device = config.device_root / f"nbd{index}"
        sys_root = config.sys_block_root / f"nbd{index}"
        if not device.exists() or not sys_root.is_dir():
            continue
        try:
            if int((sys_root / "size").read_text(encoding="utf-8").strip()) == 0:
                return device
        except (OSError, ValueError):
            continue
    raise RuntimeError("No free NBD device is available for derived-base sealing")


def _wait_nbd(
    device: Path,
    config: WindowsKvmP1DerivedBaseConfig,
    *,
    connected: bool,
    read_only: bool | None = None,
) -> None:
    sys_root = _nbd_sys_root(device, config)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            size = int((sys_root / "size").read_text(encoding="utf-8").strip())
            ro = (sys_root / "ro").read_text(encoding="utf-8").strip() == "1"
        except (OSError, ValueError):
            size = 0
            ro = False
        if not connected and size == 0:
            return
        if connected and size > 0 and (read_only is None or ro is read_only):
            return
        time.sleep(0.1)
    state = "connected" if connected else "disconnected"
    raise RuntimeError(f"NBD device did not reach {state} state: {device}")


def _windows_partition(device: Path, config: WindowsKvmP1DerivedBaseConfig) -> Path:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        for index in range(1, 17):
            partition = Path(f"{device}p{index}")
            if not partition.exists():
                continue
            completed = subprocess.run(
                [str(config.ntfsls_path), "-p", "/Windows", str(partition)],
                check=False,
                capture_output=True,
                timeout=15,
            )
            if completed.returncode == 0:
                return partition
        time.sleep(0.1)
    raise RuntimeError("Derived-base sealer could not identify the Windows partition")


def _disconnect_nbd(device: Path, config: WindowsKvmP1DerivedBaseConfig) -> JsonObject:
    partx = subprocess.run(
        [str(config.partx_path), "-d", str(device)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    disconnect = subprocess.run(
        [str(config.qemu_nbd_path), "--disconnect", str(device)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    if disconnect.returncode != 0:
        raise RuntimeError(
            f"Derived-base NBD disconnect failed ({disconnect.returncode}): "
            f"{disconnect.stdout[-500:]}"
        )
    _wait_nbd(device, config, connected=False)
    return {
        "device": str(device),
        "partxDeleteReturnCode": partx.returncode,
        "nbdDisconnectReturnCode": disconnect.returncode,
        "blockSizeReturnedToZero": True,
    }


@contextmanager
def _connected_windows_partition(
    image_path: Path,
    config: WindowsKvmP1DerivedBaseConfig,
    *,
    read_only: bool,
) -> Iterator[tuple[Path, Path, JsonObject]]:
    device = _free_nbd(config)
    arguments = [str(config.qemu_nbd_path)]
    if read_only:
        arguments.append("--read-only")
    arguments.extend(["--format=qcow2", f"--connect={device}", str(image_path)])
    _run_checked(arguments, timeout_seconds=30)
    closure: JsonObject = {}
    try:
        _wait_nbd(device, config, connected=True, read_only=read_only)
        subprocess.run(
            [str(config.partx_path), "-u", str(device)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        partition = _windows_partition(device, config)
        yield device, partition, closure
    finally:
        closure.update(_disconnect_nbd(device, config))


def _is_mountpoint(path: Path, config: WindowsKvmP1DerivedBaseConfig) -> bool:
    return (
        subprocess.run(
            [str(config.mountpoint_path), "-q", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).returncode
        == 0
    )


@contextmanager
def _mounted_windows_partition(
    partition: Path,
    mount_path: Path,
    config: WindowsKvmP1DerivedBaseConfig,
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
        [str(config.ntfs_3g_path), str(partition), str(mount_path), "-o", options],
        timeout_seconds=120,
    )
    try:
        yield mount_path
    finally:
        _run_checked([str(config.umount_path), str(mount_path)], timeout_seconds=120)
        if _is_mountpoint(mount_path, config):
            raise RuntimeError("Derived-base NTFS mount remained after unmount")
        mount_path.rmdir()


def _target_path(mount: Path, resource: WindowsKvmP1SealedResource) -> Path:
    relative = _RESOURCE_PATHS[resource.slot]
    target = mount.joinpath(*relative.parts)
    program_data = mount / "ProgramData"
    if not program_data.is_dir() or program_data.is_symlink():
        raise ValueError("Derived-base ProgramData root is missing or unsafe")
    ordivon_root = program_data / "Ordivon"
    if ordivon_root.exists() and (not ordivon_root.is_dir() or ordivon_root.is_symlink()):
        raise ValueError("Derived-base Ordivon root is unsafe")
    ordivon_root.mkdir(exist_ok=True)
    current = ordivon_root
    for component in relative.parts[2:-1]:
        current = current / component
        if current.exists() and (not current.is_dir() or current.is_symlink()):
            raise ValueError(f"Derived-base resource parent is unsafe: {current}")
        current.mkdir(exist_ok=True)
    if target.is_symlink():
        raise ValueError(f"Derived-base resource target is a symlink: {target}")
    return target


def _copy_resources(
    mount: Path,
    resources: Sequence[WindowsKvmP1SealedResource],
    sources: dict[str, Path],
) -> None:
    for resource in resources:
        source = sources[resource.slot]
        target = _target_path(mount, resource)
        if target.exists():
            existing_digest, existing_length = _digest_path(target)
            if (
                existing_digest != resource.sample.sha256
                or existing_length != resource.sample.byte_length
            ):
                raise ValueError(
                    f"Derived-base managed resource already exists with different bytes: "
                    f"{resource.slot}"
                )
            continue
        shutil.copyfile(source, target)
        digest, byte_length = _digest_path(target)
        if digest != resource.sample.sha256 or byte_length != resource.sample.byte_length:
            raise ValueError(f"Derived-base resource changed while copying: {resource.slot}")


def _verify_resources(
    mount: Path,
    resources: Sequence[WindowsKvmP1SealedResource],
) -> list[JsonObject]:
    verified: list[JsonObject] = []
    for resource in resources:
        target = _target_path(mount, resource)
        if not target.is_file() or target.is_symlink():
            raise ValueError(f"Derived-base sealed resource is missing: {resource.slot}")
        digest, byte_length = _digest_path(target)
        if digest != resource.sample.sha256 or byte_length != resource.sample.byte_length:
            raise ValueError(f"Derived-base sealed resource readback differs: {resource.slot}")
        verified.append(
            {
                "slot": resource.slot,
                "guestPath": resource.guest_path,
                "digest": digest,
                "byteLength": byte_length,
                "readOnlyVerified": True,
            }
        )
    return verified


def _backing_chain(overlay_path: Path, config: WindowsKvmP1DerivedBaseConfig) -> JsonObject:
    completed = _run_checked(
        [
            str(config.qemu_img_path),
            "info",
            "--output=json",
            "--backing-chain",
            str(overlay_path),
        ],
        timeout_seconds=60,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list) or len(value) < 2 or not isinstance(value[0], dict):
        raise ValueError("Derived-base qemu-img backing chain is malformed")
    first = value[0]
    backing = first.get("full-backing-filename", first.get("backing-filename"))
    if not isinstance(backing, str) or not backing:
        raise ValueError("Derived-base qemu-img backing path is missing")
    return {
        "backingPath": backing,
        "chainLength": len(value),
        "overlayFormat": first.get("format"),
    }


def seal_windows_kvm_p1_derived_base(
    *,
    parent_manifest_path: Path,
    resources: Sequence[WindowsKvmP1SealedResource],
    vault: SampleVault,
    config: WindowsKvmP1DerivedBaseConfig,
) -> JsonObject:
    parent = WindowsKvmBaseImage.load(parent_manifest_path)
    parent_manifest = _load_object(parent_manifest_path, "Windows KVM parent base manifest")
    parent_manifest_digest = canonical_digest(parent_manifest)
    resource_values = _resource_identity(resources)
    resource_digest = canonical_digest(resource_values)
    sources = _resolve_resources(resources, vault)
    parent_image_digest_before, parent_image_bytes = _digest_path(parent.base_image_path)
    if parent_image_digest_before != parent.base_image_digest:
        raise ValueError("Derived-base parent image differs before sealing")

    module_loaded = _ensure_nbd_devices(config)
    tools: JsonObject = {
        "qemuImg": _tool_identity(config.qemu_img_path),
        "qemuNbd": _tool_identity(config.qemu_nbd_path),
        "modprobe": _tool_identity(config.modprobe_path),
        "partx": _tool_identity(config.partx_path),
        "ntfsls": _tool_identity(config.ntfsls_path),
        "ntfs3g": _tool_identity(config.ntfs_3g_path),
        "umount": _tool_identity(config.umount_path),
        "mountpoint": _tool_identity(config.mountpoint_path),
        "sync": _tool_identity(config.sync_path),
    }
    security_identity = security_source_identity()
    images_root = config.state_root / "images"
    staging_root = config.state_root / "derived-base-staging"
    receipts_root = config.state_root / "receipts"
    for path in (images_root, staging_root, receipts_root):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)

    staging = staging_root / f"r6-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    overlay_path = staging / "derived.qcow2"
    rw_mount = staging / "mount-rw"
    ro_mount = staging / "mount-ro"
    rw_closure: JsonObject = {}
    ro_closure: JsonObject = {}
    final_overlay: Path | None = None
    final_manifest: Path | None = None
    try:
        _run_checked(
            [
                str(config.qemu_img_path),
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(parent.base_image_path),
                str(overlay_path),
            ],
            timeout_seconds=60,
        )
        overlay_path.chmod(0o600)
        chain = _backing_chain(overlay_path, config)
        if Path(str(chain["backingPath"])).resolve() != parent.base_image_path.resolve():
            raise ValueError("Derived-base overlay backing path differs from the parent base")

        with _connected_windows_partition(
            overlay_path, config, read_only=False
        ) as (_device, partition, closure):
            rw_closure = closure
            with _mounted_windows_partition(
                partition, rw_mount, config, read_only=False
            ) as mount:
                _copy_resources(mount, resources, sources)
                _run_checked([str(config.sync_path), "-f", str(mount)], timeout_seconds=120)

        with _connected_windows_partition(
            overlay_path, config, read_only=True
        ) as (_device, partition, closure):
            ro_closure = closure
            with _mounted_windows_partition(
                partition, ro_mount, config, read_only=True
            ) as mount:
                verified_resources = _verify_resources(mount, resources)

        parent_image_digest_after, parent_image_bytes_after = _digest_path(parent.base_image_path)
        if (
            parent_image_digest_after != parent_image_digest_before
            or parent_image_bytes_after != parent_image_bytes
        ):
            raise ValueError("Derived-base parent image changed during sealing")
        _run_checked(
            [str(config.qemu_img_path), "check", "-q", str(overlay_path)],
            timeout_seconds=600,
        )
        overlay_digest, overlay_bytes = _digest_path(overlay_path)
        environment_identity: JsonObject = {
            "kind": "ordivon.security.windows-kvm-p1-derived-base-identity",
            "implementation": security_identity,
            "parentManifestDigest": parent_manifest_digest,
            "parentEnvironmentImageDigest": parent.environment_image_digest,
            "parentBaseImageDigest": parent.base_image_digest,
            "derivedOverlayDigest": overlay_digest,
            "baseVarsDigest": parent.base_vars_digest,
            "firmwareCodeDigest": parent.firmware_code_digest,
            "guestRunnerDigest": parent.guest_runner_digest,
            "sealedResourcesDigest": resource_digest,
            "layering": "qcow2-backing-overlay",
            "network": "no-device-inherited",
            "windowsBuild": parent.windows_build,
            "tools": tools,
        }
        environment_digest = canonical_digest(environment_identity)
        suffix = environment_digest[-16:]
        final_overlay = images_root / f"windows-p1-derived-{suffix}.qcow2"
        final_manifest = images_root / f"windows-p1-derived-{suffix}.manifest.json"
        if final_overlay.exists() or final_manifest.exists():
            raise FileExistsError("Derived Windows base output already exists")
        overlay_backing = str(parent.base_image_path.resolve())
        final_overlay.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.rename(final_overlay)
        final_overlay.chmod(0o440)
        shutil.chown(final_overlay, user="root", group=config.run_group)

        parent_manifest_value = _load_object(
            parent_manifest_path, "Windows KVM parent base manifest"
        )
        if canonical_digest(parent_manifest_value) != parent_manifest_digest:
            raise ValueError("Derived-base parent manifest changed during sealing")
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-base-image",
            "providerId": "provider:windows-kvm",
            "security": security_identity,
            "paths": {
                "baseImage": str(final_overlay),
                "baseVars": str(parent.base_vars_path),
            },
            "digests": {
                "environmentImage": environment_digest,
                "sourceIso": parent.source_iso_digest,
                "baseImage": overlay_digest,
                "baseVars": parent.base_vars_digest,
                "firmwareCode": parent.firmware_code_digest,
                "guestRunner": parent.guest_runner_digest,
            },
            "byteLengths": {
                "baseImage": overlay_bytes,
                "baseVars": parent.base_vars_path.stat().st_size,
            },
            "guest": {
                "status": "ready-derived",
                "windowsBuild": parent.windows_build,
                "networkRequired": False,
            },
            "parent": {
                "manifestPath": str(parent_manifest_path),
                "manifestDigest": parent_manifest_digest,
                "environmentImageDigest": parent.environment_image_digest,
                "baseImageDigest": parent.base_image_digest,
                "baseVarsDigest": parent.base_vars_digest,
                "backingBaseImagePath": overlay_backing,
            },
            "sealedResources": resource_values,
            "configuration": {
                "layering": "qcow2-backing-overlay",
                "networkDevicePresent": False,
                "baseVarsInherited": True,
                "resourceWriteRoot": "C:\\ProgramData\\Ordivon",
                "thirdPartyExecutionAuthorized": False,
                "nbdModuleLoadedBySealer": module_loaded,
                "rwClosure": rw_closure,
                "roClosure": ro_closure,
            },
            "materialization": {
                "identity": environment_identity,
                "identityDigest": environment_digest,
                "readOnlyVerifiedResources": verified_resources,
                "parentImageUnchanged": True,
                "parentImageByteLength": parent_image_bytes,
                "derivedAllocatedBytes": final_overlay.stat().st_blocks * 512,
                "backingChain": chain,
            },
            "build": {"completedAtMs": time.time_ns() // 1_000_000},
        }
        _replace_private_json(final_manifest, manifest)
        loaded = WindowsKvmBaseImage.load(final_manifest)
        if loaded.environment_image_digest != environment_digest:
            raise ValueError("Derived-base manifest did not reload with the sealed identity")
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-p1-derived-base-seal-receipt",
            "status": "sealed-not-accepted",
            "manifestPath": str(final_manifest),
            "manifestDigest": canonical_digest(manifest),
            "environmentImageDigest": environment_digest,
            "derivedOverlayDigest": overlay_digest,
            "parentManifestDigest": parent_manifest_digest,
            "parentEnvironmentImageDigest": parent.environment_image_digest,
            "sealedResourcesDigest": resource_digest,
            "sealedResources": resource_values,
            "parentImageUnchanged": True,
            "rwResidualClosed": rw_closure.get("blockSizeReturnedToZero") is True,
            "roResidualClosed": ro_closure.get("blockSizeReturnedToZero") is True,
            "thirdPartyExecutionAuthorized": False,
        }
        receipt_path = receipts_root / f"windows-p1-derived-{suffix}.json"
        _replace_private_json(receipt_path, receipt)
        return receipt
    except BaseException:
        if final_manifest is not None:
            final_manifest.unlink(missing_ok=True)
        if final_overlay is not None:
            final_overlay.unlink(missing_ok=True)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
