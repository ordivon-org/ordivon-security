from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import cast

from ordivon_security._canonical import (
    JsonObject,
    JsonValue,
    canonical_bytes,
    canonical_digest,
)
from ordivon_security.identity import security_source_identity

from .windows_kvm import (
    _digest_path,
    _host_cpu_identity,
    _pci_network_devices,
    _QmpClient,
    _run_checked,
    _set_owner,
    _terminate_pid,
)

_BUILD_LABEL = "ORDIVONBLD"
_CONFIG_LABEL = "ORDIVONCFG"
_UNATTEND_NAMESPACE = {"u": "urn:schemas-microsoft-com:unattend"}
_MAX_DEPLOYMENT_COMMAND_TEXT_CHARS = 259


@dataclass(frozen=True, slots=True)
class WindowsKvmBaseBuildConfig:
    state_root: Path
    source_iso_path: Path
    qemu_path: Path = Path("/usr/bin/qemu-system-x86_64")
    qemu_img_path: Path = Path("/usr/bin/qemu-img")
    swtpm_path: Path = Path("/usr/bin/swtpm")
    setpriv_path: Path = Path("/usr/bin/setpriv")
    mkfs_fat_path: Path = Path("/usr/bin/mkfs.fat")
    mcopy_path: Path = Path("/usr/bin/mcopy")
    firmware_code_path: Path = Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    firmware_vars_template_path: Path = Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")
    run_user: str = "qemu"
    run_group: str = "qemu"
    memory_mib: int = 5120
    vcpu_count: int = 4
    disk_size_gib: int = 80
    installation_timeout_seconds: int = 7200
    qmp_ready_timeout_seconds: int = 90
    boot_prompt_initial_delay_seconds: int = 1
    boot_prompt_key_interval_ms: int = 750
    boot_prompt_max_attempts: int = 16
    boot_media_read_threshold_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            min(
                self.memory_mib,
                self.vcpu_count,
                self.disk_size_gib,
                self.installation_timeout_seconds,
                self.qmp_ready_timeout_seconds,
                self.boot_prompt_initial_delay_seconds,
                self.boot_prompt_key_interval_ms,
                self.boot_prompt_max_attempts,
                self.boot_media_read_threshold_bytes,
            )
            < 1
        ):
            raise ValueError("Windows KVM build limits must be positive")
        for path in (
            self.qemu_path,
            self.qemu_img_path,
            self.swtpm_path,
            self.setpriv_path,
            self.mkfs_fat_path,
            self.mcopy_path,
        ):
            if not path.is_file() or not path.resolve().is_file():
                raise ValueError(f"Windows KVM build tool is missing or unsafe: {path}")
        for path in (
            self.source_iso_path,
            self.firmware_code_path,
            self.firmware_vars_template_path,
        ):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Windows KVM build identity file is missing or unsafe: {path}")


def _resource_path(name: str) -> Path:
    resource = files("ordivon_security").joinpath("resources", "windows_kvm", name)
    path = Path(str(resource))
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Windows KVM resource is missing or unsafe: {name}")
    return path


def _prepare_provider_layout(config: WindowsKvmBaseBuildConfig) -> dict[str, Path]:
    root = config.state_root
    paths = {
        "root": root,
        "sources": root / "sources",
        "images": root / "images",
        "build": root / "build",
        "runs": root / "runs",
        "receipts": root / "receipts",
    }
    for key, path in paths.items():
        path.mkdir(parents=True, exist_ok=True)
        if key in {"root", "sources", "images", "build", "runs"}:
            path.chmod(0o710)
            _set_owner(path, user="root", group=config.run_group)
        else:
            path.chmod(0o700)
    config.source_iso_path.chmod(0o640)
    _set_owner(config.source_iso_path, user="root", group=config.run_group)
    return paths


def _validate_unattend(unattend: str) -> None:
    try:
        root = ET.fromstring(unattend)
    except ET.ParseError as error:
        raise ValueError("Windows KVM unattend template is not valid XML") from error

    for settings in root.findall("u:settings", _UNATTEND_NAMESPACE):
        pass_name = settings.get("pass", "unknown")
        for component in settings.findall("u:component", _UNATTEND_NAMESPACE):
            if component.get("name") != "Microsoft-Windows-Deployment":
                continue
            commands = component.findall(
                ".//u:RunSynchronousCommand",
                _UNATTEND_NAMESPACE,
            )
            for command in commands:
                order = command.findtext("u:Order", namespaces=_UNATTEND_NAMESPACE) or "unknown"
                for setting_name in ("Path", "Description"):
                    value = command.findtext(
                        f"u:{setting_name}",
                        namespaces=_UNATTEND_NAMESPACE,
                    )
                    if not value:
                        raise ValueError(
                            "Windows KVM unattend deployment command "
                            f"{setting_name} is empty in pass {pass_name}, order {order}"
                        )
                    if len(value) > _MAX_DEPLOYMENT_COMMAND_TEXT_CHARS:
                        raise ValueError(
                            "Windows KVM unattend deployment command "
                            f"{setting_name} exceeds {_MAX_DEPLOYMENT_COMMAND_TEXT_CHARS} "
                            f"characters in pass {pass_name}, order {order}: {len(value)}"
                        )


def _write_private(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Private build path already exists: {path}")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o600)


def _create_fat_image(
    config: WindowsKvmBaseBuildConfig,
    path: Path,
    *,
    size_mib: int,
    label: str,
) -> None:
    with path.open("xb") as handle:
        handle.truncate(size_mib * 1024 * 1024)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o600)
    _set_owner(path, user=config.run_user, group=config.run_group)
    if not label or len(label) > 11:
        raise ValueError("FAT volume label must contain 1 to 11 characters")
    _run_checked([str(config.mkfs_fat_path), "-n", label, str(path)])


def _copy_to_fat(
    config: WindowsKvmBaseBuildConfig,
    image_path: Path,
    source_path: Path,
    destination_name: str,
) -> None:
    environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
    _run_checked(
        [
            str(config.mcopy_path),
            "-o",
            "-i",
            str(image_path),
            str(source_path),
            f"::/{destination_name}",
        ],
        timeout_seconds=30,
        environment=environment,
    )


def _start_swtpm(
    config: WindowsKvmBaseBuildConfig,
    *,
    build_path: Path,
) -> tuple[int, Path]:
    state_path = build_path / "tpm-state"
    state_path.mkdir(mode=0o700)
    _set_owner(state_path, user=config.run_user, group=config.run_group)
    socket_path = build_path / "swtpm.sock"
    pid_path = build_path / "swtpm.pid"
    log_path = build_path / "swtpm.log"
    _run_checked(
        [
            str(config.setpriv_path),
            "--reuid",
            config.run_user,
            "--regid",
            config.run_group,
            "--init-groups",
            "--",
            str(config.swtpm_path),
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={state_path}",
            "--ctrl",
            f"type=unixio,path={socket_path}",
            "--flags",
            "not-need-init",
            "--daemon",
            "--pid",
            f"file={pid_path}",
            "--log",
            f"file={log_path},level=5",
        ]
    )
    deadline = time.monotonic() + 10
    while not pid_path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Windows KVM build swtpm PID file was not created")
        time.sleep(0.1)
    return int(pid_path.read_text(encoding="utf-8").strip()), socket_path


def windows_kvm_install_arguments(
    *,
    config: WindowsKvmBaseBuildConfig,
    base_image_path: Path,
    vars_path: Path,
    source_iso_path: Path,
    config_disk_path: Path,
    result_disk_path: Path,
    qmp_path: Path,
    tpm_socket_path: Path,
) -> list[str]:
    return [
        str(config.setpriv_path),
        "--reuid",
        config.run_user,
        "--regid",
        config.run_group,
        "--init-groups",
        "--",
        str(config.qemu_path),
        "-name",
        "ordivon-windows-base-build",
        "-machine",
        "q35,accel=kvm,smm=off",
        "-cpu",
        "host",
        "-smp",
        str(config.vcpu_count),
        "-m",
        str(config.memory_mib),
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-qmp",
        f"unix:{qmp_path},server=on,wait=off",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={config.firmware_code_path}",
        "-drive",
        f"if=pflash,format=raw,file={vars_path}",
        "-chardev",
        f"socket,id=chrtpm,path={tpm_socket_path}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-crb,tpmdev=tpm0",
        "-drive",
        f"file={base_image_path},if=none,format=qcow2,cache=none,aio=threads,id=osdisk",
        "-device",
        "ide-hd,drive=osdisk,bus=ide.0",
        "-drive",
        f"file={source_iso_path},if=none,format=raw,readonly=on,id=installcd",
        "-device",
        "ide-cd,drive=installcd,bus=ide.1",
        "-device",
        "VGA",
        "-device",
        "qemu-xhci,id=xhci",
        "-device",
        "usb-kbd,bus=xhci.0",
        "-drive",
        f"file={config_disk_path},if=none,format=raw,readonly=on,id=configdisk",
        "-device",
        f"usb-storage,drive=configdisk,bus=xhci.0,removable=on,serial={_CONFIG_LABEL}",
        "-drive",
        f"file={result_disk_path},if=none,format=raw,cache=none,aio=threads,id=resultdisk",
        "-device",
        f"usb-storage,drive=resultdisk,bus=xhci.0,removable=on,serial={_BUILD_LABEL}",
        "-device",
        "virtio-rng-pci",
        "-rtc",
        "base=utc,clock=host",
        "-boot",
        "order=c,once=d,menu=off",
        "-nic",
        "none",
    ]


def _block_read_bytes(value: JsonValue, device: str) -> int:
    if not isinstance(value, list):
        return 0
    for item in value:
        if not isinstance(item, dict) or item.get("device") != device:
            continue
        stats = item.get("stats")
        if not isinstance(stats, dict):
            return 0
        read_bytes = stats.get("rd_bytes")
        return read_bytes if isinstance(read_bytes, int) and read_bytes >= 0 else 0
    return 0


def _assist_optical_boot(
    qmp: _QmpClient,
    *,
    config: WindowsKvmBaseBuildConfig,
    boot_screen_path: Path,
) -> tuple[int, int, int]:
    time.sleep(config.boot_prompt_initial_delay_seconds)
    first_key_at_ms = 0
    for attempt in range(1, config.boot_prompt_max_attempts + 1):
        qmp.execute(
            "send-key",
            {
                "keys": cast(
                    list[JsonValue],
                    [{"type": "qcode", "data": "spc"}],
                ),
                "hold-time": 80,
            },
        )
        sent_at_ms = time.time_ns() // 1_000_000
        if first_key_at_ms == 0:
            first_key_at_ms = sent_at_ms
        time.sleep(config.boot_prompt_key_interval_ms / 1000)
        block_stats = qmp.execute("query-blockstats")
        install_media_read_bytes = _block_read_bytes(block_stats, "installcd")
        if install_media_read_bytes >= config.boot_media_read_threshold_bytes:
            qmp.execute(
                "screendump",
                {"filename": str(boot_screen_path), "format": "ppm"},
            )
            return attempt, first_key_at_ms, install_media_read_bytes
    qmp.execute(
        "screendump",
        {"filename": str(boot_screen_path), "format": "ppm"},
    )
    raise RuntimeError(
        "Windows KVM optical boot prompt was not accepted within the bounded key window"
    )


def _extract_fat_file(
    config: WindowsKvmBaseBuildConfig,
    image_path: Path,
    name: str,
    destination: Path,
) -> bool:
    environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
    completed = subprocess.run(
        [str(config.mcopy_path), "-i", str(image_path), f"::/{name}", str(destination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        return False
    destination.chmod(0o600)
    return True


def _build_windows_kvm_base_impl(
    config: WindowsKvmBaseBuildConfig,
    *,
    layout: dict[str, Path],
    source_iso_digest: str,
    source_iso_bytes: int,
    build_path: Path,
) -> JsonObject:
    guest_runner_path = _resource_path("guest-runner.ps1")
    p1_observer_path = _resource_path("p1-observer.ps1")
    base_finalize_path = _resource_path("base-finalize.ps1")
    setup_complete_path = _resource_path("SetupComplete.cmd")
    install_bootstrap_path = _resource_path("install-bootstrap.ps1")
    unattend_template_path = _resource_path("Autounattend.xml.in")
    guest_runner_digest, guest_runner_bytes = _digest_path(guest_runner_path)
    p1_observer_digest, p1_observer_bytes = _digest_path(p1_observer_path)
    base_finalize_digest, base_finalize_bytes = _digest_path(base_finalize_path)
    setup_complete_digest, setup_complete_bytes = _digest_path(setup_complete_path)
    install_bootstrap_digest, install_bootstrap_bytes = _digest_path(install_bootstrap_path)
    unattend_template_digest, unattend_template_bytes = _digest_path(unattend_template_path)
    firmware_digest, _ = _digest_path(config.firmware_code_path)
    if build_path.exists():
        raise FileExistsError(f"Windows KVM base build path already exists: {build_path}")
    build_path.mkdir(mode=0o700)
    _set_owner(build_path, user=config.run_user, group=config.run_group)

    base_image_path = build_path / "windows-11-enterprise-eval-25h2-base.qcow2"
    vars_path = build_path / "OVMF_VARS.4m.fd"
    config_disk_path = build_path / "build-config.img"
    result_disk_path = build_path / "build-result.img"
    qmp_path = build_path / "qmp.sock"
    qemu_stdout_path = build_path / "qemu.stdout.log"
    qemu_stderr_path = build_path / "qemu.stderr.log"
    boot_screen_path = build_path / "boot-screen.ppm"
    password = secrets.token_urlsafe(32)
    unattend = unattend_template_path.read_text(encoding="utf-8").replace("@@PASSWORD@@", password)
    _validate_unattend(unattend)
    unattend_path = build_path / "Autounattend.xml"
    _write_private(unattend_path, unattend.encode("utf-8"))
    password = ""

    _run_checked(
        [
            str(config.qemu_img_path),
            "create",
            "-q",
            "-f",
            "qcow2",
            str(base_image_path),
            f"{config.disk_size_gib}G",
        ]
    )
    shutil.copyfile(config.firmware_vars_template_path, vars_path)
    for path in (base_image_path, vars_path):
        path.chmod(0o600)
        _set_owner(path, user=config.run_user, group=config.run_group)
    _create_fat_image(config, config_disk_path, size_mib=16, label=_CONFIG_LABEL)
    _create_fat_image(config, result_disk_path, size_mib=16, label=_BUILD_LABEL)
    for source_path, destination_name in (
        (unattend_path, "Autounattend.xml"),
        (install_bootstrap_path, "install-bootstrap.ps1"),
        (guest_runner_path, "guest-runner.ps1"),
        (p1_observer_path, "p1-observer.ps1"),
        (base_finalize_path, "base-finalize.ps1"),
        (setup_complete_path, "SetupComplete.cmd"),
    ):
        _copy_to_fat(config, config_disk_path, source_path, destination_name)
    swtpm_pid, tpm_socket_path = _start_swtpm(config, build_path=build_path)
    arguments = windows_kvm_install_arguments(
        config=config,
        base_image_path=base_image_path,
        vars_path=vars_path,
        source_iso_path=config.source_iso_path,
        config_disk_path=config_disk_path,
        result_disk_path=result_disk_path,
        qmp_path=qmp_path,
        tpm_socket_path=tpm_socket_path,
    )
    command_path = build_path / "qemu-command.json"
    _write_private(
        command_path,
        canonical_bytes({"arguments": cast(list[JsonValue], arguments)}) + b"\n",
    )
    started_at_ms = time.time_ns() // 1_000_000
    qemu_pid = 0
    network_device_count = -1
    qemu_status: JsonObject = {}
    qmp_pci: JsonValue = []
    boot_prompt_key_attempts = 0
    boot_prompt_key_sent_at_ms = 0
    boot_media_read_bytes = 0
    try:
        with (
            qemu_stdout_path.open("xb") as stdout_handle,
            qemu_stderr_path.open("xb") as stderr_handle,
        ):
            process = subprocess.Popen(arguments, stdout=stdout_handle, stderr=stderr_handle)
            qemu_pid = process.pid
            with _QmpClient(qmp_path, timeout_seconds=config.qmp_ready_timeout_seconds) as qmp:
                status_value = qmp.execute("query-status")
                if isinstance(status_value, dict):
                    qemu_status = status_value
                qmp_pci = qmp.execute("query-pci")
                network_devices = _pci_network_devices(qmp_pci)
                network_device_count = len(network_devices)
                if network_devices:
                    qmp.execute("quit")
                    raise RuntimeError("Windows KVM base build exposed a network device")
                (
                    boot_prompt_key_attempts,
                    boot_prompt_key_sent_at_ms,
                    boot_media_read_bytes,
                ) = _assist_optical_boot(
                    qmp,
                    config=config,
                    boot_screen_path=boot_screen_path,
                )
            try:
                process.wait(timeout=config.installation_timeout_seconds)
            except subprocess.TimeoutExpired as error:
                try:
                    with _QmpClient(qmp_path, timeout_seconds=5) as qmp:
                        qmp.execute("quit")
                except Exception:
                    process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                raise TimeoutError("Windows KVM base installation exceeded its bound") from error
            if process.returncode != 0:
                raise RuntimeError(f"Windows KVM base QEMU exited with {process.returncode}")
    finally:
        if qemu_pid:
            _terminate_pid(qemu_pid, expected_fragment="qemu-system-x86_64")
        _terminate_pid(swtpm_pid, expected_fragment="swtpm")

    base_ready_path = build_path / "base-ready.json"
    if not _extract_fat_file(config, result_disk_path, "base-ready.json", base_ready_path):
        raise ValueError("Windows KVM guest did not emit base-ready evidence")
    base_ready = json.loads(base_ready_path.read_text(encoding="utf-8"))
    if not isinstance(base_ready, dict) or base_ready.get("status") != "ready":
        raise ValueError("Windows KVM base-ready evidence is invalid")
    windows_build = base_ready.get("windowsBuild")
    if not isinstance(windows_build, str) or not windows_build:
        raise ValueError("Windows KVM base-ready evidence lacks Windows build identity")
    _run_checked(
        [str(config.qemu_img_path), "check", "-q", str(base_image_path)], timeout_seconds=600
    )
    base_image_digest, base_image_bytes = _digest_path(base_image_path)
    base_vars_digest, base_vars_bytes = _digest_path(vars_path)
    environment_image: JsonObject = {
        "sourceIsoDigest": source_iso_digest,
        "baseImageDigest": base_image_digest,
        "baseVarsDigest": base_vars_digest,
        "firmwareCodeDigest": firmware_digest,
        "guestRunnerDigest": guest_runner_digest,
        "p1ObserverDigest": p1_observer_digest,
        "baseFinalizeDigest": base_finalize_digest,
        "setupCompleteDigest": setup_complete_digest,
        "installBootstrapDigest": install_bootstrap_digest,
        "unattendTemplateDigest": unattend_template_digest,
        "sourceMediaMode": "original-udf-read-only",
        "configurationMedia": "usb-fat-read-only-removable",
        "resultMedia": "usb-fat-writable-removable",
        "configurationDiskLabel": _CONFIG_LABEL,
        "resultDiskLabel": _BUILD_LABEL,
        "secureBoot": False,
        "smm": False,
        "compatibilityOverrides": ["BypassSecureBootCheck"],
        "bootPromptAssist": "bounded-qmp-send-key:spc",
        "windowsBuild": windows_build,
        "machine": "q35,accel=kvm,smm=off",
        "cpu": "host",
        "display": "VGA",
        "network": "no-device",
        "tpm": "swtpm-2.0",
        "privilegeDrop": "setpriv",
    }
    environment_image_digest = canonical_digest(environment_image)
    final_base_path = (
        layout["images"] / f"windows-11-enterprise-eval-25h2-{environment_image_digest[-16:]}.qcow2"
    )
    final_vars_path = (
        layout["images"]
        / f"windows-11-enterprise-eval-25h2-{environment_image_digest[-16:]}.vars.fd"
    )
    manifest_path = (
        layout["images"]
        / f"windows-11-enterprise-eval-25h2-{environment_image_digest[-16:]}.manifest.json"
    )
    for path in (final_base_path, final_vars_path, manifest_path):
        if path.exists():
            raise FileExistsError(f"Windows KVM sealed image path already exists: {path}")
    os.rename(base_image_path, final_base_path)
    os.rename(vars_path, final_vars_path)
    for path in (final_base_path, final_vars_path):
        _set_owner(path, user="root", group=config.run_group)
        path.chmod(0o440)
    completed_at_ms = time.time_ns() // 1_000_000
    manifest: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-kvm-base-image",
        "providerId": "provider:windows-kvm",
        "security": security_source_identity(),
        "paths": {
            "baseImage": str(final_base_path),
            "baseVars": str(final_vars_path),
        },
        "digests": {
            "environmentImage": environment_image_digest,
            "sourceIso": source_iso_digest,
            "baseImage": base_image_digest,
            "baseVars": base_vars_digest,
            "firmwareCode": firmware_digest,
            "guestRunner": guest_runner_digest,
            "p1Observer": p1_observer_digest,
            "baseFinalize": base_finalize_digest,
            "setupComplete": setup_complete_digest,
            "installBootstrap": install_bootstrap_digest,
            "unattendTemplate": unattend_template_digest,
        },
        "byteLengths": {
            "sourceIso": source_iso_bytes,
            "baseImage": base_image_bytes,
            "baseVars": base_vars_bytes,
            "guestRunner": guest_runner_bytes,
            "p1Observer": p1_observer_bytes,
            "baseFinalize": base_finalize_bytes,
            "setupComplete": setup_complete_bytes,
            "installBootstrap": install_bootstrap_bytes,
            "unattendTemplate": unattend_template_bytes,
        },
        "guest": base_ready,
        "buildHostCpu": _host_cpu_identity(),
        "configuration": {
            "memoryMiB": config.memory_mib,
            "vcpus": config.vcpu_count,
            "diskSizeGiB": config.disk_size_gib,
            "networkDevicePresent": False,
            "networkDeviceCount": network_device_count,
            "qmpInitialStatus": qemu_status,
            "runUser": config.run_user,
            "runGroup": config.run_group,
            "privilegeDrop": "setpriv",
            "display": "VGA",
            "sourceMediaMode": "original-udf-read-only",
            "configurationDiskLabel": _CONFIG_LABEL,
            "resultDiskLabel": _BUILD_LABEL,
            "configurationDiskReadOnly": True,
            "configurationDiskRemovable": True,
            "resultDiskReadOnly": False,
            "resultDiskRemovable": True,
            "secureBoot": False,
            "smm": False,
            "compatibilityOverrides": ["BypassSecureBootCheck"],
            "bootPromptAssist": "bounded-qmp-send-key:spc",
            "bootPromptInitialDelaySeconds": config.boot_prompt_initial_delay_seconds,
            "bootPromptKeyIntervalMs": config.boot_prompt_key_interval_ms,
            "bootPromptMaxAttempts": config.boot_prompt_max_attempts,
            "bootPromptKeyAttempts": boot_prompt_key_attempts,
            "bootPromptKeySentAtMs": boot_prompt_key_sent_at_ms,
            "bootMediaReadThresholdBytes": config.boot_media_read_threshold_bytes,
            "bootMediaReadBytesAtAcceptance": boot_media_read_bytes,
        },
        "build": {
            "startedAtMs": started_at_ms,
            "completedAtMs": completed_at_ms,
        },
    }
    _write_private(manifest_path, canonical_bytes(manifest) + b"\n")
    receipt_path = layout["receipts"] / f"windows-kvm-base-{environment_image_digest[-16:]}.json"
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.windows-kvm-base-build-receipt",
        "manifestPath": str(manifest_path),
        "manifestDigest": canonical_digest(manifest),
        "environmentImageDigest": environment_image_digest,
        "baseImageDigest": base_image_digest,
        "baseVarsDigest": base_vars_digest,
        "sourceIsoDigest": source_iso_digest,
        "windowsBuild": windows_build,
        "networkDevicePresent": False,
        "sourceMediaMode": "original-udf-read-only",
        "configurationDiskLabel": _CONFIG_LABEL,
        "resultDiskLabel": _BUILD_LABEL,
        "configurationDiskReadOnly": True,
        "configurationDiskRemovable": True,
        "secureBoot": False,
        "smm": False,
        "compatibilityOverrides": ["BypassSecureBootCheck"],
        "bootPromptAssist": "bounded-qmp-send-key:spc",
        "bootPromptKeyAttempts": boot_prompt_key_attempts,
        "bootPromptKeySentAtMs": boot_prompt_key_sent_at_ms,
        "bootMediaReadBytesAtAcceptance": boot_media_read_bytes,
        "completedAtMs": completed_at_ms,
    }
    _write_private(receipt_path, canonical_bytes(receipt) + b"\n")
    qmp_topology_path = build_path / "qmp-topology.json"
    _write_private(
        qmp_topology_path,
        canonical_bytes(
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-build-qmp-topology",
                "status": qemu_status,
                "pci": qmp_pci,
                "networkDevicePresent": network_device_count > 0,
                "bootPromptAssist": "bounded-qmp-send-key:spc",
                "bootPromptKeyAttempts": boot_prompt_key_attempts,
                "bootPromptKeySentAtMs": boot_prompt_key_sent_at_ms,
                "bootMediaReadBytesAtAcceptance": boot_media_read_bytes,
            }
        )
        + b"\n",
    )
    evidence_path = (
        layout["receipts"] / f"windows-kvm-base-{environment_image_digest[-16:]}-evidence"
    )
    evidence_path.mkdir(mode=0o700)
    if boot_screen_path.is_file():
        boot_screen_path.chmod(0o600)
    for path in (
        base_ready_path,
        qemu_stdout_path,
        qemu_stderr_path,
        command_path,
        qmp_topology_path,
        boot_screen_path,
        build_path / "swtpm.log",
    ):
        if path.is_file():
            destination = evidence_path / path.name
            shutil.copyfile(path, destination)
            destination.chmod(0o600)
    shutil.rmtree(build_path, ignore_errors=True)
    return receipt


def build_windows_kvm_base(config: WindowsKvmBaseBuildConfig) -> JsonObject:
    layout = _prepare_provider_layout(config)
    source_iso_digest, source_iso_bytes = _digest_path(config.source_iso_path)
    build_token = source_iso_digest.removeprefix("sha256:")[:16]
    build_path = layout["build"] / f"windows-25h2-{build_token}"
    try:
        return _build_windows_kvm_base_impl(
            config,
            layout=layout,
            source_iso_digest=source_iso_digest,
            source_iso_bytes=source_iso_bytes,
            build_path=build_path,
        )
    except BaseException as error:
        shutil.rmtree(build_path, ignore_errors=True)
        build_path_removed = not build_path.exists()
        recorded_at_ns = time.time_ns()
        failure_receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-base-build-failure",
            "security": security_source_identity(),
            "sourceIsoDigest": source_iso_digest,
            "buildPath": str(build_path),
            "errorType": type(error).__name__,
            "errorMessage": str(error),
            "buildPathRemoved": build_path_removed,
            "recordedAtMs": recorded_at_ns // 1_000_000,
        }
        receipt_path = (
            layout["receipts"] / f"windows-kvm-base-failure-{build_token}-{recorded_at_ns}.json"
        )
        _write_private(receipt_path, canonical_bytes(failure_receipt) + b"\n")
        if not build_path_removed:
            raise RuntimeError(
                f"Windows KVM build failed and temporary state remains: {build_path}"
            ) from error
        raise
