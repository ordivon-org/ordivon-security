from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ordivon_security._canonical import (
    JsonObject,
    JsonValue,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security.identity import security_source_identity

from .backend import (
    EvaluationArtifact,
    EvaluationExecution,
    EvaluationInstance,
    GuardianRecord,
    ObserverRecord,
    ResidualClosureReceipt,
)
from .models import EvaluationSpec, SampleIdentity

_CHUNK_BYTES = 4 * 1024 * 1024
_RUN_ACTION = "execute-benign-fixture"
_RUN_LABEL = "ORDIVON_RUN"
_NETWORK_PCI_CLASS_MIN = 0x0200
_NETWORK_PCI_CLASS_MAX = 0x02FF


def _digest_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_length = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
            byte_length += len(chunk)
    return "sha256:" + digest.hexdigest(), byte_length


def _load_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_private_json(path: Path, value: JsonObject) -> None:
    validate_json(value)
    if path.is_symlink():
        raise ValueError(f"Private JSON path must not be a symlink: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _write_private_json(path: Path, value: JsonObject) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Private JSON path already exists: {path}")
    _replace_private_json(path, value)


def _host_cpu_identity() -> JsonObject:
    fields: dict[str, str] = {}
    for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in {
            "vendor_id",
            "cpu family",
            "model",
            "model name",
            "stepping",
            "microcode",
            "flags",
        }:
            fields[key] = value
    if "model name" not in fields or "flags" not in fields:
        raise ValueError("Host CPU identity is incomplete")
    identity: JsonObject = {
        "vendorId": fields.get("vendor_id"),
        "family": fields.get("cpu family"),
        "model": fields.get("model"),
        "modelName": fields["model name"],
        "stepping": fields.get("stepping"),
        "microcode": fields.get("microcode"),
        "flags": cast(list[JsonValue], sorted(set(fields["flags"].split()))),
    }
    validate_json(identity)
    return identity


def _version_line(executable: Path, *args: str) -> str:
    completed = subprocess.run(
        [str(executable), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    line = completed.stdout.splitlines()[0].strip()
    if not line:
        raise ValueError(f"Tool returned no version identity: {executable}")
    return line


def _run_checked(
    arguments: list[str],
    *,
    timeout_seconds: int = 120,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
        env=environment,
    )


def _process_identity(pid: int) -> tuple[str, int] | None:
    if pid < 1:
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    _, separator, suffix = raw.rpartition(")")
    if not separator:
        return None
    fields = suffix.strip().split()
    if len(fields) <= 19:
        return None
    try:
        start_time = int(fields[19])
    except ValueError:
        return None
    return fields[0], start_time


def _process_state(pid: int) -> str | None:
    identity = _process_identity(pid)
    return identity[0] if identity is not None else None


def _process_start_time(pid: int) -> int | None:
    identity = _process_identity(pid)
    return identity[1] if identity is not None else None


def _reap_child(pid: int) -> None:
    with suppress(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def _is_process_alive(pid: int) -> bool:
    if pid < 1:
        return False
    state = _process_state(pid)
    if state == "Z":
        _reap_child(pid)
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_pid(
    pid: int,
    *,
    expected_fragment: str,
    expected_start_time: int | None = None,
) -> bool:
    identity = _process_identity(pid)
    if identity is None:
        return True
    state, start_time = identity
    if expected_start_time is not None and start_time != expected_start_time:
        return False
    if state == "Z":
        _reap_child(pid)
        return True

    command_path = Path(f"/proc/{pid}/cmdline")
    try:
        command = command_path.read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace")
    except OSError:
        command = ""
    if expected_start_time is None and expected_fragment not in command:
        return False
    if expected_start_time is not None and command and expected_fragment not in command:
        return False

    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        identity = _process_identity(pid)
        if identity is None:
            return True
        state, current_start_time = identity
        if current_start_time != start_time:
            return False
        if state == "Z":
            _reap_child(pid)
            return True
        time.sleep(0.1)

    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    for _ in range(50):
        identity = _process_identity(pid)
        if identity is None:
            return True
        state, current_start_time = identity
        if current_start_time != start_time:
            return False
        if state == "Z":
            _reap_child(pid)
            return True
        time.sleep(0.1)
    return _process_identity(pid) is None


def _set_owner(path: Path, *, user: str, group: str) -> None:
    shutil.chown(path, user=user, group=group)


def _artifact(path: Path, *, artifact_id: str, kind: str, media_type: str) -> EvaluationArtifact:
    digest, byte_length = _digest_path(path)
    return EvaluationArtifact(
        artifact_id=artifact_id,
        kind=kind,
        digest=digest,
        byte_length=byte_length,
        media_type=media_type,
        logical_name=path.name,
        source_path=path,
    )


@dataclass(frozen=True, slots=True)
class WindowsKvmBaseImage:
    manifest_path: Path
    base_image_path: Path
    base_vars_path: Path
    environment_image_digest: str
    source_iso_digest: str
    base_image_digest: str
    base_vars_digest: str
    firmware_code_digest: str
    guest_runner_digest: str
    windows_build: str

    @classmethod
    def load(cls, manifest_path: Path) -> WindowsKvmBaseImage:
        manifest = _load_object(manifest_path, "Windows KVM base manifest")
        if (
            manifest.get("schemaVersion") != 1
            or manifest.get("kind") != "ordivon.security.windows-kvm-base-image"
        ):
            raise ValueError("Windows KVM base manifest schema is unsupported")
        paths = manifest.get("paths")
        digests = manifest.get("digests")
        guest = manifest.get("guest")
        if (
            not isinstance(paths, dict)
            or not isinstance(digests, dict)
            or not isinstance(guest, dict)
        ):
            raise ValueError("Windows KVM base manifest sections are missing")
        image_value = paths.get("baseImage")
        vars_value = paths.get("baseVars")
        required_digests = (
            "environmentImage",
            "sourceIso",
            "baseImage",
            "baseVars",
            "firmwareCode",
            "guestRunner",
        )
        if not isinstance(image_value, str) or not isinstance(vars_value, str):
            raise ValueError("Windows KVM base paths are invalid")
        for key in required_digests:
            value = digests.get(key)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                raise ValueError(f"Windows KVM base digest is invalid: {key}")
        windows_build = guest.get("windowsBuild")
        if not isinstance(windows_build, str) or not windows_build:
            raise ValueError("Windows KVM guest build identity is missing")
        image_path = Path(image_value)
        vars_path = Path(vars_value)
        for path in (manifest_path, image_path, vars_path):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Windows KVM base file is missing or unsafe: {path}")
        actual_image_digest, _ = _digest_path(image_path)
        actual_vars_digest, _ = _digest_path(vars_path)
        if actual_image_digest != digests["baseImage"]:
            raise ValueError("Windows KVM base image digest differs")
        if actual_vars_digest != digests["baseVars"]:
            raise ValueError("Windows KVM base UEFI variables digest differs")
        return cls(
            manifest_path=manifest_path,
            base_image_path=image_path,
            base_vars_path=vars_path,
            environment_image_digest=cast(str, digests["environmentImage"]),
            source_iso_digest=cast(str, digests["sourceIso"]),
            base_image_digest=digests["baseImage"],
            base_vars_digest=digests["baseVars"],
            firmware_code_digest=cast(str, digests["firmwareCode"]),
            guest_runner_digest=cast(str, digests["guestRunner"]),
            windows_build=windows_build,
        )


@dataclass(frozen=True, slots=True)
class WindowsKvmProviderConfig:
    state_root: Path
    base_manifest_path: Path
    qemu_path: Path = Path("/usr/bin/qemu-system-x86_64")
    qemu_img_path: Path = Path("/usr/bin/qemu-img")
    swtpm_path: Path = Path("/usr/bin/swtpm")
    setpriv_path: Path = Path("/usr/bin/setpriv")
    mkfs_fat_path: Path = Path("/usr/bin/mkfs.fat")
    mcopy_path: Path = Path("/usr/bin/mcopy")
    mdir_path: Path = Path("/usr/bin/mdir")
    firmware_code_path: Path = Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    run_user: str = "qemu"
    run_group: str = "qemu"
    admitted_sample_digest: str = ""
    fixture_attestation_digest: str = ""
    memory_mib: int = 5120
    vcpu_count: int = 4
    qmp_ready_timeout_seconds: int = 60
    shutdown_grace_seconds: int = 15
    run_disk_mib: int = 128

    def __post_init__(self) -> None:
        for label, value in (
            ("admitted Sample", self.admitted_sample_digest),
            ("fixture attestation", self.fixture_attestation_digest),
        ):
            if len(value) != 71 or not value.startswith("sha256:"):
                raise ValueError(f"Windows KVM {label} digest is invalid")
            try:
                bytes.fromhex(value.removeprefix("sha256:"))
            except ValueError as error:
                raise ValueError(f"Windows KVM {label} digest is invalid") from error
        if (
            min(
                self.memory_mib,
                self.vcpu_count,
                self.qmp_ready_timeout_seconds,
                self.shutdown_grace_seconds,
                self.run_disk_mib,
            )
            < 1
        ):
            raise ValueError("Windows KVM provider limits must be positive")
        for path in (
            self.qemu_path,
            self.qemu_img_path,
            self.swtpm_path,
            self.setpriv_path,
            self.mkfs_fat_path,
            self.mcopy_path,
            self.mdir_path,
        ):
            if not path.is_file() or not path.resolve().is_file():
                raise ValueError(f"Windows KVM provider tool is missing or unsafe: {path}")
        for path in (self.firmware_code_path, self.base_manifest_path):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Windows KVM provider identity file is missing or unsafe: {path}")


class _QmpClient:
    def __init__(self, path: Path, *, timeout_seconds: int) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None
        self._reader: Any = None
        self._writer: Any = None

    def __enter__(self) -> _QmpClient:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            connection: socket.socket | None = None
            try:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(5)
                connection.connect(str(self.path))
                self._socket = connection
                self._reader = connection.makefile("r", encoding="utf-8", newline="\n")
                self._writer = connection.makefile("w", encoding="utf-8", newline="\n")
                greeting = self._read_message()
                if "QMP" not in greeting:
                    raise ValueError("QMP greeting is missing")
                self.execute("qmp_capabilities")
                return self
            except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as error:
                if connection is not None:
                    connection.close()
                self._socket = None
                self._reader = None
                self._writer = None
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"QMP socket did not become ready: {self.path}") from error
                time.sleep(0.25)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._reader is not None:
            self._reader.close()
        if self._writer is not None:
            self._writer.close()
        if self._socket is not None:
            self._socket.close()

    def _read_message(self) -> JsonObject:
        line = self._reader.readline()
        if not line:
            raise ConnectionError("QMP connection closed")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("QMP message must be an object")
        return cast(JsonObject, value)

    def execute(self, command: str, arguments: JsonObject | None = None) -> JsonValue:
        request: JsonObject = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self._writer.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._writer.flush()
        while True:
            message = self._read_message()
            if "event" in message:
                continue
            if "error" in message:
                raise RuntimeError(f"QMP command failed: {message['error']}")
            if "return" in message:
                return message["return"]


def _pci_network_devices(value: JsonValue) -> list[JsonObject]:
    found: list[JsonObject] = []
    if isinstance(value, list):
        for item in value:
            found.extend(_pci_network_devices(item))
    elif isinstance(value, dict):
        class_info = value.get("class_info")
        if isinstance(class_info, dict):
            class_value = class_info.get("class")
            if (
                isinstance(class_value, int)
                and _NETWORK_PCI_CLASS_MIN <= class_value <= _NETWORK_PCI_CLASS_MAX
            ):
                found.append(value)
        for item in value.values():
            found.extend(_pci_network_devices(item))
    return found


def windows_kvm_qemu_arguments(
    *,
    config: WindowsKvmProviderConfig,
    overlay_path: Path,
    vars_path: Path,
    run_disk_path: Path,
    qmp_path: Path,
    tpm_socket_path: Path,
    name: str,
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
        name,
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
        f"file={overlay_path},if=none,format=qcow2,cache=none,aio=threads,id=osdisk",
        "-device",
        "ide-hd,drive=osdisk,bus=ide.0",
        "-device",
        "VGA",
        "-device",
        "qemu-xhci,id=xhci",
        "-drive",
        f"file={run_disk_path},if=none,format=raw,cache=none,aio=threads,id=rundisk",
        "-device",
        f"usb-storage,drive=rundisk,bus=xhci.0,removable=on,serial={_RUN_LABEL}",
        "-device",
        "virtio-rng-pci",
        "-rtc",
        "base=utc,clock=host",
        "-boot",
        "order=c,menu=off",
        "-nic",
        "none",
    ]


class WindowsKvmEvaluationBackend:
    """Disposable, deny-all Windows VM backend admitted only for the benign fixture gate."""

    backend_id = "backend:windows-kvm-disposable"
    provider_id = "provider:windows-kvm"

    def __init__(self, config: WindowsKvmProviderConfig) -> None:
        self.config = config
        self.base = WindowsKvmBaseImage.load(config.base_manifest_path)
        self.runs_root = config.state_root / "runs"
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.runs_root.chmod(0o710)
        _set_owner(self.runs_root, user="root", group=config.run_group)
        self.ledgers_root = config.state_root / "run-ledgers"
        self.ledgers_root.mkdir(parents=True, exist_ok=True)
        self.ledgers_root.chmod(0o700)
        _set_owner(self.ledgers_root, user="root", group="root")

    def _persist_run_state(self, instance: EvaluationInstance, phase: str) -> None:
        state_path_value = instance.state.get("runStatePath")
        if not isinstance(state_path_value, str) or not state_path_value:
            return
        state_path = Path(state_path_value)
        run_path_value = instance.state.get("runPath")
        if not isinstance(run_path_value, str):
            raise ValueError("Windows KVM Run path is missing from the state ledger")
        run_path = Path(run_path_value)
        expected_name = run_path.name + ".json"
        if state_path.parent != self.ledgers_root or state_path.name != expected_name:
            raise ValueError("Windows KVM Run state path differs from the root-owned ledger path")
        instance.state["phase"] = phase
        ledger: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "providerId": self.provider_id,
            "instanceId": instance.instance_id,
            "generation": instance.generation,
            "runId": instance.instance_id.replace("evaluation-instance:", "evaluation-run:"),
            "phase": phase,
            "updatedAtNs": time.time_ns(),
            "security": cast(JsonObject, instance.state["security"]),
            "baseEnvironmentImageDigest": self.base.environment_image_digest,
            "evaluationSpecDigest": instance.state["evaluationSpecDigest"],
            "ownerPid": instance.state["ownerPid"],
            "ownerStartTime": instance.state["ownerStartTime"],
            "runPath": instance.state["runPath"],
            "overlayPath": instance.state["overlayPath"],
            "varsPath": instance.state["varsPath"],
            "runDiskPath": instance.state["runDiskPath"],
            "qmpPath": instance.state["qmpPath"],
            "tpmSocketPath": instance.state["tpmSocketPath"],
            "tpmStatePath": instance.state["tpmStatePath"],
            "qemuPid": instance.state.get("qemuPid", 0),
            "qemuStartTime": instance.state.get("qemuStartTime"),
            "swtpmPid": instance.state.get("swtpmPid", 0),
            "swtpmStartTime": instance.state.get("swtpmStartTime"),
            "staged": instance.state.get("staged", False),
            "qemuExited": instance.state.get("qemuExited", False),
            "qemuExitCode": instance.state.get("qemuExitCode"),
            "networkDevicePresent": instance.state.get("networkDevicePresent"),
        }
        _replace_private_json(state_path, ledger)

    @property
    def execution_identity(self) -> JsonObject:
        qemu_digest, _ = _digest_path(self.config.qemu_path)
        swtpm_digest, _ = _digest_path(self.config.swtpm_path)
        firmware_digest, _ = _digest_path(self.config.firmware_code_path)
        if firmware_digest != self.base.firmware_code_digest:
            raise ValueError("Windows KVM firmware differs from the sealed base identity")
        configuration: JsonObject = {
            "memoryMiB": self.config.memory_mib,
            "vcpus": self.config.vcpu_count,
            "machine": "q35,accel=kvm,smm=off",
            "cpu": "host",
            "display": "VGA",
            "secureBoot": False,
            "smm": False,
            "network": "no-device",
            "systemDisk": "qcow2-overlay",
            "runDisk": "usb-fat-writable-removable",
            "runDiskLabel": _RUN_LABEL,
            "runDiskReadOnly": False,
            "runDiskRemovable": True,
            "tpm": "disposable-swtpm-2.0",
            "runUser": self.config.run_user,
            "runGroup": self.config.run_group,
            "privilegeDrop": "setpriv",
            "admittedSampleDigest": self.config.admitted_sample_digest,
            "fixtureAttestationDigest": self.config.fixture_attestation_digest,
        }
        return {
            "kind": "ordivon.security.evaluation-backend",
            "backendId": self.backend_id,
            "providerId": self.provider_id,
            "implementationRevision": "1",
            "configurationDigest": canonical_digest(configuration),
            "configuration": configuration,
            "environmentImageDigest": self.base.environment_image_digest,
            "baseImageDigest": self.base.base_image_digest,
            "baseVarsDigest": self.base.base_vars_digest,
            "sourceIsoDigest": self.base.source_iso_digest,
            "guestRunnerDigest": self.base.guest_runner_digest,
            "windowsBuild": self.base.windows_build,
            "hostCpu": _host_cpu_identity(),
            "qemu": {
                "path": str(self.config.qemu_path),
                "digest": qemu_digest,
                "version": _version_line(self.config.qemu_path, "--version"),
            },
            "swtpm": {
                "path": str(self.config.swtpm_path),
                "digest": swtpm_digest,
                "version": _version_line(self.config.swtpm_path, "--version"),
            },
            "firmwareCode": {
                "path": str(self.config.firmware_code_path),
                "digest": firmware_digest,
            },
            "networkDevicePresent": False,
            "sampleExecution": True,
            "admittedAction": _RUN_ACTION,
        }

    def _validate_spec(self, spec: EvaluationSpec) -> None:
        if spec.environment.provider_id != self.provider_id:
            raise ValueError("Evaluation environment Provider differs from Windows KVM")
        if spec.guardian_policy.network_mode != "deny-all" or spec.authority.allow_network:
            raise ValueError("Windows KVM benign gate requires deny-all network Authority")
        if spec.requested_actions != (_RUN_ACTION,):
            raise ValueError("Windows KVM P0 admits only the benign fixture action")
        if self.config.memory_mib > spec.guardian_policy.max_memory_mib:
            raise ValueError("Windows KVM memory exceeds the Guardian bound")
        if spec.guardian_policy.max_processes < 2:
            raise ValueError("Windows KVM benign fixture requires two admitted processes")
        if spec.sample.media_type != "application/vnd.microsoft.portable-executable":
            raise ValueError("Windows KVM benign gate requires a PE executable Sample")
        if spec.sample.sha256 != self.config.admitted_sample_digest:
            raise ValueError("Windows KVM Sample differs from the admitted benign fixture bytes")
        if spec.metadata.get("fixtureId") != "ordivon-benign-v1":
            raise ValueError("Windows KVM P0 requires the exact benign fixture identity")
        if spec.metadata.get("fixtureCompilationDigest") != self.config.fixture_attestation_digest:
            raise ValueError("Windows KVM fixture attestation differs from Provider identity")
        if spec.environment.image_digest != self.base.environment_image_digest:
            raise ValueError("Evaluation environment does not bind the sealed Windows image")
        if spec.environment.configuration_digest != canonical_digest(self.execution_identity):
            raise ValueError("Evaluation environment does not bind the Windows KVM configuration")

    def create(self, run_id: str, spec: EvaluationSpec) -> EvaluationInstance:
        self._validate_spec(spec)
        token = run_id.removeprefix("evaluation-run:")
        run_path = self.runs_root / token
        if run_path.exists():
            raise FileExistsError(f"Windows KVM Run already exists: {run_path}")
        run_path.mkdir(mode=0o700)
        _set_owner(run_path, user=self.config.run_user, group=self.config.run_group)
        overlay_path = run_path / "system-overlay.qcow2"
        vars_path = run_path / "OVMF_VARS.4m.fd"
        run_disk_path = run_path / "ordivon-run.img"
        qmp_path = run_path / "qmp.sock"
        tpm_socket_path = run_path / "swtpm.sock"
        tpm_state_path = run_path / "tpm-state"
        tpm_state_path.mkdir(mode=0o700)
        _set_owner(tpm_state_path, user=self.config.run_user, group=self.config.run_group)
        _run_checked(
            [
                str(self.config.qemu_img_path),
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(self.base.base_image_path),
                str(overlay_path),
            ]
        )
        shutil.copyfile(self.base.base_vars_path, vars_path)
        for path in (overlay_path, vars_path):
            path.chmod(0o600)
            _set_owner(path, user=self.config.run_user, group=self.config.run_group)
        owner_start_time = _process_start_time(os.getpid())
        if owner_start_time is None:
            shutil.rmtree(run_path, ignore_errors=True)
            raise RuntimeError("Windows KVM owner process identity was not observable")
        state: JsonObject = {
            "runPath": str(run_path),
            "runStatePath": str(self.ledgers_root / f"{token}.json"),
            "overlayPath": str(overlay_path),
            "varsPath": str(vars_path),
            "runDiskPath": str(run_disk_path),
            "qmpPath": str(qmp_path),
            "tpmSocketPath": str(tpm_socket_path),
            "tpmStatePath": str(tpm_state_path),
            "qemuPid": 0,
            "swtpmPid": 0,
            "ownerPid": os.getpid(),
            "ownerStartTime": owner_start_time,
            "security": security_source_identity(),
            "evaluationSpecDigest": spec.digest,
            "staged": False,
            "qemuExited": False,
            "fixtureRuntimeMs": min(120_000, spec.guardian_policy.max_runtime_ms),
        }
        instance = EvaluationInstance(
            instance_id=f"evaluation-instance:{token}",
            generation=f"windows-kvm:{self.base.environment_image_digest[-16:]}",
            state=state,
        )
        self._persist_run_state(instance, "created")
        return instance

    def stage(
        self,
        instance: EvaluationInstance,
        sample_path: Path,
        sample: SampleIdentity,
    ) -> JsonObject:
        actual_digest, actual_length = _digest_path(sample_path)
        if actual_digest != sample.sha256 or actual_length != sample.byte_length:
            raise ValueError("Windows KVM stage received bytes outside the admitted Sample")
        run_path = Path(cast(str, instance.state["runPath"]))
        run_disk_path = Path(cast(str, instance.state["runDiskPath"]))
        with run_disk_path.open("xb") as handle:
            handle.truncate(self.config.run_disk_mib * 1024 * 1024)
        _run_checked([str(self.config.mkfs_fat_path), "-n", _RUN_LABEL, str(run_disk_path)])
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run",
            "runId": instance.instance_id.replace("evaluation-instance:", "evaluation-run:"),
            "sampleDigest": sample.sha256,
            "sampleByteLength": sample.byte_length,
            "action": _RUN_ACTION,
            "maxRuntimeMs": instance.state["fixtureRuntimeMs"],
            "fixtureId": "ordivon-benign-v1",
        }
        manifest_path = run_path / "ordivon-run.json"
        _write_private_json(manifest_path, manifest)
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        _run_checked(
            [
                str(self.config.mcopy_path),
                "-o",
                "-i",
                str(run_disk_path),
                str(sample_path),
                "::/fixture.exe",
            ],
            environment=environment,
        )
        _run_checked(
            [
                str(self.config.mcopy_path),
                "-o",
                "-i",
                str(run_disk_path),
                str(manifest_path),
                "::/ordivon-run.json",
            ],
            environment=environment,
        )
        run_disk_path.chmod(0o600)
        _set_owner(run_disk_path, user=self.config.run_user, group=self.config.run_group)
        instance.state["sampleDigest"] = sample.sha256
        instance.state["staged"] = True
        self._persist_run_state(instance, "staged")
        staged_digest, staged_length = _digest_path(run_disk_path)
        return {
            "instanceId": instance.instance_id,
            "sampleId": sample.sample_id,
            "sampleDigest": sample.sha256,
            "runDiskDigestBeforeExecution": staged_digest,
            "runDiskByteLength": staged_length,
            "networkDevicePresent": False,
            "executed": False,
        }

    def _start_swtpm(self, instance: EvaluationInstance) -> int:
        run_path = Path(cast(str, instance.state["runPath"]))
        tpm_state_path = Path(cast(str, instance.state["tpmStatePath"]))
        tpm_socket_path = Path(cast(str, instance.state["tpmSocketPath"]))
        pid_path = run_path / "swtpm.pid"
        log_path = run_path / "swtpm.log"
        _run_checked(
            [
                str(self.config.setpriv_path),
                "--reuid",
                self.config.run_user,
                "--regid",
                self.config.run_group,
                "--init-groups",
                "--",
                str(self.config.swtpm_path),
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={tpm_state_path}",
                "--ctrl",
                f"type=unixio,path={tpm_socket_path}",
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
                raise TimeoutError("swtpm PID file was not created")
            time.sleep(0.1)
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        start_time = _process_start_time(pid)
        if start_time is None:
            raise RuntimeError("swtpm process identity was not observable")
        instance.state["swtpmPid"] = pid
        instance.state["swtpmStartTime"] = start_time
        self._persist_run_state(instance, "swtpm-started")
        return pid

    def _extract_run_file(self, run_disk_path: Path, run_path: Path, name: str) -> Path | None:
        destination = run_path / f"extracted-{name}"
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        completed = subprocess.run(
            [str(self.config.mcopy_path), "-i", str(run_disk_path), f"::/{name}", str(destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            timeout=30,
        )
        if completed.returncode != 0:
            destination.unlink(missing_ok=True)
            return None
        destination.chmod(0o600)
        return destination

    def execute(self, instance: EvaluationInstance, spec: EvaluationSpec) -> EvaluationExecution:
        if (
            instance.state.get("staged") is not True
            or instance.state.get("sampleDigest") != spec.sample.sha256
        ):
            raise ValueError("Windows KVM Sample was not staged")
        run_path = Path(cast(str, instance.state["runPath"]))
        overlay_path = Path(cast(str, instance.state["overlayPath"]))
        vars_path = Path(cast(str, instance.state["varsPath"]))
        run_disk_path = Path(cast(str, instance.state["runDiskPath"]))
        qmp_path = Path(cast(str, instance.state["qmpPath"]))
        tpm_socket_path = Path(cast(str, instance.state["tpmSocketPath"]))
        self._start_swtpm(instance)
        qemu_stdout_path = run_path / "qemu.stdout.log"
        qemu_stderr_path = run_path / "qemu.stderr.log"
        arguments = windows_kvm_qemu_arguments(
            config=self.config,
            overlay_path=overlay_path,
            vars_path=vars_path,
            run_disk_path=run_disk_path,
            qmp_path=qmp_path,
            tpm_socket_path=tpm_socket_path,
            name=instance.instance_id.replace("evaluation-instance:", "ordivon-"),
        )
        started_at = time.monotonic_ns()
        guardian_records: list[GuardianRecord] = []
        with (
            qemu_stdout_path.open("xb") as stdout_handle,
            qemu_stderr_path.open("xb") as stderr_handle,
        ):
            process = subprocess.Popen(arguments, stdout=stdout_handle, stderr=stderr_handle)
            qemu_start_time = _process_start_time(process.pid)
            if qemu_start_time is None:
                process.kill()
                process.wait(timeout=10)
                raise RuntimeError("QEMU process identity was not observable")
            instance.state["qemuPid"] = process.pid
            instance.state["qemuStartTime"] = qemu_start_time
            self._persist_run_state(instance, "executing")
            terminal_reason = "windows-kvm-provider-failed"
            network_devices: list[JsonObject] = []
            qmp_status: JsonValue = {}
            qmp_pci: JsonValue = []
            timed_out = False
            try:
                with _QmpClient(
                    qmp_path, timeout_seconds=self.config.qmp_ready_timeout_seconds
                ) as qmp:
                    qmp_status = qmp.execute("query-status")
                    qmp_pci = qmp.execute("query-pci")
                    network_devices = _pci_network_devices(qmp_pci)
                    instance.state["networkDevicePresent"] = bool(network_devices)
                    if network_devices:
                        guardian_records.append(
                            GuardianRecord(
                                decision="terminate",
                                reason="network-device-present",
                                payload={"deviceCount": len(network_devices)},
                            )
                        )
                        qmp.execute("quit")
                    else:
                        guardian_records.append(
                            GuardianRecord(
                                decision="allow",
                                reason="management-plane-confirmed-no-network-device",
                                payload={"deviceCount": 0},
                            )
                        )
                if not network_devices:
                    timeout_seconds = spec.guardian_policy.max_runtime_ms / 1000
                    try:
                        process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        guardian_records.append(
                            GuardianRecord(
                                decision="terminate",
                                reason="runtime-bound-exceeded",
                                payload={"maxRuntimeMs": spec.guardian_policy.max_runtime_ms},
                            )
                        )
                        try:
                            with _QmpClient(qmp_path, timeout_seconds=5) as qmp:
                                qmp.execute("system_powerdown")
                        except Exception:
                            pass
                        try:
                            process.wait(timeout=self.config.shutdown_grace_seconds)
                        except subprocess.TimeoutExpired:
                            try:
                                with _QmpClient(qmp_path, timeout_seconds=5) as qmp:
                                    qmp.execute("quit")
                            except Exception:
                                process.terminate()
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=10)
                else:
                    process.wait(timeout=30)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                instance.state["qemuExited"] = True
                instance.state["qemuExitCode"] = process.returncode
                self._persist_run_state(instance, "executed")

        qmp_topology_path = run_path / "qmp-topology.json"
        _write_private_json(
            qmp_topology_path,
            {
                "schemaVersion": 1,
                "kind": "ordivon.security.windows-kvm-qmp-topology",
                "status": qmp_status,
                "pci": qmp_pci,
                "networkDevices": cast(list[JsonValue], network_devices),
                "networkDevicePresent": bool(network_devices),
            },
        )
        extracted: dict[str, Path] = {}
        for name in ("ordivon-result.json", "fixture-result.json", "guest-runner.log"):
            path = self._extract_run_file(run_disk_path, run_path, name)
            if path is not None:
                extracted[name] = path
        result: JsonObject | None = None
        fixture_result: JsonObject | None = None
        if "ordivon-result.json" in extracted:
            result = _load_object(extracted["ordivon-result.json"], "Windows KVM result")
        if "fixture-result.json" in extracted:
            fixture_result = _load_object(extracted["fixture-result.json"], "Benign fixture result")

        if timed_out:
            terminal_reason = "guardian-runtime-bound-exceeded"
        elif network_devices:
            terminal_reason = "guardian-network-device-present"
        elif result is None:
            terminal_reason = "windows-kvm-guest-result-missing"
        elif (
            result.get("status") == "completed"
            and result.get("runId")
            == instance.instance_id.replace("evaluation-instance:", "evaluation-run:")
            and result.get("sampleDigest") == spec.sample.sha256
            and result.get("action") == _RUN_ACTION
            and fixture_result is not None
            and fixture_result.get("fixtureId") == "ordivon-benign-v1"
            and fixture_result.get("completed") is True
            and fixture_result.get("networkRequested") is False
        ):
            terminal_reason = "benign-fixture-completed"
        else:
            terminal_reason = "windows-kvm-guest-result-invalid"

        artifacts: list[EvaluationArtifact] = []
        artifact_specs = (
            ("ordivon-result.json", "windows-kvm-result", "application/json"),
            ("fixture-result.json", "benign-fixture-result", "application/json"),
            ("guest-runner.log", "windows-kvm-guest-log", "text/plain"),
        )
        for name, kind, media_type in artifact_specs:
            path = extracted.get(name)
            if path is not None:
                artifacts.append(
                    _artifact(
                        path,
                        artifact_id=f"artifact:windows-kvm:{kind}",
                        kind=kind,
                        media_type=media_type,
                    )
                )
        for path, kind, media_type in (
            (qmp_topology_path, "windows-kvm-qmp-topology", "application/json"),
            (qemu_stdout_path, "windows-kvm-qemu-stdout", "text/plain"),
            (qemu_stderr_path, "windows-kvm-qemu-stderr", "text/plain"),
            (run_path / "swtpm.log", "windows-kvm-swtpm-log", "text/plain"),
        ):
            if path.is_file():
                path.chmod(0o600)
                artifacts.append(
                    _artifact(
                        path,
                        artifact_id=f"artifact:windows-kvm:{kind}",
                        kind=kind,
                        media_type=media_type,
                    )
                )
        duration_ms = max(0, (time.monotonic_ns() - started_at) // 1_000_000)
        observer_records: list[ObserverRecord] = []
        if result is not None:
            observer_records.append(
                ObserverRecord(
                    channel="windows-guest-runner",
                    event_type="benign.fixture-execution",
                    payload=result,
                )
            )
        if fixture_result is not None:
            observer_records.append(
                ObserverRecord(
                    channel="benign-fixture",
                    event_type="benign.fixture-result",
                    payload=fixture_result,
                )
            )
        return EvaluationExecution(
            terminal_reason=terminal_reason,
            observer_records=tuple(observer_records),
            guardian_records=tuple(guardian_records),
            world_facts={
                "providerId": self.provider_id,
                "environmentImageDigest": self.base.environment_image_digest,
                "sampleExecutionAttempted": True,
                "sampleExecuted": fixture_result is not None,
                "sampleDigest": spec.sample.sha256,
                "action": _RUN_ACTION,
                "networkDevicePresent": bool(network_devices),
                "qmpStatus": qmp_status,
                "qemuExitCode": instance.state.get("qemuExitCode"),
                "guestResultPresent": result is not None,
                "fixtureResultPresent": fixture_result is not None,
            },
            raw_metrics={
                "windows_kvm.duration_ms": duration_ms,
                "windows_kvm.network_device_count": len(network_devices),
                "windows_kvm.qemu_exit_code": instance.state.get("qemuExitCode", -1),
                "windows_kvm.guest_result_present": result is not None,
                "windows_kvm.fixture_result_present": fixture_result is not None,
            },
            artifacts=tuple(artifacts),
        )

    def destroy(self, instance: EvaluationInstance) -> ResidualClosureReceipt:
        run_path_value = instance.state.get("runPath")
        if not isinstance(run_path_value, str) or not run_path_value:
            return ResidualClosureReceipt(
                clean=False,
                details={"reason": "run-path-missing", "residualObjects": ["unknown-run-path"]},
            )
        run_path = Path(run_path_value)
        if run_path.exists():
            self._persist_run_state(instance, "closing")
        qemu_pid = instance.state.get("qemuPid", 0)
        swtpm_pid = instance.state.get("swtpmPid", 0)
        qemu_start_time = instance.state.get("qemuStartTime")
        swtpm_start_time = instance.state.get("swtpmStartTime")
        qemu_closed = (
            not isinstance(qemu_pid, int)
            or qemu_pid == 0
            or _terminate_pid(
                qemu_pid,
                expected_fragment="qemu-system-x86_64",
                expected_start_time=(qemu_start_time if isinstance(qemu_start_time, int) else None),
            )
        )
        swtpm_closed = (
            not isinstance(swtpm_pid, int)
            or swtpm_pid == 0
            or _terminate_pid(
                swtpm_pid,
                expected_fragment="swtpm",
                expected_start_time=(
                    swtpm_start_time if isinstance(swtpm_start_time, int) else None
                ),
            )
        )
        ledger_path_value = instance.state.get("runStatePath")
        ledger_path = Path(ledger_path_value) if isinstance(ledger_path_value, str) else None
        if qemu_closed and swtpm_closed:
            if run_path.exists():
                instance.state["qemuClosed"] = True
                instance.state["swtpmClosed"] = True
                self._persist_run_state(instance, "closed")
            shutil.rmtree(run_path, ignore_errors=True)
        run_removed = not run_path.exists()
        ledger_removed = False
        if qemu_closed and swtpm_closed and run_removed and ledger_path is not None:
            ledger_path.unlink(missing_ok=True)
            _fsync_directory(self.ledgers_root)
            ledger_removed = not ledger_path.exists()
        clean = qemu_closed and swtpm_closed and run_removed and ledger_removed
        residual_objects: list[JsonValue] = []
        if not qemu_closed:
            residual_objects.append(f"process:qemu:{qemu_pid}")
        if not swtpm_closed:
            residual_objects.append(f"process:swtpm:{swtpm_pid}")
        if not run_removed:
            residual_objects.append(str(run_path))
        if not ledger_removed:
            residual_objects.append(
                str(ledger_path) if ledger_path is not None else "unknown-ledger"
            )
        return ResidualClosureReceipt(
            clean=clean,
            details={
                "instanceId": instance.instance_id,
                "generation": instance.generation,
                "qemuClosed": qemu_closed,
                "swtpmClosed": swtpm_closed,
                "runDirectoryRemoved": run_removed,
                "ledgerRemoved": ledger_removed,
                "networkDevicePresent": False,
                "residualObjects": residual_objects,
            },
        )
