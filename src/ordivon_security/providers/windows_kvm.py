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

_CHUNK_BYTES = 4 * 1024 * 1024
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
    arguments: list[str], *, timeout_seconds: int = 120
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
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


def _process_start_time(pid: int) -> int | None:
    identity = _process_identity(pid)
    return identity[1] if identity is not None else None


def _reap_child(pid: int) -> None:
    with suppress(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


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
    try:
        command = (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode("utf-8", errors="replace")
        )
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
        if not isinstance(image_value, str) or not isinstance(vars_value, str):
            raise ValueError("Windows KVM base paths are invalid")
        for key in (
            "environmentImage",
            "sourceIso",
            "baseImage",
            "baseVars",
            "firmwareCode",
            "guestRunner",
        ):
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
            base_image_digest=cast(str, digests["baseImage"]),
            base_vars_digest=cast(str, digests["baseVars"]),
            firmware_code_digest=cast(str, digests["firmwareCode"]),
            guest_runner_digest=cast(str, digests["guestRunner"]),
            windows_build=windows_build,
        )


@dataclass(frozen=True, slots=True)
class WindowsKvmMachineConfig:
    state_root: Path
    base_manifest_path: Path
    qemu_path: Path
    qemu_img_path: Path
    swtpm_path: Path
    setpriv_path: Path
    firmware_code_path: Path
    run_user: str
    run_group: str
    memory_mib: int
    vcpu_count: int
    qmp_ready_timeout_seconds: int
    shutdown_grace_seconds: int

    def __post_init__(self) -> None:
        if (
            min(
                self.memory_mib,
                self.vcpu_count,
                self.qmp_ready_timeout_seconds,
                self.shutdown_grace_seconds,
            )
            < 1
        ):
            raise ValueError("Windows KVM machine limits must be positive")
        for path in (self.qemu_path, self.qemu_img_path, self.swtpm_path, self.setpriv_path):
            if not path.is_file() or not path.resolve().is_file():
                raise ValueError(f"Windows KVM machine tool is missing or unsafe: {path}")
        for path in (self.firmware_code_path, self.base_manifest_path):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Windows KVM machine identity file is missing or unsafe: {path}")


@dataclass(frozen=True, slots=True)
class WindowsKvmMachineClosure:
    clean: bool
    details: JsonObject


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

    def wait_for_event(self, event_name: str, *, timeout_seconds: int) -> JsonObject:
        if not event_name or event_name != event_name.strip():
            raise ValueError("QMP event name must be non-empty and trimmed")
        if timeout_seconds < 1:
            raise ValueError("QMP event timeout must be positive")
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"QMP event did not arrive: {event_name}")
            if self._socket is not None:
                # Buffered socket.makefile() readers can become unusable after a read timeout.
                # Use the remaining deadline as one blocking read instead of polling timeouts.
                self._socket.settimeout(remaining)
            try:
                message = self._read_message()
            except TimeoutError as error:
                raise TimeoutError(f"QMP event did not arrive: {event_name}") from error
            if message.get("event") == event_name:
                return message


def windows_kvm_machine_base_arguments(
    *,
    config: WindowsKvmMachineConfig,
    state: JsonObject,
    name: str,
) -> list[str]:
    if not name or name != name.strip():
        raise ValueError("Windows KVM machine name must be non-empty and trimmed")
    required_paths = ("overlayPath", "varsPath", "qmpPath", "tpmSocketPath")
    values: dict[str, Path] = {}
    for key in required_paths:
        value = state.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Windows KVM machine state is missing {key}")
        values[key] = Path(value)
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
        f"unix:{values['qmpPath']},server=on,wait=off",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={config.firmware_code_path}",
        "-drive",
        f"if=pflash,format=raw,file={values['varsPath']}",
        "-chardev",
        f"socket,id=chrtpm,path={values['tpmSocketPath']}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-crb,tpmdev=tpm0",
        "-drive",
        (f"file={values['overlayPath']},if=none,format=qcow2,cache=none,aio=threads,id=osdisk"),
        "-device",
        "ide-hd,drive=osdisk,bus=ide.0",
        "-device",
        "VGA",
        "-device",
        "qemu-xhci,id=xhci",
        "-device",
        "virtio-rng-pci",
        "-rtc",
        "base=utc,clock=host",
        "-boot",
        "order=c,menu=off",
    ]


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


class WindowsKvmMachineProvider:
    provider_id = "provider:windows-kvm"

    def __init__(self, config: WindowsKvmMachineConfig) -> None:
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
            "secureBoot": False,
            "smm": False,
            "networkAuthority": "caller-supplied-qemu-topology",
            "systemDisk": "qcow2-overlay",
            "tpm": "disposable-swtpm-2.0",
            "runUser": self.config.run_user,
            "runGroup": self.config.run_group,
            "privilegeDrop": "setpriv",
        }
        return {
            "kind": "ordivon.security.windows-kvm-machine-provider",
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
        }

    def create_state(self, *, token: str, instance_id: str, generation: str) -> JsonObject:
        if not token or token != token.strip() or "/" in token:
            raise ValueError("Windows KVM machine token is invalid")
        run_path = self.runs_root / token
        if run_path.exists():
            raise FileExistsError(f"Windows KVM Run already exists: {run_path}")
        run_path.mkdir(mode=0o700)
        _set_owner(run_path, user=self.config.run_user, group=self.config.run_group)
        overlay_path = run_path / "system-overlay.qcow2"
        vars_path = run_path / "OVMF_VARS.4m.fd"
        qmp_path = run_path / "qmp.sock"
        tpm_socket_path = run_path / "swtpm.sock"
        tpm_state_path = run_path / "tpm-state"
        tpm_state_path.mkdir(mode=0o700)
        _set_owner(tpm_state_path, user=self.config.run_user, group=self.config.run_group)
        try:
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
                raise RuntimeError("Windows KVM owner process identity was not observable")
        except BaseException:
            shutil.rmtree(run_path, ignore_errors=True)
            raise
        return {
            "runPath": str(run_path),
            "runStatePath": str(self.ledgers_root / f"{token}.json"),
            "overlayPath": str(overlay_path),
            "varsPath": str(vars_path),
            "qmpPath": str(qmp_path),
            "tpmSocketPath": str(tpm_socket_path),
            "tpmStatePath": str(tpm_state_path),
            "qemuPid": 0,
            "swtpmPid": 0,
            "ownerPid": os.getpid(),
            "ownerStartTime": owner_start_time,
            "security": security_source_identity(),
            "instanceId": instance_id,
            "generation": generation,
            "qemuExited": False,
        }

    def persist_state(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        phase: str,
        extra: JsonObject | None = None,
    ) -> None:
        state_path_value = state.get("runStatePath")
        run_path_value = state.get("runPath")
        if not isinstance(state_path_value, str) or not isinstance(run_path_value, str):
            raise ValueError("Windows KVM machine state paths are missing")
        state_path = Path(state_path_value)
        run_path = Path(run_path_value)
        expected_name = run_path.name + ".json"
        if state_path.parent != self.ledgers_root or state_path.name != expected_name:
            raise ValueError("Windows KVM Run state path differs from the root-owned ledger path")
        state["phase"] = phase
        ledger: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "providerId": self.provider_id,
            "instanceId": instance_id,
            "generation": generation,
            "phase": phase,
            "updatedAtNs": time.time_ns(),
            "security": cast(JsonObject, state["security"]),
            "baseEnvironmentImageDigest": self.base.environment_image_digest,
            "ownerPid": state["ownerPid"],
            "ownerStartTime": state["ownerStartTime"],
            "runPath": state["runPath"],
            "overlayPath": state["overlayPath"],
            "varsPath": state["varsPath"],
            "qmpPath": state["qmpPath"],
            "tpmSocketPath": state["tpmSocketPath"],
            "tpmStatePath": state["tpmStatePath"],
            "qemuPid": state.get("qemuPid", 0),
            "qemuStartTime": state.get("qemuStartTime"),
            "swtpmPid": state.get("swtpmPid", 0),
            "swtpmStartTime": state.get("swtpmStartTime"),
            "qemuExited": state.get("qemuExited", False),
            "qemuExitCode": state.get("qemuExitCode"),
            "networkDevicePresent": state.get("networkDevicePresent"),
        }
        if extra is not None:
            for key, value in extra.items():
                if key in ledger and ledger[key] != value:
                    raise ValueError(f"Windows KVM ledger extra conflicts with core field: {key}")
                ledger[key] = value
        _replace_private_json(state_path, ledger)

    def start_swtpm(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        ledger_extra: JsonObject | None = None,
    ) -> int:
        run_path = Path(cast(str, state["runPath"]))
        tpm_state_path = Path(cast(str, state["tpmStatePath"]))
        tpm_socket_path = Path(cast(str, state["tpmSocketPath"]))
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
        state["swtpmPid"] = pid
        state["swtpmStartTime"] = start_time
        self.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="swtpm-started",
            extra=ledger_extra,
        )
        return pid

    def start_qemu(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        arguments: list[str],
        stdout_path: Path,
        stderr_path: Path,
        ledger_extra: JsonObject | None = None,
    ) -> subprocess.Popen[bytes]:
        expected_prefix = [
            str(self.config.setpriv_path),
            "--reuid",
            self.config.run_user,
            "--regid",
            self.config.run_group,
            "--init-groups",
            "--",
            str(self.config.qemu_path),
        ]
        if arguments[: len(expected_prefix)] != expected_prefix:
            raise ValueError("Windows KVM QEMU command does not match Provider execution identity")
        run_path = Path(cast(str, state["runPath"]))
        for path in (stdout_path, stderr_path):
            if path.parent != run_path or path.exists() or path.is_symlink():
                raise ValueError("Windows KVM QEMU log path is outside the machine Run")
        with (
            stdout_path.open("xb") as stdout_handle,
            stderr_path.open("xb") as stderr_handle,
        ):
            process = subprocess.Popen(arguments, stdout=stdout_handle, stderr=stderr_handle)
        start_time = _process_start_time(process.pid)
        if start_time is None:
            process.kill()
            process.wait(timeout=10)
            raise RuntimeError("QEMU process identity was not observable")
        state["qemuPid"] = process.pid
        state["qemuStartTime"] = start_time
        self.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="executing",
            extra=ledger_extra,
        )
        return process

    def record_qemu_exit(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        exit_code: int,
        ledger_extra: JsonObject | None = None,
    ) -> None:
        if not isinstance(exit_code, int):
            raise TypeError("Windows KVM QEMU exit code must be an integer")
        state["qemuExited"] = True
        state["qemuExitCode"] = exit_code
        self.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="executed",
            extra=ledger_extra,
        )

    def inspect_qmp(self, state: JsonObject) -> JsonObject:
        qmp_path = Path(cast(str, state["qmpPath"]))
        with _QmpClient(qmp_path, timeout_seconds=self.config.qmp_ready_timeout_seconds) as qmp:
            status = qmp.execute("query-status")
            pci = qmp.execute("query-pci")
        network_devices = _pci_network_devices(pci)
        state["networkDevicePresent"] = bool(network_devices)
        return {
            "status": status,
            "pci": pci,
            "networkDevices": cast(list[JsonValue], network_devices),
            "networkDevicePresent": bool(network_devices),
        }

    def qmp_execute(
        self,
        state: JsonObject,
        command: str,
        *,
        timeout_seconds: int = 5,
    ) -> JsonValue:
        qmp_path = Path(cast(str, state["qmpPath"]))
        with _QmpClient(qmp_path, timeout_seconds=timeout_seconds) as qmp:
            return qmp.execute(command)

    def wait_for_qmp_event(
        self,
        state: JsonObject,
        event_name: str,
        *,
        timeout_seconds: int,
    ) -> JsonObject:
        qmp_path = Path(cast(str, state["qmpPath"]))
        with _QmpClient(
            qmp_path,
            timeout_seconds=self.config.qmp_ready_timeout_seconds,
        ) as qmp:
            return qmp.wait_for_event(event_name, timeout_seconds=timeout_seconds)

    def destroy_state(
        self,
        *,
        instance_id: str,
        generation: str,
        state: JsonObject,
        ledger_extra: JsonObject | None = None,
    ) -> WindowsKvmMachineClosure:
        run_path_value = state.get("runPath")
        if not isinstance(run_path_value, str) or not run_path_value:
            return WindowsKvmMachineClosure(
                clean=False,
                details={"reason": "run-path-missing", "residualObjects": ["unknown-run-path"]},
            )
        run_path = Path(run_path_value)
        ledger_path_value = state.get("runStatePath")
        ledger_path = Path(ledger_path_value) if isinstance(ledger_path_value, str) else None
        if run_path.exists() and ledger_path is not None:
            self.persist_state(
                instance_id=instance_id,
                generation=generation,
                state=state,
                phase="closing",
                extra=ledger_extra,
            )
        qemu_pid = state.get("qemuPid", 0)
        swtpm_pid = state.get("swtpmPid", 0)
        qemu_start_time = state.get("qemuStartTime")
        swtpm_start_time = state.get("swtpmStartTime")
        qemu_closed = (
            not isinstance(qemu_pid, int)
            or qemu_pid == 0
            or _terminate_pid(
                qemu_pid,
                expected_fragment="qemu-system-x86_64",
                expected_start_time=qemu_start_time if isinstance(qemu_start_time, int) else None,
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
        if qemu_closed and swtpm_closed:
            if run_path.exists():
                state["qemuClosed"] = True
                state["swtpmClosed"] = True
                if ledger_path is not None:
                    self.persist_state(
                        instance_id=instance_id,
                        generation=generation,
                        state=state,
                        phase="closed",
                        extra=ledger_extra,
                    )
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
            residual_objects.append(str(ledger_path) if ledger_path else "unknown-ledger")
        return WindowsKvmMachineClosure(
            clean=clean,
            details={
                "instanceId": instance_id,
                "generation": generation,
                "qemuClosed": qemu_closed,
                "swtpmClosed": swtpm_closed,
                "runDirectoryRemoved": run_removed,
                "ledgerRemoved": ledger_removed,
                "networkDevicePresent": state.get("networkDevicePresent", False),
                "residualObjects": residual_objects,
            },
        )
