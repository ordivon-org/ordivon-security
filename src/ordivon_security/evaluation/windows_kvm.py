from __future__ import annotations

import os
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest
from ordivon_security.providers.windows_kvm import (
    WindowsKvmBaseImage as WindowsKvmBaseImage,
)
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
)
from ordivon_security.providers.windows_kvm import (
    digest_path as _digest_path,
)
from ordivon_security.providers.windows_kvm import (
    executable_version_line as _version_line,
)
from ordivon_security.providers.windows_kvm import (
    host_cpu_identity as _host_cpu_identity,
)
from ordivon_security.providers.windows_kvm import (
    load_json_object as _load_object,
)
from ordivon_security.providers.windows_kvm import (
    replace_private_json as _replace_private_json,
)
from ordivon_security.providers.windows_kvm import (
    set_path_owner as _set_owner,
)

from .backend import (
    EvaluationArtifact,
    EvaluationExecution,
    EvaluationInstance,
    GuardianRecord,
    ObserverRecord,
    ResidualClosureReceipt,
)
from .models import EvaluationSpec, SampleIdentity

_RUN_ACTION = "execute-benign-fixture"
_RUN_LABEL = "ORDIVON_RUN"
_READONLY_MEDIA_FIXTURE_ID = "ordivon-readonly-media-verifier-v1"


def _write_private_json(path: Path, value: JsonObject) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Private JSON path already exists: {path}")
    _replace_private_json(path, value)


def run_windows_kvm_command(
    arguments: list[str],
    *,
    timeout_seconds: int = 120,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command for the Windows Evaluation P0/P1 profile family."""
    return subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
        env=environment,
    )


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
    admitted_fixture_id: str = "ordivon-benign-v1"
    read_only_sample_media_path: Path | None = None
    read_only_sample_media_digest: str | None = None
    read_only_sample_media_serial: str | None = None
    fixture_runtime_ms: int = 120_000
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
            not self.admitted_fixture_id
            or self.admitted_fixture_id != self.admitted_fixture_id.strip()
        ):
            raise ValueError("Windows KVM admitted fixture identity is invalid")
        media_values = (
            self.read_only_sample_media_path,
            self.read_only_sample_media_digest,
            self.read_only_sample_media_serial,
        )
        if any(value is not None for value in media_values) and not all(
            value is not None for value in media_values
        ):
            raise ValueError("Windows KVM read-only Sample media identity is incomplete")
        if self.read_only_sample_media_path is not None:
            media_path = self.read_only_sample_media_path
            media_digest = cast(str, self.read_only_sample_media_digest)
            media_serial = cast(str, self.read_only_sample_media_serial)
            if media_path.is_symlink() or not media_path.is_file():
                raise ValueError("Windows KVM read-only Sample media is missing or unsafe")
            if len(media_digest) != 71 or not media_digest.startswith("sha256:"):
                raise ValueError("Windows KVM read-only Sample media digest is invalid")
            try:
                bytes.fromhex(media_digest.removeprefix("sha256:"))
            except ValueError as error:
                raise ValueError("Windows KVM read-only Sample media digest is invalid") from error
            if not media_serial or media_serial != media_serial.strip() or "," in media_serial:
                raise ValueError("Windows KVM read-only Sample media serial is invalid")
        if (
            min(
                self.memory_mib,
                self.vcpu_count,
                self.fixture_runtime_ms,
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

    def machine_config(self) -> WindowsKvmMachineConfig:
        return WindowsKvmMachineConfig(
            state_root=self.state_root,
            base_manifest_path=self.base_manifest_path,
            qemu_path=self.qemu_path,
            qemu_img_path=self.qemu_img_path,
            swtpm_path=self.swtpm_path,
            setpriv_path=self.setpriv_path,
            firmware_code_path=self.firmware_code_path,
            run_user=self.run_user,
            run_group=self.run_group,
            memory_mib=self.memory_mib,
            vcpu_count=self.vcpu_count,
            qmp_ready_timeout_seconds=self.qmp_ready_timeout_seconds,
            shutdown_grace_seconds=self.shutdown_grace_seconds,
        )


def windows_kvm_qemu_arguments(
    *,
    config: WindowsKvmProviderConfig,
    overlay_path: Path,
    vars_path: Path,
    run_disk_path: Path,
    qmp_path: Path,
    tpm_socket_path: Path,
    name: str,
    read_only_sample_media_path: Path | None = None,
    read_only_sample_media_serial: str | None = None,
) -> list[str]:
    arguments = [
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
    if read_only_sample_media_path is not None:
        if read_only_sample_media_serial is None:
            raise ValueError("Windows KVM read-only Sample media serial is missing")
        arguments.extend(
            [
                "-drive",
                (
                    f"file={read_only_sample_media_path},if=none,format=raw,readonly=on,"
                    "cache=none,aio=threads,id=sampledisk"
                ),
                "-device",
                (
                    "usb-storage,drive=sampledisk,bus=xhci.0,removable=on,"
                    f"serial={read_only_sample_media_serial}"
                ),
            ]
        )
    return arguments


class WindowsKvmEvaluationBackend:
    """Disposable, deny-all Windows VM backend admitted only for the benign fixture gate."""

    backend_id = "backend:windows-kvm-disposable"
    provider_id = "provider:windows-kvm"

    def __init__(self, config: WindowsKvmProviderConfig) -> None:
        self.config = config
        self.machine_provider = WindowsKvmMachineProvider(config.machine_config())
        self.base = self.machine_provider.base
        self.runs_root = self.machine_provider.runs_root
        self.ledgers_root = self.machine_provider.ledgers_root

    def _ledger_extra(self, instance: EvaluationInstance) -> JsonObject:
        extra: JsonObject = {
            "runId": instance.instance_id.replace("evaluation-instance:", "evaluation-run:"),
        }
        for key in ("evaluationSpecDigest", "runDiskPath"):
            if key in instance.state:
                extra[key] = instance.state[key]
        if "staged" in instance.state:
            extra["staged"] = instance.state["staged"]
        return extra

    def _persist_run_state(self, instance: EvaluationInstance, phase: str) -> None:
        self.machine_provider.persist_state(
            instance_id=instance.instance_id,
            generation=instance.generation,
            state=instance.state,
            phase=phase,
            extra=self._ledger_extra(instance),
        )

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
            "admittedFixtureId": self.config.admitted_fixture_id,
            "fixtureRuntimeMs": self.config.fixture_runtime_ms,
            "readOnlySampleMedia": (
                {
                    "path": str(self.config.read_only_sample_media_path),
                    "digest": self.config.read_only_sample_media_digest,
                    "serial": self.config.read_only_sample_media_serial,
                    "readOnly": True,
                    "removable": True,
                }
                if self.config.read_only_sample_media_path is not None
                else None
            ),
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
        if spec.metadata.get("fixtureId") != self.config.admitted_fixture_id:
            if self.config.admitted_fixture_id == "ordivon-benign-v1":
                raise ValueError("Windows KVM P0 requires the exact benign fixture identity")
            raise ValueError("Windows KVM requires the exact admitted fixture identity")
        if self.config.read_only_sample_media_path is not None:
            expected_media = spec.metadata.get("readOnlySampleMedia")
            if not isinstance(expected_media, dict):
                raise ValueError("Windows KVM read-only Sample media binding is missing")
            if (
                expected_media.get("digest") != self.config.read_only_sample_media_digest
                or expected_media.get("serial") != self.config.read_only_sample_media_serial
                or expected_media.get("readOnly") is not True
                or expected_media.get("sampleExecutionAuthorized") is not False
            ):
                raise ValueError("Windows KVM read-only Sample media binding differs")
        if spec.metadata.get("fixtureCompilationDigest") != self.config.fixture_attestation_digest:
            raise ValueError("Windows KVM fixture attestation differs from Provider identity")
        if spec.environment.image_digest != self.base.environment_image_digest:
            raise ValueError("Evaluation environment does not bind the sealed Windows image")
        if spec.environment.configuration_digest != canonical_digest(self.execution_identity):
            raise ValueError("Evaluation environment does not bind the Windows KVM configuration")

    def create(self, run_id: str, spec: EvaluationSpec) -> EvaluationInstance:
        self._validate_spec(spec)
        token = run_id.removeprefix("evaluation-run:")
        instance_id = f"evaluation-instance:{token}"
        generation = f"windows-kvm:{self.base.environment_image_digest[-16:]}"
        state = self.machine_provider.create_state(
            token=token,
            instance_id=instance_id,
            generation=generation,
        )
        run_path = Path(cast(str, state["runPath"]))
        state.update(
            {
                "runDiskPath": str(run_path / "ordivon-run.img"),
                "evaluationSpecDigest": spec.digest,
                "staged": False,
                "fixtureRuntimeMs": min(
                    self.config.fixture_runtime_ms,
                    spec.guardian_policy.max_runtime_ms,
                ),
                "readOnlySampleMedia": spec.metadata.get("readOnlySampleMedia"),
            }
        )
        instance = EvaluationInstance(
            instance_id=instance_id,
            generation=generation,
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
        run_windows_kvm_command([str(self.config.mkfs_fat_path), "-n", _RUN_LABEL, str(run_disk_path)])
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run",
            "runId": instance.instance_id.replace("evaluation-instance:", "evaluation-run:"),
            "sampleDigest": sample.sha256,
            "sampleByteLength": sample.byte_length,
            "action": _RUN_ACTION,
            "maxRuntimeMs": instance.state["fixtureRuntimeMs"],
            "fixtureId": self.config.admitted_fixture_id,
            "readOnlySampleMedia": instance.state.get("readOnlySampleMedia"),
        }
        manifest_path = run_path / "ordivon-run.json"
        _write_private_json(manifest_path, manifest)
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        run_windows_kvm_command(
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
        run_windows_kvm_command(
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
        return self.machine_provider.start_swtpm(
            instance_id=instance.instance_id,
            generation=instance.generation,
            state=instance.state,
            ledger_extra=self._ledger_extra(instance),
        )

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
            read_only_sample_media_path=self.config.read_only_sample_media_path,
            read_only_sample_media_serial=self.config.read_only_sample_media_serial,
        )
        started_at = time.monotonic_ns()
        guardian_records: list[GuardianRecord] = []
        process = self.machine_provider.start_qemu(
            instance_id=instance.instance_id,
            generation=instance.generation,
            state=instance.state,
            arguments=arguments,
            stdout_path=qemu_stdout_path,
            stderr_path=qemu_stderr_path,
            ledger_extra=self._ledger_extra(instance),
        )
        terminal_reason = "windows-kvm-provider-failed"
        network_devices: list[JsonObject] = []
        qmp_status: JsonValue = {}
        qmp_pci: JsonValue = []
        timed_out = False
        provider_error: Exception | None = None
        try:
            topology = self.machine_provider.inspect_qmp(instance.state)
            qmp_status = topology["status"]
            qmp_pci = topology["pci"]
            network_devices = cast(list[JsonObject], topology["networkDevices"])
            if network_devices:
                guardian_records.append(
                    GuardianRecord(
                        decision="terminate",
                        reason="network-device-present",
                        payload={"deviceCount": len(network_devices)},
                    )
                )
                self.machine_provider.qmp_execute(instance.state, "quit")
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
                    with suppress(Exception):
                        self.machine_provider.qmp_execute(
                            instance.state,
                            "system_powerdown",
                        )
                    try:
                        process.wait(timeout=self.config.shutdown_grace_seconds)
                    except subprocess.TimeoutExpired:
                        try:
                            self.machine_provider.qmp_execute(instance.state, "quit")
                        except Exception:
                            process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
            else:
                process.wait(timeout=30)
        except Exception as error:
            provider_error = error
            guardian_records.append(
                GuardianRecord(
                    decision="terminate",
                    reason="provider-management-plane-failure",
                    payload={"errorType": type(error).__name__},
                )
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            exit_code = process.returncode
            if not isinstance(exit_code, int):
                raise RuntimeError("QEMU exit code was not observable")
            self.machine_provider.record_qemu_exit(
                instance_id=instance.instance_id,
                generation=instance.generation,
                state=instance.state,
                exit_code=exit_code,
                ledger_extra=self._ledger_extra(instance),
            )
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
                "providerErrorType": (
                    type(provider_error).__name__ if provider_error is not None else None
                ),
                "providerErrorMessage": str(provider_error) if provider_error is not None else None,
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

        if provider_error is not None:
            terminal_reason = "windows-kvm-provider-failed:" + type(provider_error).__name__
        elif timed_out:
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
            and fixture_result.get("fixtureId") == self.config.admitted_fixture_id
            and fixture_result.get("completed") is True
            and fixture_result.get("networkRequested") is False
        ):
            if self.config.admitted_fixture_id == _READONLY_MEDIA_FIXTURE_ID:
                if (
                    fixture_result.get("archiveIdentityMatch") is True
                    and fixture_result.get("writeBlocked") is True
                    and fixture_result.get("sampleExecuted") is False
                ):
                    terminal_reason = "readonly-sample-media-verification-completed"
                else:
                    terminal_reason = "windows-kvm-guest-result-invalid"
            else:
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
        if provider_error is not None:
            observer_records.append(
                ObserverRecord(
                    channel="windows-kvm-provider",
                    event_type="provider.management-plane-failure",
                    payload={
                        "errorType": type(provider_error).__name__,
                        "errorMessage": str(provider_error),
                        "qemuExitCode": instance.state.get("qemuExitCode"),
                    },
                )
            )
        if result is not None:
            observer_records.append(
                ObserverRecord(
                    channel="windows-guest-runner",
                    event_type=(
                        "media.readonly-verification"
                        if self.config.admitted_fixture_id == _READONLY_MEDIA_FIXTURE_ID
                        else "benign.fixture-execution"
                    ),
                    payload=result,
                )
            )
        if fixture_result is not None:
            observer_records.append(
                ObserverRecord(
                    channel=(
                        "readonly-media-verifier"
                        if self.config.admitted_fixture_id == _READONLY_MEDIA_FIXTURE_ID
                        else "benign-fixture"
                    ),
                    event_type=(
                        "media.readonly-verification-result"
                        if self.config.admitted_fixture_id == _READONLY_MEDIA_FIXTURE_ID
                        else "benign.fixture-result"
                    ),
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
                "attachedThirdPartySampleExecutionAttempted": False,
                "attachedThirdPartySampleExecuted": False,
                "sampleDigest": spec.sample.sha256,
                "fixtureId": self.config.admitted_fixture_id,
                "action": _RUN_ACTION,
                "readOnlySampleMediaAttached": self.config.read_only_sample_media_path is not None,
                "readOnlySampleMediaDigest": self.config.read_only_sample_media_digest,
                "networkDevicePresent": bool(network_devices),
                "qmpStatus": qmp_status,
                "qemuExitCode": instance.state.get("qemuExitCode"),
                "guestResultPresent": result is not None,
                "fixtureResultPresent": fixture_result is not None,
                "providerErrorType": (
                    type(provider_error).__name__ if provider_error is not None else None
                ),
            },
            raw_metrics={
                "windows_kvm.duration_ms": duration_ms,
                "windows_kvm.network_device_count": len(network_devices),
                "windows_kvm.qemu_exit_code": instance.state.get("qemuExitCode", -1),
                "windows_kvm.guest_result_present": result is not None,
                "windows_kvm.fixture_result_present": fixture_result is not None,
                "windows_kvm.provider_error": provider_error is not None,
            },
            artifacts=tuple(artifacts),
        )

    def destroy(self, instance: EvaluationInstance) -> ResidualClosureReceipt:
        closure = self.machine_provider.destroy_state(
            instance_id=instance.instance_id,
            generation=instance.generation,
            state=instance.state,
            ledger_extra=self._ledger_extra(instance),
        )
        return ResidualClosureReceipt(clean=closure.clean, details=closure.details)
