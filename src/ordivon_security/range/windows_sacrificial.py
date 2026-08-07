from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.identity import security_source_identity
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
    _set_owner,
    windows_kvm_machine_base_arguments,
)

from .model import RangeSessionSpec
from .protocol import BackendCheckpoint, PendingRangeEvent, RangeSessionInstance

_RANGE_ID = "range:windows-sacrificial-s3"
_RUN_LABEL = "ORDIVON_RUN"
_CANARY_ID = "ordivon-s3-sacrificial-canary-v1"


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _run_checked(arguments: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(
        arguments,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
        timeout=120,
    )


@dataclass(frozen=True, slots=True)
class SacrificialWindowsRangeConfig:
    machine: WindowsKvmMachineConfig
    canary_path: Path
    canary_digest: str
    mkfs_fat_path: Path = Path("/usr/bin/mkfs.fat")
    mcopy_path: Path = Path("/usr/bin/mcopy")
    run_disk_mib: int = 128
    max_runtime_seconds: int = 8 * 60

    def __post_init__(self) -> None:
        if self.canary_path.is_symlink() or not self.canary_path.is_file():
            raise ValueError("S3 sacrificial canary is missing or unsafe")
        if _file_digest(self.canary_path) != self.canary_digest:
            raise ValueError("S3 sacrificial canary digest differs")
        for path in (self.mkfs_fat_path, self.mcopy_path):
            if not path.is_file() or not path.resolve().is_file():
                raise ValueError(f"S3 media tool is missing or unsafe: {path}")
        if min(self.run_disk_mib, self.max_runtime_seconds) < 1:
            raise ValueError("S3 Range limits must be positive")


@dataclass(slots=True)
class _SacrificialRun:
    instance: RangeSessionInstance
    state: JsonObject
    process: subprocess.Popen[bytes]
    events: list[PendingRangeEvent] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    reset_observed: bool = False
    exit_recorded: bool = False
    guest_claim_recorded: bool = False
    watcher: threading.Thread | None = None


class AdversarialWindowsRange:
    """S3 single-node sacrificial Windows Range with external machine authority."""

    range_id = _RANGE_ID

    def __init__(self, config: SacrificialWindowsRangeConfig) -> None:
        self.config = config
        self.machine_provider = WindowsKvmMachineProvider(config.machine)
        self._runs: dict[str, _SacrificialRun] = {}

    @property
    def execution_identity(self) -> JsonObject:
        identity: JsonObject = {
            "kind": "ordivon.security.windows-sacrificial-range",
            "rangeId": self.range_id,
            "implementationRevision": "1",
            "securitySource": security_source_identity(),
            "machineProvider": self.machine_provider.execution_identity,
            "canary": {
                "canaryId": _CANARY_ID,
                "digest": self.config.canary_digest,
                "byteLength": self.config.canary_path.stat().st_size,
            },
            "networkMode": "deny-all-no-nic",
            "guestAuthority": "untrusted-disposable",
            "guestLauncher": {
                "transport": "sealed-guest-runner-v1",
                "compatibilityAction": "execute-benign-fixture",
                "semanticRole": "launch-maintained-sacrificial-canary",
            },
            "checkpointSupport": "not-implemented-s3",
        }
        validate_json(identity)
        return identity

    def _ledger_extra(self, spec: RangeSessionSpec) -> JsonObject:
        return {
            "rangeSessionId": spec.session_id,
            "rangeSpecDigest": spec.digest,
            "rangeId": self.range_id,
            "canaryId": _CANARY_ID,
            "canaryDigest": self.config.canary_digest,
            "networkMode": "deny-all-no-nic",
            "guestLauncherCompatibilityAction": "execute-benign-fixture",
        }

    def _stage_run_disk(self, state: JsonObject, spec: RangeSessionSpec) -> None:
        run_path = Path(cast(str, state["runPath"]))
        run_disk_path = run_path / "ordivon-run.img"
        with run_disk_path.open("xb") as handle:
            handle.truncate(self.config.run_disk_mib * 1024 * 1024)
        _run_checked([str(self.config.mkfs_fat_path), "-n", _RUN_LABEL, str(run_disk_path)])
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run",
            "runId": spec.session_id,
            "sampleDigest": self.config.canary_digest,
            "sampleByteLength": self.config.canary_path.stat().st_size,
            "action": "execute-benign-fixture",
            "maxRuntimeMs": self.config.max_runtime_seconds * 1000,
            "fixtureId": _CANARY_ID,
            "sacrificialRange": True,
            "semanticAction": "execute-sacrificial-canary-v1",
            "launcherCompatibilityAction": "execute-benign-fixture",
        }
        manifest_path = run_path / "ordivon-run.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        for source, destination in (
            (self.config.canary_path, "::/fixture.exe"),
            (manifest_path, "::/ordivon-run.json"),
        ):
            _run_checked(
                [
                    str(self.config.mcopy_path),
                    "-o",
                    "-i",
                    str(run_disk_path),
                    str(source),
                    destination,
                ],
                environment=environment,
            )
        run_disk_path.chmod(0o600)
        _set_owner(
            run_disk_path,
            user=self.config.machine.run_user,
            group=self.config.machine.run_group,
        )
        state["runDiskPath"] = str(run_disk_path)
        state["canaryDigest"] = self.config.canary_digest
        state["networkDevicePresent"] = False

    def _qemu_arguments(self, state: JsonObject, instance_id: str) -> list[str]:
        run_disk_path = Path(cast(str, state["runDiskPath"]))
        arguments = windows_kvm_machine_base_arguments(
            config=self.config.machine,
            state=state,
            name=instance_id,
        )
        arguments.extend(
            [
                "-drive",
                f"file={run_disk_path},if=none,format=raw,cache=none,aio=threads,id=rundisk",
                "-device",
                f"usb-storage,drive=rundisk,bus=xhci.0,removable=on,serial={_RUN_LABEL}",
                "-nic",
                "none",
            ]
        )
        return arguments

    def _emit(
        self,
        run: _SacrificialRun,
        *,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> None:
        with run.lock:
            run.events.append(
                PendingRangeEvent(
                    cursor=len(run.events),
                    logical_time=logical_time,
                    plane=plane,
                    source_id=source_id,
                    event_type=event_type,
                    payload=payload,
                )
            )

    def _watch_reset(self, run: _SacrificialRun) -> None:
        try:
            event = self.machine_provider.wait_for_qmp_event(
                run.state,
                "RESET",
                timeout_seconds=self.config.max_runtime_seconds,
            )
            run.reset_observed = True
            payload: JsonObject = {
                "authority": "qmp",
                "event": event,
                "networkDevicePresent": run.state.get("networkDevicePresent", False),
            }
            self._emit(
                run,
                logical_time=1,
                plane="management",
                source_id="provider:windows-kvm:qmp",
                event_type="machine.reset-observed",
                payload=payload,
            )
        except Exception as error:
            self._emit(
                run,
                logical_time=1,
                plane="management",
                source_id="provider:windows-kvm:qmp",
                event_type="machine.reset-watch-ended",
                payload={"errorType": type(error).__name__, "errorMessage": str(error)},
            )

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        if spec.range_id != self.range_id:
            raise ValueError("S3 Range specification targets another Range")
        token = hashlib.sha256(spec.session_id.encode("utf-8")).hexdigest()[:16]
        instance = RangeSessionInstance(
            instance_id=f"range-instance:s3-{token}",
            session_id=spec.session_id,
        )
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        state = self.machine_provider.create_state(
            token=f"s3-{token}",
            instance_id=instance.instance_id,
            generation=generation,
        )
        state["rangeSpecDigest"] = spec.digest
        process: subprocess.Popen[bytes] | None = None
        run: _SacrificialRun | None = None
        try:
            self._stage_run_disk(state, spec)
            self.machine_provider.persist_state(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                phase="staged",
                extra=self._ledger_extra(spec),
            )
            self.machine_provider.start_swtpm(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                ledger_extra=self._ledger_extra(spec),
            )
            run_path = Path(cast(str, state["runPath"]))
            process = self.machine_provider.start_qemu(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                arguments=self._qemu_arguments(state, instance.instance_id),
                stdout_path=run_path / "qemu.stdout.log",
                stderr_path=run_path / "qemu.stderr.log",
                ledger_extra=self._ledger_extra(spec),
            )
            run = _SacrificialRun(instance=instance, state=state, process=process)
            self._runs[instance.instance_id] = run
            topology = self.machine_provider.inspect_qmp(state)
            if topology["networkDevicePresent"] is True:
                raise RuntimeError("S3 sacrificial Range unexpectedly has a network device")
            self.machine_provider.persist_state(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                phase="running-contained",
                extra=self._ledger_extra(spec),
            )
            self._emit(
                run,
                logical_time=0,
                plane="management",
                source_id="provider:windows-kvm:qmp",
                event_type="machine.containment-confirmed",
                payload={
                    "networkDevicePresent": False,
                    "authority": "qmp-query-pci",
                    "instanceId": instance.instance_id,
                },
            )
            watcher = threading.Thread(
                target=self._watch_reset,
                args=(run,),
                name=f"ordivon-s3-reset-watch-{token}",
                daemon=True,
            )
            run.watcher = watcher
            watcher.start()
            return instance
        except BaseException:
            self._runs.pop(instance.instance_id, None)
            self.machine_provider.destroy_state(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                ledger_extra=self._ledger_extra(spec),
            )
            raise

    def _run(self, instance: RangeSessionInstance) -> _SacrificialRun:
        try:
            return self._runs[instance.instance_id]
        except KeyError as error:
            raise KeyError(f"unknown S3 Range instance: {instance.instance_id}") from error

    def _extract_guest_claim(self, run: _SacrificialRun) -> JsonObject | None:
        if run.guest_claim_recorded:
            claim = run.state.get("guestCanaryClaim")
            return cast(JsonObject, claim) if isinstance(claim, dict) else None
        run_disk_path = Path(cast(str, run.state["runDiskPath"]))
        run_path = Path(cast(str, run.state["runPath"]))
        destination = run_path / "guest-canary-claim.json"
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        completed = subprocess.run(
            [
                str(self.config.mcopy_path),
                "-i",
                str(run_disk_path),
                "::/fixture-result.json",
                str(destination),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            timeout=30,
        )
        run.guest_claim_recorded = True
        if completed.returncode != 0 or not destination.is_file():
            return None
        value = json.loads(destination.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
        validate_json(value)
        claim = cast(JsonObject, value)
        run.state["guestCanaryClaim"] = claim
        self._emit(
            run,
            logical_time=2,
            plane="contested",
            source_id="guest:s3-sacrificial-canary",
            event_type="guest.sacrificial-canary-claim",
            payload={"claim": claim, "authority": "guest-claim-not-world-truth"},
        )
        return claim

    def _record_exit_if_needed(self, run: _SacrificialRun) -> int | None:
        exit_code = run.process.poll()
        if exit_code is None or run.exit_recorded:
            return exit_code
        spec_digest = run.state.get("rangeSpecDigest")
        if not isinstance(spec_digest, str):
            raise ValueError("S3 Range state lost its specification digest")
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        self.machine_provider.record_qemu_exit(
            instance_id=run.instance.instance_id,
            generation=generation,
            state=run.state,
            exit_code=exit_code,
            ledger_extra={
                "rangeSessionId": run.instance.session_id,
                "rangeSpecDigest": spec_digest,
                "rangeId": self.range_id,
                "canaryId": _CANARY_ID,
                "canaryDigest": self.config.canary_digest,
                "networkMode": "deny-all-no-nic",
            },
        )
        run.exit_recorded = True
        self._emit(
            run,
            logical_time=3,
            plane="management",
            source_id="provider:windows-kvm",
            event_type="machine.qemu-exited",
            payload={"exitCode": exit_code, "resetObserved": run.reset_observed},
        )
        self._extract_guest_claim(run)
        return exit_code

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        run = self._run(instance)
        exit_code = self._record_exit_if_needed(run)
        result: JsonObject = {
            "instanceId": instance.instance_id,
            "sessionId": instance.session_id,
            "running": exit_code is None,
            "qemuPid": run.state.get("qemuPid"),
            "qemuExitCode": exit_code,
            "resetObserved": run.reset_observed,
            "networkDevicePresent": run.state.get("networkDevicePresent", False),
            "guestAuthority": "untrusted-disposable",
            "guestCanaryClaim": run.state.get("guestCanaryClaim"),
        }
        validate_json(result)
        return result

    def events(
        self,
        instance: RangeSessionInstance,
        *,
        after_cursor: int,
    ) -> tuple[PendingRangeEvent, ...]:
        run = self._run(instance)
        self._record_exit_if_needed(run)
        with run.lock:
            return tuple(item for item in run.events if item.cursor > after_cursor)

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        del instance, label
        raise NotImplementedError("S3 sacrificial Range does not implement checkpoints")

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        run = self._run(instance)
        if not reason or reason != reason.strip():
            raise ValueError("S3 termination reason must be non-empty and trimmed")
        if run.process.poll() is None:
            try:
                self.machine_provider.qmp_execute(run.state, "quit")
            except Exception:
                run.process.terminate()
            try:
                run.process.wait(timeout=self.config.machine.shutdown_grace_seconds + 5)
            except subprocess.TimeoutExpired:
                run.process.kill()
                run.process.wait(timeout=10)
        exit_code = self._record_exit_if_needed(run)
        receipt: JsonObject = {
            "instanceId": instance.instance_id,
            "reason": reason,
            "qemuExitCode": exit_code,
            "resetObserved": run.reset_observed,
        }
        validate_json(receipt)
        return receipt

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        run = self._run(instance)
        if run.process.poll() is None:
            self.terminate(instance, "range-destroy")
        spec_digest = run.state.get("rangeSpecDigest")
        if not isinstance(spec_digest, str):
            raise ValueError("S3 Range state lost its specification digest")
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        closure = self.machine_provider.destroy_state(
            instance_id=instance.instance_id,
            generation=generation,
            state=run.state,
            ledger_extra={
                "rangeSessionId": instance.session_id,
                "rangeSpecDigest": spec_digest,
                "rangeId": self.range_id,
                "canaryId": _CANARY_ID,
                "canaryDigest": self.config.canary_digest,
                "networkMode": "deny-all-no-nic",
            },
        )
        if run.watcher is not None:
            run.watcher.join(timeout=1)
        self._runs.pop(instance.instance_id, None)
        receipt: JsonObject = {
            "instanceId": instance.instance_id,
            "clean": closure.clean,
            "closure": closure.details,
            "resetObserved": run.reset_observed,
            "guestCanaryClaim": run.state.get("guestCanaryClaim"),
        }
        validate_json(receipt)
        return receipt
