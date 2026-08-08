from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_bytes, canonical_digest
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
    _process_start_time,
    _set_owner,
    windows_kvm_machine_base_arguments,
)

_REQUEST_KIND = "ordivon.world.entity-migration-destination-request"
_RESPONSE_KIND = "ordivon.world.entity-migration-destination-response"
_PLAN_KIND = "ordivon.world.prepared-entity-migration"
_DEPARTURE_KIND = "ordivon.world.entity-departure-receipt"
_RECEIPT_KIND = "ordivon.world.entity-migration-receipt"
_MIGRATION_DISK_LABEL = "ORDIVON_MIG"


class WorldEntityMigrationRequestError(ValueError):
    code = "invalid-request"


class WorldEntityMigrationIdentityConflict(WorldEntityMigrationRequestError):
    code = "identity-conflict"


class WorldEntityMigrationPolicyRejected(WorldEntityMigrationRequestError):
    code = "policy-rejected"


@dataclass(frozen=True, slots=True)
class WorldEntityKvmConfig:
    machine: WindowsKvmMachineConfig
    destination_world_id: str
    allowed_source_world_ids: tuple[str, ...] = ()
    mkfs_fat_path: Path = Path("/usr/bin/mkfs.fat")
    mcopy_path: Path = Path("/usr/bin/mcopy")
    run_disk_mib: int = 4

    def __post_init__(self) -> None:
        if not self.destination_world_id:
            raise ValueError("Destination World identity must be non-empty")
        if self.run_disk_mib < 1:
            raise ValueError("Entity continuity disk must be at least 1 MiB")


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise WorldEntityMigrationRequestError(f"{label} must be a JSON object")
    return cast(JsonObject, value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorldEntityMigrationRequestError(f"{label} must be a non-empty string")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label)
    if not text.startswith("sha256:") or len(text) != 71:
        raise WorldEntityMigrationRequestError(f"{label} must be a sha256: digest")
    return text


def _process_arguments(pid: object, start_time: object) -> tuple[str, ...]:
    if not isinstance(pid, int) or pid < 1 or not isinstance(start_time, int):
        return ()
    if _process_start_time(pid) != start_time:
        return ()
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ()
    return tuple(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)


class WorldEntityKvmDestination:
    """Security-owned destination for one source-departed Entity continuity carrier.

    A deterministic Windows KVM Run ledger is the pre-body fence. The opaque
    continuity payload is staged on a removable FAT disk before any native
    process starts. QMP plus the root-owned ledger are destination materialization
    authority; Guest self-report is deliberately not used.
    """

    def __init__(
        self,
        config: WorldEntityKvmConfig,
        *,
        machine_provider: WindowsKvmMachineProvider | None = None,
    ) -> None:
        self.config = config
        self.machine_provider = machine_provider or WindowsKvmMachineProvider(config.machine)
        self.allowed_source_world_ids = frozenset(config.allowed_source_world_ids)
        self.receipts_root = config.machine.state_root / "world-entity-receipts"
        self.locks_root = config.machine.state_root / "world-entity-locks"
        for path in (self.receipts_root, self.locks_root):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "kind": "ordivon.security.world-entity-kvm-destination",
            "revision": "4",
            "destinationWorldId": self.config.destination_world_id,
            "machineProvider": self.machine_provider.execution_identity,
            "materializationRole": "entity-continuity-carrier",
            "continuityTransport": "opaque-removable-fat-disk",
            "guestClaimAuthority": "not-used",
            "networkMode": "deny-all-no-nic",
            "recoveryMode": "reobserve-publish-or-prebody-compensate-no-owner-rewrite",
            "unpublishedNativeState": "unknown-unless-completion-or-safe-abandonment-observed",
            "sourceAuthorityAuthentication": "caller-trust-boundary",
        }

    def handle(self, request: JsonObject) -> JsonObject:
        operation, plan, plan_digest = self._validate_request(request)
        if operation == "materialize":
            return self._materialize(request, plan, plan_digest)
        return self._reconcile(plan, plan_digest)

    def _validate_request(self, request: JsonObject) -> tuple[str, JsonObject, str]:
        if request.get("schemaVersion") != 1 or request.get("kind") != _REQUEST_KIND:
            raise WorldEntityMigrationRequestError(
                "Entity Migration destination request schema is unsupported"
            )
        operation = _text(request.get("operation"), "Entity Migration destination operation")
        if operation not in {"materialize", "reconcile"}:
            raise WorldEntityMigrationRequestError(
                "Entity Migration destination operation is unsupported"
            )
        plan = _object(request.get("plan"), "Entity Migration plan")
        if plan.get("schemaVersion") != 1 or plan.get("kind") != _PLAN_KIND:
            raise WorldEntityMigrationRequestError(
                "Prepared Entity Migration schema is unsupported"
            )
        plan_digest = _digest(request.get("planDigest"), "Entity Migration plan digest")
        if canonical_digest(plan) != plan_digest:
            raise WorldEntityMigrationRequestError(
                "Entity Migration plan digest does not match plan content"
            )
        _text(plan.get("migrationId"), "Entity Migration identity")
        _text(plan.get("entityId"), "Entity identity")
        source_world_id = _text(plan.get("sourceWorldId"), "Source World identity")
        destination_world_id = _text(plan.get("destinationWorldId"), "Destination World identity")
        _digest(plan.get("sourceDepartureDigest"), "Source departure digest")
        _digest(plan.get("continuityPayloadDigest"), "Continuity payload digest")
        if destination_world_id != self.config.destination_world_id:
            raise WorldEntityMigrationPolicyRejected(
                "Entity Migration targets another destination World"
            )
        if self.allowed_source_world_ids and source_world_id not in self.allowed_source_world_ids:
            raise WorldEntityMigrationPolicyRejected(
                "Source World is not admitted by this destination"
            )
        if operation == "materialize":
            departure = self._source_departure(request.get("sourceDeparture"), plan)
            continuity = cast(JsonValue, request.get("continuityPayload"))
            if canonical_digest(departure) != plan["sourceDepartureDigest"]:
                raise WorldEntityMigrationRequestError(
                    "Source departure digest does not match request content"
                )
            if canonical_digest(continuity) != plan["continuityPayloadDigest"]:
                raise WorldEntityMigrationRequestError(
                    "Continuity payload digest does not match request content"
                )
        elif "sourceDeparture" in request or "continuityPayload" in request:
            raise WorldEntityMigrationRequestError(
                "Reconcile must not resend source departure or continuity payload"
            )
        return operation, plan, plan_digest

    def _source_departure(self, value: object, plan: JsonObject) -> JsonObject:
        departure = _object(value, "Entity Departure receipt")
        if departure.get("schemaVersion") != 1 or departure.get("kind") != _DEPARTURE_KIND:
            raise WorldEntityMigrationRequestError("Entity Departure receipt schema is unsupported")
        expected = {
            "migrationId": plan.get("migrationId"),
            "entityId": plan.get("entityId"),
            "sourceWorldId": plan.get("sourceWorldId"),
            "destinationWorldId": plan.get("destinationWorldId"),
        }
        for field, expected_value in expected.items():
            if departure.get(field) != expected_value:
                raise WorldEntityMigrationRequestError(
                    f"Entity Departure receipt {field} differs from Entity Migration plan"
                )
        _text(departure.get("sourceOccurrenceId"), "Entity Departure source occurrence identity")
        _digest(
            departure.get("sourceOccurrenceDigest"), "Entity Departure source occurrence digest"
        )
        authority = _object(departure.get("authority"), "Entity Departure authority")
        _text(authority.get("authorityId"), "Entity Departure authority identity")
        _text(authority.get("mechanism"), "Entity Departure authority mechanism")
        _object(authority.get("evidence"), "Entity Departure authority evidence")
        return departure

    @staticmethod
    def _coordinates(plan: JsonObject) -> tuple[str, str, str]:
        migration_id = _text(plan.get("migrationId"), "Entity Migration identity")
        token_digest = hashlib.sha256(migration_id.encode("utf-8")).hexdigest()
        return (
            f"wem-{token_digest[:16]}",
            f"entity-body:{token_digest[:20]}",
            migration_id,
        )

    def _generation(self) -> str:
        return f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"

    def _binding(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        return {
            "migrationId": _text(plan.get("migrationId"), "Entity Migration identity"),
            "planDigest": plan_digest,
            "entityId": _text(plan.get("entityId"), "Entity identity"),
            "sourceWorldId": _text(plan.get("sourceWorldId"), "Source World identity"),
            "destinationWorldId": _text(
                plan.get("destinationWorldId"), "Destination World identity"
            ),
            "sourceDepartureDigest": _digest(
                plan.get("sourceDepartureDigest"), "Source departure digest"
            ),
            "continuityPayloadDigest": _digest(
                plan.get("continuityPayloadDigest"), "Continuity payload digest"
            ),
        }

    def _ledger_extra(self, binding: JsonObject) -> JsonObject:
        return {
            "worldEntityMigration": binding,
            "materializationRole": "entity-continuity-carrier",
            "networkMode": "deny-all-no-nic",
        }

    def _materialize(self, request: JsonObject, plan: JsonObject, plan_digest: str) -> JsonObject:
        migration_id = _text(plan.get("migrationId"), "Entity Migration identity")
        with self._migration_lock(migration_id):
            retained = self._load_receipt(migration_id)
            if retained is not None:
                return self._materialized_response(
                    self._receipt_for_exact_plan(retained, plan, plan_digest)
                )
            binding = self._binding(plan, plan_digest)
            token, instance_id, _ = self._coordinates(plan)
            generation = self._generation()
            ledger_path = self.machine_provider.ledgers_root / f"{token}.json"
            run_path = self.machine_provider.runs_root / token
            if ledger_path.exists():
                try:
                    observed = self._observe_existing_state(plan, plan_digest)
                except RuntimeError as error:
                    return self._unknown_response(
                        plan, plan_digest, f"existing-state:{type(error).__name__}"
                    )
                if observed.get("phase") == "migration-running-contained":
                    receipt = self._build_receipt(observed, binding, plan_digest)
                    return self._materialized_response(self._commit_receipt(receipt))
                return self._unknown_response(
                    plan,
                    plan_digest,
                    f"existing-unpublished-phase:{observed.get('phase')}",
                )
            if run_path.exists():
                return self._unknown_response(plan, plan_digest, "run-exists-without-ledger")
            state = self.machine_provider.create_state(
                token=token,
                instance_id=instance_id,
                generation=generation,
            )
            self._stage_continuity(state, request, binding)
            self.machine_provider.persist_state(
                instance_id=instance_id,
                generation=generation,
                state=state,
                phase="migration-staged",
                extra=self._ledger_extra(binding),
            )
            return self._continue_new_materialization(state, binding, plan, plan_digest)

    def _observe_existing_state(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        token, instance_id, _ = self._coordinates(plan)
        generation = self._generation()
        binding = self._binding(plan, plan_digest)
        ledger_path = self.machine_provider.ledgers_root / f"{token}.json"
        if ledger_path.is_symlink() or not ledger_path.is_file():
            raise RuntimeError("Entity Migration KVM ledger is missing or unsafe")
        try:
            loaded = json.loads(ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("Entity Migration KVM ledger is unreadable") from error
        if not isinstance(loaded, dict):
            raise RuntimeError("Entity Migration KVM ledger is not an object")
        if (
            loaded.get("schemaVersion") != 1
            or loaded.get("kind") != "ordivon.security.windows-kvm-run-state"
            or loaded.get("providerId") != self.machine_provider.provider_id
        ):
            raise RuntimeError("Entity Migration KVM ledger schema is unsupported")
        if loaded.get("instanceId") != instance_id or loaded.get("generation") != generation:
            raise WorldEntityMigrationIdentityConflict(
                "Entity Migration KVM ledger belongs to another materialization identity"
            )
        if (
            loaded.get("baseEnvironmentImageDigest")
            != self.machine_provider.base.environment_image_digest
        ):
            raise WorldEntityMigrationIdentityConflict(
                "Entity Migration KVM ledger belongs to another environment generation"
            )
        if loaded.get("worldEntityMigration") != binding:
            raise WorldEntityMigrationIdentityConflict(
                "Entity Migration KVM ledger belongs to another semantic binding"
            )
        run_path = Path(str(loaded.get("runPath", "")))
        if (
            not run_path.is_absolute()
            or run_path.parent != self.machine_provider.runs_root
            or run_path.name != token
            or run_path.is_symlink()
            or not run_path.is_dir()
        ):
            raise RuntimeError("Entity Migration KVM Run path is absent or unsafe")
        loaded["runStatePath"] = str(ledger_path)
        return cast(JsonObject, loaded)

    def _completed_unpublished_observation(self, state: JsonObject) -> bool:
        if state.get("phase") != "executing":
            return False
        qemu_pid = state.get("qemuPid")
        qemu_start_time = state.get("qemuStartTime")
        swtpm_pid = state.get("swtpmPid")
        swtpm_start_time = state.get("swtpmStartTime")
        if (
            not isinstance(qemu_pid, int)
            or not isinstance(qemu_start_time, int)
            or _process_start_time(qemu_pid) != qemu_start_time
        ):
            return False
        if (
            not isinstance(swtpm_pid, int)
            or not isinstance(swtpm_start_time, int)
            or _process_start_time(swtpm_pid) != swtpm_start_time
        ):
            return False
        run_path = Path(str(state["runPath"]))
        run_disk = run_path / "ordivon-migration.img"
        if run_disk.is_symlink() or not run_disk.is_file():
            return False
        arguments = _process_arguments(qemu_pid, qemu_start_time)
        drive_argument = (
            f"file={run_disk},if=none,format=raw,cache=none,aio=threads,id=migrationdisk"
        )
        device_argument = (
            f"usb-storage,drive=migrationdisk,bus=xhci.0,removable=on,serial={_MIGRATION_DISK_LABEL}"
        )
        if (
            str(self.config.machine.qemu_path) not in arguments
            or drive_argument not in arguments
            or device_argument not in arguments
        ):
            return False
        topology = self.machine_provider.inspect_qmp(state)
        status = topology.get("status")
        if (
            not isinstance(status, dict)
            or status.get("running") is not True
            or topology.get("networkDevicePresent") is not False
        ):
            return False
        block = self.machine_provider.qmp_execute(state, "query-block")
        return "migrationdisk" in json.dumps(block, sort_keys=True, separators=(",", ":"))

    def _continue_new_materialization(
        self,
        state: JsonObject,
        binding: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject:
        _, instance_id, _ = self._coordinates(plan)
        generation = self._generation()
        run_path = Path(str(state["runPath"]))
        run_disk = run_path / "ordivon-migration.img"
        state["migrationRunDiskPath"] = str(run_disk)
        if state.get("phase") != "migration-staged":
            raise RuntimeError("Fresh Entity Migration lost its pre-body staged phase")
        extra = self._ledger_extra(binding)

        self.machine_provider.start_swtpm(
            instance_id=instance_id,
            generation=generation,
            state=state,
            ledger_extra=extra,
        )
        arguments = windows_kvm_machine_base_arguments(
            config=self.config.machine,
            state=state,
            name=instance_id,
        )
        arguments.extend(
            [
                "-drive",
                f"file={run_disk},if=none,format=raw,cache=none,aio=threads,id=migrationdisk",
                "-device",
                f"usb-storage,drive=migrationdisk,bus=xhci.0,removable=on,serial={_MIGRATION_DISK_LABEL}",
            ]
        )
        self.machine_provider.start_qemu(
            instance_id=instance_id,
            generation=generation,
            state=state,
            arguments=arguments,
            stdout_path=run_path / "qemu.stdout.log",
            stderr_path=run_path / "qemu.stderr.log",
            ledger_extra=extra,
        )
        topology = self.machine_provider.inspect_qmp(state)
        if topology.get("networkDevicePresent") is True:
            raise RuntimeError("Entity Migration KVM carrier unexpectedly has a network device")
        self.machine_provider.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="migration-running-contained",
            extra=extra,
        )
        receipt = self._build_receipt(state, binding, plan_digest)
        return self._materialized_response(self._commit_receipt(receipt))

    def _stage_continuity(
        self,
        state: JsonObject,
        request: JsonObject,
        binding: JsonObject,
    ) -> None:
        run_path = Path(str(state["runPath"]))
        run_disk = run_path / "ordivon-migration.img"
        continuity_path = run_path / "ordivon-continuity.json"
        manifest_path = run_path / "ordivon-migration.json"
        with run_disk.open("xb") as handle:
            handle.truncate(self.config.run_disk_mib * 1024 * 1024)
        subprocess.run(
            [str(self.config.mkfs_fat_path), "-n", _MIGRATION_DISK_LABEL, str(run_disk)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        continuity = cast(JsonValue, request["continuityPayload"])
        continuity_path.write_bytes(canonical_bytes(continuity) + b"\n")
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-entity-carrier",
            "migrationId": binding["migrationId"],
            "entityId": binding["entityId"],
            "sourceDepartureDigest": binding["sourceDepartureDigest"],
            "continuityPayloadDigest": binding["continuityPayloadDigest"],
            "continuityFile": "continuity.json",
            "guestInterpretationRequired": False,
        }
        manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        for source, destination in (
            (continuity_path, "::/continuity.json"),
            (manifest_path, "::/migration.json"),
        ):
            subprocess.run(
                [str(self.config.mcopy_path), "-o", "-i", str(run_disk), str(source), destination],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                env=environment,
            )
        descriptor, temporary_name = tempfile.mkstemp(prefix="continuity-readback-", dir=run_path)
        os.close(descriptor)
        readback = Path(temporary_name)
        try:
            subprocess.run(
                [
                    str(self.config.mcopy_path),
                    "-o",
                    "-i",
                    str(run_disk),
                    "::/continuity.json",
                    str(readback),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
                env=environment,
            )
            if json.loads(readback.read_text(encoding="utf-8")) != continuity:
                raise RuntimeError("Entity continuity readback differs from staged payload")
        finally:
            readback.unlink(missing_ok=True)
        run_disk.chmod(0o600)
        _set_owner(run_disk, user=self.config.machine.run_user, group=self.config.machine.run_group)
        state["migrationRunDiskPath"] = str(run_disk)

    def _compensate_abandoned_prebody(
        self,
        state: JsonObject,
        binding: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject | None:
        phase = state.get("phase")
        if phase not in {"migration-staged", "swtpm-started"}:
            return None
        owner_pid = state.get("ownerPid")
        owner_start_time = state.get("ownerStartTime")
        if not isinstance(owner_pid, int) or not isinstance(owner_start_time, int):
            return None
        if _process_start_time(owner_pid) == owner_start_time:
            return None

        run_path = Path(str(state["runPath"]))
        qemu_pid = state.get("qemuPid", 0)
        qemu_start_time = state.get("qemuStartTime")
        if qemu_pid not in {0, None} or qemu_start_time is not None:
            return None
        if any(
            (run_path / name).exists()
            for name in ("qemu.stdout.log", "qemu.stderr.log", "qmp.sock")
        ):
            return None

        swtpm_pid = state.get("swtpmPid", 0)
        swtpm_start_time = state.get("swtpmStartTime")
        swtpm_evidence = any(
            (run_path / name).exists()
            for name in ("swtpm.pid", "swtpm.log", "swtpm.sock")
        )
        if phase == "migration-staged":
            if swtpm_pid not in {0, None} or swtpm_start_time is not None or swtpm_evidence:
                return None
        else:
            if not isinstance(swtpm_pid, int) or swtpm_pid < 1:
                return None
            if not isinstance(swtpm_start_time, int):
                return None
            current_swtpm_start = _process_start_time(swtpm_pid)
            if current_swtpm_start is not None and current_swtpm_start != swtpm_start_time:
                return None
            if current_swtpm_start == swtpm_start_time:
                arguments = _process_arguments(swtpm_pid, swtpm_start_time)
                if str(self.config.machine.swtpm_path) not in arguments:
                    return None

        _, instance_id, _ = self._coordinates(plan)
        closure = self.machine_provider.destroy_state(
            instance_id=instance_id,
            generation=self._generation(),
            state=state,
            ledger_extra=self._ledger_extra(binding),
        )
        if not closure.clean:
            return self._unknown_response(plan, plan_digest, "prebody-compensation-incomplete")
        return self._not_committed_response(
            plan,
            plan_digest,
            {
                "nativeRunAbsent": True,
                "preBodyFenceRetained": False,
                "abandonedPreBodyCompensated": True,
                "abandonedPhase": phase,
                "predecessorOwnerDead": True,
                "zeroResidualsObserved": True,
            },
        )

    def _reconcile(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        migration_id = _text(plan.get("migrationId"), "Entity Migration identity")
        with self._migration_lock(migration_id):
            retained = self._load_receipt(migration_id)
            if retained is not None:
                return self._materialized_response(
                    self._receipt_for_exact_plan(retained, plan, plan_digest)
                )
            binding = self._binding(plan, plan_digest)
            token, _, _ = self._coordinates(plan)
            ledger_path = self.machine_provider.ledgers_root / f"{token}.json"
            run_path = self.machine_provider.runs_root / token
            if not ledger_path.exists():
                if run_path.exists():
                    return self._unknown_response(plan, plan_digest, "run-exists-without-ledger")
                return self._not_committed_response(
                    plan,
                    plan_digest,
                    {"nativeRunAbsent": True, "preBodyFenceRetained": False},
                )
            try:
                observed = self._observe_existing_state(plan, plan_digest)
            except RuntimeError as error:
                return self._unknown_response(
                    plan, plan_digest, f"existing-state:{type(error).__name__}"
                )
            phase = observed.get("phase")
            if phase == "migration-running-contained":
                receipt = self._build_receipt(observed, binding, plan_digest)
                return self._materialized_response(self._commit_receipt(receipt))
            if phase == "executing":
                try:
                    completed = self._completed_unpublished_observation(observed)
                except Exception as error:
                    return self._unknown_response(
                        plan,
                        plan_digest,
                        f"unpublished-observation:{type(error).__name__}",
                    )
                if completed:
                    _, instance_id, _ = self._coordinates(plan)
                    self.machine_provider.persist_state(
                        instance_id=instance_id,
                        generation=self._generation(),
                        state=observed,
                        phase="migration-running-contained",
                        extra=self._ledger_extra(binding),
                    )
                    receipt = self._build_receipt(observed, binding, plan_digest)
                    return self._materialized_response(self._commit_receipt(receipt))
            if phase in {"migration-staged", "swtpm-started"}:
                compensated = self._compensate_abandoned_prebody(
                    observed,
                    binding,
                    plan,
                    plan_digest,
                )
                if compensated is not None:
                    return compensated
            unresolved = self._unresolved_launch_evidence(
                Path(str(observed["runPath"])), observed
            )
            if unresolved:
                return self._unknown_response(
                    plan,
                    plan_digest,
                    "unresolved-native-materialization:" + ",".join(unresolved),
                )
            return self._unknown_response(
                plan,
                plan_digest,
                f"unpublished-native-phase:{phase}",
            )

    @staticmethod
    def _unresolved_launch_evidence(run_path: Path, state: JsonObject) -> list[str]:
        unresolved: list[str] = []
        qemu_pid = state.get("qemuPid", 0)
        if (not isinstance(qemu_pid, int) or qemu_pid == 0) and any(
            (run_path / name).exists()
            for name in ("qemu.stdout.log", "qemu.stderr.log", "qmp.sock")
        ):
            unresolved.append("qemu")
        swtpm_pid = state.get("swtpmPid", 0)
        if (not isinstance(swtpm_pid, int) or swtpm_pid == 0) and any(
            (run_path / name).exists() for name in ("swtpm.pid", "swtpm.log", "swtpm.sock")
        ):
            unresolved.append("swtpm")
        return unresolved

    def _build_receipt(
        self, state: JsonObject, binding: JsonObject, plan_digest: str
    ) -> JsonObject:
        materialization = {
            "instanceId": state["instanceId"],
            "generation": state["generation"],
            "planDigest": plan_digest,
            "sourceDepartureDigest": binding["sourceDepartureDigest"],
            "continuityPayloadDigest": binding["continuityPayloadDigest"],
            "qemuPid": state.get("qemuPid", 0),
            "qemuStartTime": state.get("qemuStartTime"),
            "networkDevicePresent": state.get("networkDevicePresent", False),
            "phase": "migration-running-contained",
        }
        return {
            "schemaVersion": 1,
            "kind": _RECEIPT_KIND,
            "migrationId": binding["migrationId"],
            "planDigest": plan_digest,
            "entityId": binding["entityId"],
            "destinationWorldId": binding["destinationWorldId"],
            "sourceDepartureDigest": binding["sourceDepartureDigest"],
            "materializationId": state["instanceId"],
            "materializationDigest": canonical_digest(materialization),
            "destinationEvidence": {
                "authority": "ordivon-security:windows-kvm-entity-carrier",
                "providerId": self.machine_provider.provider_id,
                "generation": state["generation"],
                "materializationRole": "entity-continuity-carrier",
                "continuityPayloadDigest": binding["continuityPayloadDigest"],
                "continuityStagedOnRunDisk": True,
                "sourceDepartureStructurallyBound": True,
                "sourceAuthorityAuthentication": "caller-trust-boundary",
                "networkDevicePresent": state.get("networkDevicePresent", False),
                "qemuPid": state.get("qemuPid", 0),
                "qemuStartTime": state.get("qemuStartTime"),
                "guestClaimAuthority": "not-used",
                "historicalMaterializationReceipt": True,
            },
        }

    def _receipt_path(self, migration_id: str) -> Path:
        return self.receipts_root / f"{hashlib.sha256(migration_id.encode()).hexdigest()}.json"

    def _load_receipt(self, migration_id: str) -> JsonObject | None:
        path = self._receipt_path(migration_id)
        if not path.exists():
            return None
        value = _object(json.loads(path.read_text(encoding="utf-8")), "Entity Migration receipt")
        if value.get("schemaVersion") != 1 or value.get("kind") != _RECEIPT_KIND:
            raise RuntimeError("Retained Entity Migration receipt schema is unsupported")
        if value.get("migrationId") != migration_id:
            raise RuntimeError("Retained Entity Migration receipt identity mismatch")
        return value

    def _commit_receipt(self, receipt: JsonObject) -> JsonObject:
        path = self._receipt_path(_text(receipt.get("migrationId"), "Entity Migration identity"))
        if path.exists():
            retained = self._load_receipt(str(receipt["migrationId"]))
            if retained != receipt:
                raise WorldEntityMigrationIdentityConflict(
                    "Entity Migration identity already has a different destination receipt"
                )
            return cast(JsonObject, retained)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=self.receipts_root)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(canonical_bytes(receipt) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                retained = self._load_receipt(str(receipt["migrationId"]))
                if retained != receipt:
                    raise WorldEntityMigrationIdentityConflict(
                        "Concurrent Entity Migration receipt differs"
                    ) from error
                return cast(JsonObject, retained)
            directory_fd = os.open(self.receipts_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return receipt
        finally:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _receipt_for_exact_plan(
        self,
        receipt: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject:
        expected = {
            "migrationId": plan.get("migrationId"),
            "planDigest": plan_digest,
            "entityId": plan.get("entityId"),
            "destinationWorldId": plan.get("destinationWorldId"),
            "sourceDepartureDigest": plan.get("sourceDepartureDigest"),
        }
        for field, value in expected.items():
            if receipt.get(field) != value:
                raise WorldEntityMigrationIdentityConflict(
                    f"Entity Migration receipt differs for {field}"
                )
        evidence = _object(
            receipt.get("destinationEvidence"), "Entity Migration destination evidence"
        )
        if evidence.get("continuityPayloadDigest") != plan.get("continuityPayloadDigest"):
            raise WorldEntityMigrationIdentityConflict(
                "Entity Migration receipt binds another continuity payload"
            )
        return receipt

    @staticmethod
    def _materialized_response(receipt: JsonObject) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RESPONSE_KIND,
            "status": "materialized",
            "receipt": cast(JsonValue, receipt),
        }

    def _not_committed_response(
        self,
        plan: JsonObject,
        plan_digest: str,
        native: JsonObject,
    ) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RESPONSE_KIND,
            "status": "not_committed",
            "migrationId": plan["migrationId"],
            "planDigest": plan_digest,
            "entityId": plan["entityId"],
            "destinationWorldId": plan["destinationWorldId"],
            "sourceDepartureDigest": plan["sourceDepartureDigest"],
            "continuityPayloadDigest": plan["continuityPayloadDigest"],
            "evidence": {
                "authority": "ordivon-security:windows-kvm-entity-carrier",
                "exactOriginalRetrySafe": True,
                "nativeSubstrateChecked": True,
                **native,
            },
        }

    @staticmethod
    def _unknown_response(plan: JsonObject, plan_digest: str, reason: str) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RESPONSE_KIND,
            "status": "unknown",
            "migrationId": plan["migrationId"],
            "planDigest": plan_digest,
            "reason": reason,
        }

    def _lock_path(self, migration_id: str) -> Path:
        return self.locks_root / f"{hashlib.sha256(migration_id.encode()).hexdigest()}.lock"

    @contextlib.contextmanager
    def _migration_lock(self, migration_id: str):
        descriptor = os.open(
            self._lock_path(migration_id),
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def rejected_world_entity_response(error: WorldEntityMigrationRequestError) -> JsonObject:
    return {
        "schemaVersion": 1,
        "kind": _RESPONSE_KIND,
        "status": "rejected",
        "code": error.code,
        "reason": str(error),
    }
