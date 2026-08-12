from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation.world_entity import (
    WorldEntityKvmConfig,
    WorldEntityKvmDestination,
    WorldEntityMigrationIdentityConflict,
    WorldEntityMigrationRequestError,
)
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig

SOURCE = "run:w2-entity:A"
DESTINATION = "security-world:w2-entity:B"
BASE_MANIFEST = Path(
    "/var/lib/ordivon/security/providers/windows-kvm/images/"
    "windows-11-enterprise-eval-25h2-5539ce279f1e4cad.manifest.json"
)


def departure(migration_id: str = "migration:w2:entity:1") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-departure-receipt",
        "migrationId": migration_id,
        "entityId": "entity:w2:agent",
        "sourceWorldId": SOURCE,
        "destinationWorldId": DESTINATION,
        "sourceOccurrenceId": "entity-departure:w2:fact-1",
        "sourceOccurrenceDigest": canonical_digest({"factId": "fact:w2:departure"}),
        "authority": {
            "authorityId": "source-world:w2:A",
            "mechanism": "verified-departure.v1",
            "evidence": {"factId": "fact:w2:departure", "verified": True},
        },
    }


def continuity(state: str = "v1") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.w2.entity-continuity",
        "entityId": "entity:w2:agent",
        "identityRef": "agent-identity:w2:agent",
        "cognitionRef": f"agent-context:{state}",
        "sourceWorldLocalStateCopied": False,
    }


def plan(
    migration_id: str = "migration:w2:entity:1",
    *,
    departure_value: dict[str, object] | None = None,
    continuity_value: dict[str, object] | None = None,
) -> dict[str, object]:
    d = departure(migration_id) if departure_value is None else departure_value
    c = continuity() if continuity_value is None else continuity_value
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.prepared-entity-migration",
        "migrationId": migration_id,
        "entityId": "entity:w2:agent",
        "sourceWorldId": SOURCE,
        "destinationWorldId": DESTINATION,
        "sourceDepartureDigest": canonical_digest(d),
        "continuityPayloadDigest": canonical_digest(c),
    }


def materialize_request(
    migration_id: str = "migration:w2:entity:1",
    *,
    departure_value: dict[str, object] | None = None,
    continuity_value: dict[str, object] | None = None,
) -> dict[str, object]:
    d = departure(migration_id) if departure_value is None else departure_value
    c = continuity() if continuity_value is None else continuity_value
    prepared = plan(migration_id, departure_value=d, continuity_value=c)
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-migration-destination-request",
        "operation": "materialize",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
        "sourceDeparture": d,
        "continuityPayload": c,
    }


def reconcile_request(prepared: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.entity-migration-destination-request",
        "operation": "reconcile",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
    }


class _FakeMachineProvider:
    provider_id = "provider:windows-kvm"

    def __init__(self, root: Path) -> None:
        self.base = SimpleNamespace(environment_image_digest="sha256:" + "a" * 64)
        self.runs_root = root / "runs"
        self.ledgers_root = root / "run-ledgers"
        self.runs_root.mkdir(parents=True)
        self.ledgers_root.mkdir(parents=True)
        self.start_swtpm_calls = 0
        self.start_qemu_calls = 0
        self.inspect_calls = 0
        self.persist_calls = 0
        self.destroy_calls = 0
        self.destroy_clean = True

    @property
    def execution_identity(self):
        return {"providerId": self.provider_id, "implementationRevision": "fake"}

    def create_state(self, *, token: str, instance_id: str, generation: str):
        run = self.runs_root / token
        run.mkdir()
        (run / "tpm-state").mkdir()
        for name in ("system-overlay.qcow2", "OVMF_VARS.4m.fd"):
            (run / name).write_bytes(b"fake")
        return {
            "runPath": str(run),
            "runStatePath": str(self.ledgers_root / f"{token}.json"),
            "overlayPath": str(run / "system-overlay.qcow2"),
            "varsPath": str(run / "OVMF_VARS.4m.fd"),
            "qmpPath": str(run / "qmp.sock"),
            "tpmSocketPath": str(run / "swtpm.sock"),
            "tpmStatePath": str(run / "tpm-state"),
            "qemuPid": 0,
            "qemuStartTime": None,
            "swtpmPid": 0,
            "swtpmStartTime": None,
            "ownerPid": os.getpid(),
            "ownerStartTime": 1,
            "security": {"revision": "fake"},
            "instanceId": instance_id,
            "generation": generation,
            "qemuExited": False,
        }

    def persist_state(self, *, instance_id, generation, state, phase, extra=None):
        self.persist_calls += 1
        state["phase"] = phase
        value = {
            **state,
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run-state",
            "providerId": self.provider_id,
            "instanceId": instance_id,
            "generation": generation,
            "baseEnvironmentImageDigest": self.base.environment_image_digest,
        }
        value.pop("runStatePath", None)
        value.pop("migrationRunDiskPath", None)
        value.pop("claimedFromPhase", None)
        if extra:
            value.update(extra)
        Path(state["runStatePath"]).write_text(json.dumps(value), encoding="utf-8")

    def load_state(self, *, token, instance_id, generation):
        raise AssertionError("Entity reconciliation must not claim Provider recovery authority")

    def claim_existing_state(self, *, token, instance_id, generation, phase, expected_extra=None):
        raise AssertionError("Entity reconciliation must not rewrite Provider owner authority")

    def start_swtpm(self, *, instance_id, generation, state, ledger_extra=None):
        self.start_swtpm_calls += 1
        state["swtpmPid"] = 111
        state["swtpmStartTime"] = 1001
        self.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="swtpm-started",
            extra=ledger_extra,
        )
        return 111

    def start_qemu(
        self, *, instance_id, generation, state, stdout_path, stderr_path, ledger_extra=None, **_
    ):
        self.start_qemu_calls += 1
        stdout_path.touch()
        stderr_path.touch()
        state["qemuPid"] = 222
        state["qemuStartTime"] = 2002
        self.persist_state(
            instance_id=instance_id,
            generation=generation,
            state=state,
            phase="executing",
            extra=ledger_extra,
        )
        return SimpleNamespace(pid=222)

    def inspect_qmp(self, state):
        self.inspect_calls += 1
        state["networkDevicePresent"] = False
        return {"status": {"status": "running", "running": True}, "networkDevicePresent": False}

    def qmp_execute(self, state, command):
        assert command == "query-block"
        return [{"device": "migrationdisk"}]

    def destroy_state(self, *, instance_id, generation, state, ledger_extra=None):
        del instance_id, generation, ledger_extra
        self.destroy_calls += 1
        if not self.destroy_clean:
            return SimpleNamespace(clean=False, details={"residualObjects": ["fixture-residual"]})
        run_path = Path(state["runPath"])
        ledger_path = Path(state["runStatePath"])
        shutil.rmtree(run_path, ignore_errors=True)
        ledger_path.unlink(missing_ok=True)
        return SimpleNamespace(
            clean=True,
            details={
                "qemuClosed": True,
                "swtpmClosed": True,
                "runDirectoryRemoved": True,
                "ledgerRemoved": True,
                "residualObjects": [],
            },
        )


class WorldEntityKvmDestinationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        tools = self.root / "tools"
        tools.mkdir()
        tool_paths: dict[str, Path] = {}
        for name in ("qemu-system-x86_64", "qemu-img", "swtpm", "setpriv"):
            path = tools / name
            path.write_bytes(b"tool")
            path.chmod(0o755)
            tool_paths[name] = path

        mkfs_fat = tools / "mkfs.fat"
        mkfs_fat.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        mkfs_fat.chmod(0o755)
        mcopy = tools / "mcopy"
        mcopy.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import shutil, sys\n"
            "args = sys.argv[1:]\n"
            "image = Path(args[args.index('-i') + 1])\n"
            "source, destination = args[-2], args[-1]\n"
            "store = Path(str(image) + '.mcopy')\n"
            "store.mkdir(exist_ok=True)\n"
            "if source.startswith('::/'):\n"
            "    shutil.copyfile(store / Path(source).name, destination)\n"
            "else:\n"
            "    shutil.copyfile(source, store / Path(destination).name)\n",
            encoding="utf-8",
        )
        mcopy.chmod(0o755)

        manifest = self.root / "base.manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        firmware = self.root / "OVMF_CODE.fd"
        firmware.write_bytes(b"firmware")
        machine = WindowsKvmMachineConfig(
            state_root=self.root,
            base_manifest_path=manifest,
            qemu_path=tool_paths["qemu-system-x86_64"],
            qemu_img_path=tool_paths["qemu-img"],
            swtpm_path=tool_paths["swtpm"],
            setpriv_path=tool_paths["setpriv"],
            firmware_code_path=firmware,
            run_user="qemu",
            run_group="qemu",
            memory_mib=512,
            vcpu_count=1,
            qmp_ready_timeout_seconds=5,
            shutdown_grace_seconds=1,
        )
        self.provider = _FakeMachineProvider(self.root)
        self.destination = WorldEntityKvmDestination(
            WorldEntityKvmConfig(
                machine=machine,
                destination_world_id=DESTINATION,
                allowed_source_world_ids=(SOURCE,),
                mkfs_fat_path=mkfs_fat,
                mcopy_path=mcopy,
            ),
            machine_provider=self.provider,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _stage_only(self, prepared: dict[str, object]) -> tuple[dict[str, object], Path]:
        request = materialize_request(str(prepared["migrationId"]))
        binding = self.destination._binding(prepared, canonical_digest(prepared))
        token, instance_id, _ = self.destination._coordinates(prepared)
        state = self.provider.create_state(
            token=token,
            instance_id=instance_id,
            generation=self.destination._generation(),
        )
        with patch("ordivon_security.evaluation.world_entity._set_owner"):
            self.destination._stage_continuity(state, request, binding)
        self.provider.persist_state(
            instance_id=instance_id,
            generation=self.destination._generation(),
            state=state,
            phase="migration-staged",
            extra=self.destination._ledger_extra(binding),
        )
        return state, Path(state["runStatePath"])

    def test_execution_identity_declares_publication_and_prebody_compensation(self) -> None:
        identity = self.destination.execution_identity
        self.assertEqual(identity["revision"], "5")
        self.assertEqual(
            identity["inspectionMode"],
            "read-only-native-commitment-projection-v1",
        )
        self.assertEqual(
            identity["recoveryMode"],
            "reobserve-publish-or-prebody-compensate-no-owner-rewrite",
        )
        self.assertEqual(
            identity["unpublishedNativeState"],
            "unknown-unless-completion-or-safe-abandonment-observed",
        )

    def test_reconcile_without_run_proves_native_non_materialization(self) -> None:
        prepared = plan()
        response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "not_committed")
        self.assertTrue(response["evidence"]["nativeSubstrateChecked"])
        self.assertTrue(response["evidence"]["nativeRunAbsent"])
        self.assertTrue(response["evidence"]["exactOriginalRetrySafe"])

    def test_dead_owner_staged_prebody_is_compensated_to_not_committed(self) -> None:
        prepared = plan()
        state, ledger = self._stage_only(prepared)
        run_path = Path(state["runPath"])
        with patch(
            "ordivon_security.evaluation.world_entity._process_start_time",
            return_value=None,
        ):
            response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "not_committed")
        self.assertTrue(response["evidence"]["abandonedPreBodyCompensated"])
        self.assertEqual(response["evidence"]["abandonedPhase"], "migration-staged")
        self.assertTrue(response["evidence"]["predecessorOwnerDead"])
        self.assertTrue(response["evidence"]["zeroResidualsObserved"])
        self.assertTrue(response["evidence"]["exactOriginalRetrySafe"])
        self.assertFalse(ledger.exists())
        self.assertFalse(run_path.exists())
        self.assertEqual(self.provider.destroy_calls, 1)

    def test_live_owner_staged_prebody_remains_unknown_without_cleanup(self) -> None:
        prepared = plan()
        _, ledger = self._stage_only(prepared)
        before = ledger.read_bytes()
        with patch(
            "ordivon_security.evaluation.world_entity._process_start_time",
            return_value=1,
        ):
            response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "unknown")
        self.assertEqual(response["reason"], "unpublished-native-phase:migration-staged")
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(self.provider.destroy_calls, 0)

    def test_dead_owner_swtpm_only_prebody_is_compensated_to_not_committed(self) -> None:
        prepared = plan()
        state, ledger = self._stage_only(prepared)
        binding = self.destination._binding(prepared, canonical_digest(prepared))
        token, instance_id, _ = self.destination._coordinates(prepared)
        del token
        self.provider.start_swtpm(
            instance_id=instance_id,
            generation=self.destination._generation(),
            state=state,
            ledger_extra=self.destination._ledger_extra(binding),
        )
        with (
            patch(
                "ordivon_security.evaluation.world_entity._process_start_time",
                side_effect=lambda pid: 1001 if pid == 111 else None,
            ),
            patch(
                "ordivon_security.evaluation.world_entity._process_arguments",
                return_value=(str(self.destination.config.machine.swtpm_path), "socket"),
            ),
        ):
            response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "not_committed")
        self.assertTrue(response["evidence"]["abandonedPreBodyCompensated"])
        self.assertEqual(response["evidence"]["abandonedPhase"], "swtpm-started")
        self.assertFalse(ledger.exists())
        self.assertEqual(self.provider.destroy_calls, 1)
        self.assertEqual(self.provider.start_qemu_calls, 0)

    def test_incomplete_prebody_compensation_remains_unknown(self) -> None:
        prepared = plan()
        _, ledger = self._stage_only(prepared)
        self.provider.destroy_clean = False
        with patch(
            "ordivon_security.evaluation.world_entity._process_start_time",
            return_value=None,
        ):
            response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "unknown")
        self.assertEqual(response["reason"], "prebody-compensation-incomplete")
        self.assertTrue(ledger.exists())
        self.assertEqual(self.provider.destroy_calls, 1)

    def test_launch_evidence_without_persisted_body_never_returns_not_committed(self) -> None:
        prepared = plan()
        state, ledger = self._stage_only(prepared)
        run = Path(state["runPath"])
        (run / "qemu.stdout.log").touch()
        response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "unknown")
        self.assertEqual(response["reason"], "unresolved-native-materialization:qemu")
        self.assertTrue(ledger.exists())

    def test_executing_reconcile_is_read_only_and_preserves_predecessor_owner(self) -> None:
        prepared = plan()
        _, ledger = self._stage_only(prepared)
        value = json.loads(ledger.read_text(encoding="utf-8"))
        value.update(
            {
                "phase": "executing",
                "ownerPid": 424242,
                "ownerStartTime": 31337,
                "qemuPid": 222,
                "qemuStartTime": 2002,
                "swtpmPid": 111,
                "swtpmStartTime": 1001,
                "networkDevicePresent": False,
            }
        )
        ledger.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        before = ledger.read_bytes()
        persist_calls = self.provider.persist_calls
        inspect_calls = self.provider.inspect_calls
        response = self.destination.handle(reconcile_request(prepared))
        self.assertEqual(response["status"], "unknown")
        self.assertEqual(response["reason"], "unpublished-native-phase:executing")
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(self.provider.persist_calls, persist_calls)
        self.assertEqual(self.provider.inspect_calls, inspect_calls)
        retained = json.loads(ledger.read_text(encoding="utf-8"))
        self.assertEqual(retained["ownerPid"], 424242)
        self.assertEqual(retained["ownerStartTime"], 31337)

    def test_completed_executing_reconcile_publishes_without_rewriting_owner(self) -> None:
        prepared = plan()
        state, ledger = self._stage_only(prepared)
        run_disk = Path(state["runPath"]) / "ordivon-migration.img"
        value = json.loads(ledger.read_text(encoding="utf-8"))
        value.update(
            {
                "phase": "executing",
                "ownerPid": 424242,
                "ownerStartTime": 31337,
                "qemuPid": 222,
                "qemuStartTime": 2002,
                "swtpmPid": 111,
                "swtpmStartTime": 1001,
                "networkDevicePresent": False,
            }
        )
        ledger.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        qemu_arguments = (
            str(self.destination.config.machine.qemu_path),
            f"file={run_disk},if=none,format=raw,cache=none,aio=threads,id=migrationdisk",
            "usb-storage,drive=migrationdisk,bus=xhci.0,removable=on,serial=ORDIVON_MIG",
        )

        def process_start_time(pid: int) -> int | None:
            return {222: 2002, 111: 1001}.get(pid)

        persist_calls = self.provider.persist_calls
        with (
            patch(
                "ordivon_security.evaluation.world_entity._process_start_time",
                side_effect=process_start_time,
            ),
            patch(
                "ordivon_security.evaluation.world_entity._process_arguments",
                return_value=qemu_arguments,
            ),
        ):
            response = self.destination.handle(reconcile_request(prepared))

        self.assertEqual(response["status"], "materialized")
        self.assertEqual(self.provider.persist_calls, persist_calls + 1)
        self.assertEqual(self.provider.inspect_calls, 1)
        self.assertEqual(self.provider.start_swtpm_calls, 0)
        self.assertEqual(self.provider.start_qemu_calls, 0)
        retained = json.loads(ledger.read_text(encoding="utf-8"))
        self.assertEqual(retained["phase"], "migration-running-contained")
        self.assertEqual(retained["ownerPid"], 424242)
        self.assertEqual(retained["ownerStartTime"], 31337)

    def test_materialize_does_not_resume_an_existing_unpublished_fence(self) -> None:
        prepared = plan()
        self._stage_only(prepared)
        persist_calls = self.provider.persist_calls
        response = self.destination.handle(materialize_request())
        self.assertEqual(response["status"], "unknown")
        self.assertEqual(response["reason"], "existing-unpublished-phase:migration-staged")
        self.assertEqual(self.provider.persist_calls, persist_calls)
        self.assertEqual(self.provider.start_swtpm_calls, 0)
        self.assertEqual(self.provider.start_qemu_calls, 0)

    def test_materialize_stages_real_fat_continuity_and_commits_one_receipt(self) -> None:
        request = materialize_request()
        with (
            patch("ordivon_security.evaluation.world_entity._set_owner"),
            patch(
                "ordivon_security.evaluation.world_entity.windows_kvm_machine_base_arguments",
                return_value=[],
            ),
        ):
            first = self.destination.handle(request)
            second = self.destination.handle(request)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "materialized")
        receipt = first["receipt"]
        evidence = receipt["destinationEvidence"]
        self.assertEqual(evidence["materializationRole"], "entity-continuity-carrier")
        self.assertTrue(evidence["continuityStagedOnRunDisk"])
        self.assertEqual(evidence["guestClaimAuthority"], "not-used")
        self.assertFalse(evidence["networkDevicePresent"])
        self.assertEqual(self.provider.start_qemu_calls, 1)
        self.assertEqual(self.provider.start_swtpm_calls, 1)
        token, _, _ = self.destination._coordinates(request["plan"])
        disk = self.provider.runs_root / token / "ordivon-migration.img"
        self.assertTrue(disk.is_file())

    def test_running_contained_ledger_reconstructs_historical_receipt_without_new_body(
        self,
    ) -> None:
        request = materialize_request()
        with (
            patch("ordivon_security.evaluation.world_entity._set_owner"),
            patch(
                "ordivon_security.evaluation.world_entity.windows_kvm_machine_base_arguments",
                return_value=[],
            ),
        ):
            self.destination.handle(request)
        receipt_path = self.destination._receipt_path(str(request["plan"]["migrationId"]))
        receipt_path.unlink()
        self.assertEqual(self.provider.start_qemu_calls, 1)
        recovered = self.destination.handle(reconcile_request(request["plan"]))
        self.assertEqual(recovered["status"], "materialized")
        self.assertEqual(self.provider.start_qemu_calls, 1)
        self.assertTrue(
            recovered["receipt"]["destinationEvidence"]["historicalMaterializationReceipt"]
        )

    def test_inspection_absent_state_is_bounded_and_read_only(self) -> None:
        prepared = plan("migration:inspection:absent")
        before = (
            self.provider.persist_calls,
            self.provider.inspect_calls,
            self.provider.destroy_calls,
            self.provider.start_qemu_calls,
            self.provider.start_swtpm_calls,
        )
        result = self.destination.inspect_commitment(prepared, canonical_digest(prepared))
        self.assertEqual(result["state"], "not-started")
        self.assertEqual(result["commitmentClass"], "not-yet-native")
        self.assertEqual(result["nativePhase"], "absent")
        self.assertEqual(result["nextOwnerOperation"], "materialize-exact-original-request")
        self.assertEqual(result["authority"], "not-granted-by-inspection")
        self.assertEqual(result["externalCurrentness"], "not-claimed")
        self.assertTrue(result["evidence"]["nativeRunAbsent"])
        self.assertEqual(list(self.destination.receipts_root.iterdir()), [])
        self.assertEqual(list(self.provider.ledgers_root.iterdir()), [])
        self.assertEqual(list(self.provider.runs_root.iterdir()), [])
        self.assertEqual(
            before,
            (
                self.provider.persist_calls,
                self.provider.inspect_calls,
                self.provider.destroy_calls,
                self.provider.start_qemu_calls,
                self.provider.start_swtpm_calls,
            ),
        )
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in ("runPath", "qemuPid", "swtpmPid", "continuityPayload", "sourceDeparture"):
            self.assertNotIn(forbidden, encoded)

    def test_inspection_staged_ledger_is_native_outstanding_and_byte_preserving(self) -> None:
        prepared = plan("migration:inspection:staged")
        _, ledger = self._stage_only(prepared)
        before_bytes = ledger.read_bytes()
        before = (
            self.provider.persist_calls,
            self.provider.inspect_calls,
            self.provider.destroy_calls,
            self.provider.start_qemu_calls,
            self.provider.start_swtpm_calls,
        )
        result = self.destination.inspect_commitment(prepared, canonical_digest(prepared))
        self.assertEqual(result["state"], "native-outstanding")
        self.assertEqual(result["commitmentClass"], "outstanding")
        self.assertEqual(result["nativePhase"], "migration-staged")
        self.assertEqual(result["nextOwnerOperation"], "reconcile-or-compensate-prebody")
        self.assertTrue(str(result["evidence"]["ledgerDigest"]).startswith("sha256:"))
        self.assertEqual(ledger.read_bytes(), before_bytes)
        self.assertEqual(
            before,
            (
                self.provider.persist_calls,
                self.provider.inspect_calls,
                self.provider.destroy_calls,
                self.provider.start_qemu_calls,
                self.provider.start_swtpm_calls,
            ),
        )
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in ("runPath", "qemuPid", "swtpmPid", "continuityPayload", "sourceDeparture"):
            self.assertNotIn(forbidden, encoded)

    def test_inspection_materialized_receipt_survives_fresh_destination_without_native_actions(self) -> None:
        request = materialize_request("migration:inspection:materialized")
        with (
            patch("ordivon_security.evaluation.world_entity._set_owner"),
            patch(
                "ordivon_security.evaluation.world_entity.windows_kvm_machine_base_arguments",
                return_value=[],
            ),
        ):
            response = self.destination.handle(request)
        self.assertEqual(response["status"], "materialized")
        migration_id = str(request["plan"]["migrationId"])
        receipt_path = self.destination._receipt_path(migration_id)
        token, _, _ = self.destination._coordinates(request["plan"])
        ledger_path = self.provider.ledgers_root / f"{token}.json"
        receipt_before = receipt_path.read_bytes()
        ledger_before = ledger_path.read_bytes()
        before = (
            self.provider.persist_calls,
            self.provider.inspect_calls,
            self.provider.destroy_calls,
            self.provider.start_qemu_calls,
            self.provider.start_swtpm_calls,
        )
        fresh = WorldEntityKvmDestination(
            self.destination.config,
            machine_provider=self.provider,
        )
        result = fresh.inspect_commitment(request["plan"], request["planDigest"])
        self.assertEqual(result["state"], "materialized")
        self.assertEqual(result["commitmentClass"], "historical-terminal")
        self.assertEqual(result["nativePhase"], "migration-running-contained")
        self.assertIsNone(result["nextOwnerOperation"])
        self.assertTrue(str(result["evidence"]["receiptDigest"]).startswith("sha256:"))
        self.assertEqual(
            result["evidence"]["materializationDigest"],
            response["receipt"]["materializationDigest"],
        )
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        self.assertEqual(ledger_path.read_bytes(), ledger_before)
        self.assertEqual(
            before,
            (
                self.provider.persist_calls,
                self.provider.inspect_calls,
                self.provider.destroy_calls,
                self.provider.start_qemu_calls,
                self.provider.start_swtpm_calls,
            ),
        )
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in ("runPath", "qemuPid", "swtpmPid", "continuityPayload", "sourceDeparture"):
            self.assertNotIn(forbidden, encoded)

    def test_inspection_changed_plan_for_same_native_identity_fails_closed(self) -> None:
        prepared = plan("migration:inspection:identity-conflict")
        self._stage_only(prepared)
        changed = plan(
            "migration:inspection:identity-conflict",
            continuity_value=continuity("inspection-changed"),
        )
        with self.assertRaises(WorldEntityMigrationIdentityConflict):
            self.destination.inspect_commitment(changed, canonical_digest(changed))

    def test_changed_continuity_or_departure_fails_before_native_launch(self) -> None:
        request = materialize_request()
        changed = dict(request)
        changed["continuityPayload"] = continuity("tampered")
        with self.assertRaises(WorldEntityMigrationRequestError):
            self.destination.handle(changed)
        changed_departure = materialize_request()
        changed_departure["sourceDeparture"] = {
            **changed_departure["sourceDeparture"],
            "destinationWorldId": "security-world:forged",
        }
        with self.assertRaises(WorldEntityMigrationRequestError):
            self.destination.handle(changed_departure)
        self.assertEqual(self.provider.start_qemu_calls, 0)

    def test_same_migration_ledger_with_changed_plan_fails_closed(self) -> None:
        prepared = plan()
        self._stage_only(prepared)
        changed_continuity = continuity("changed")
        changed = plan(continuity_value=changed_continuity)
        with self.assertRaises(WorldEntityMigrationIdentityConflict):
            self.destination.handle(reconcile_request(changed))


if __name__ == "__main__":
    unittest.main()
