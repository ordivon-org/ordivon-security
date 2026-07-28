from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence

from ordivon_security_contracts.bindings import (
    ComponentBinding,
    ResidualCheck,
    ResidualReport,
)
from ordivon_security_contracts.bundle import (
    BundleError,
    EvidenceAttachment,
    export_evidence_bundle,
    verify_evidence_bundle,
)
from ordivon_security_contracts.campaign import digest, manifest_digest
from ordivon_security_contracts.coordinator import (
    AmbiguousOperationError,
    CampaignCoordinator,
    ObserverUnavailableError,
)
from ordivon_security_contracts.ledger import (
    CampaignLedger,
    LedgerConflict,
    LedgerCorrupt,
    replay_campaign,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/campaigns/valid/minimal-owned-range.json"
TIME = "2026-07-28T12:00:00Z"
LATER = "2026-07-28T12:00:01Z"


def manifest() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ScriptedPort:
    def __init__(
        self,
        project: str,
        *,
        ambiguous_once: set[str] | None = None,
        observer_unavailable: set[str] | None = None,
        residuals: Sequence[ResidualCheck] | None = None,
        reconstruction_drift: bool = False,
    ) -> None:
        self.project = project
        self.native_id = f"{project}-native-fixture"
        self.ambiguous_once = set() if ambiguous_once is None else set(ambiguous_once)
        self.observer_unavailable = (
            set() if observer_unavailable is None else set(observer_unavailable)
        )
        self.residuals = tuple(residuals or ())
        self.reconstruction_drift = reconstruction_drift
        self.last_campaign_id: str | None = None
        self.last_world_id: str | None = None
        self.execute_calls: list[tuple[str, str]] = []
        self.reconcile_calls: list[tuple[str, str]] = []
        self.accepted: set[tuple[str, str]] = set()
        self.triggered_ambiguities: set[tuple[str, str]] = set()

    def snapshot(self, campaign_id: str, world_id: str) -> dict[str, Any]:
        self.last_campaign_id = campaign_id
        self.last_world_id = world_id
        material = {
            "project": self.project,
            "native_id": self.native_id,
            "campaign_id": campaign_id,
            "world_id": world_id,
            "revision": "fixture-1",
        }
        return {
            "native_id": self.native_id,
            "revision": "fixture-1",
            "root_digest": digest(material),
            "metadata": {"profile": "fixture", "project": self.project},
        }

    def execute(self, operation: str, operation_id: str) -> dict[str, Any]:
        key = (operation, operation_id)
        self.execute_calls.append(key)
        if operation in self.observer_unavailable:
            raise ObserverUnavailableError(f"{self.project} observer unavailable")
        self.accepted.add(key)
        if operation in self.ambiguous_once and key not in self.triggered_ambiguities:
            self.triggered_ambiguities.add(key)
            raise AmbiguousOperationError(f"{self.project} response lost after admission")
        return self._receipt(operation, operation_id, "completed")

    def reconcile(self, operation: str, operation_id: str) -> dict[str, Any]:
        key = (operation, operation_id)
        self.reconcile_calls.append(key)
        if operation in self.observer_unavailable:
            raise ObserverUnavailableError(f"{self.project} observer unavailable")
        if key not in self.accepted:
            raise RuntimeError("native operation identity was never admitted")
        return self._receipt(operation, operation_id, "reconciled")

    def residual_checks(self) -> Sequence[ResidualCheck]:
        return self.residuals

    def _receipt(self, operation: str, operation_id: str, status: str) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "native_id": self.native_id,
            "operation": operation,
            "operation_id": operation_id,
            "status": status,
        }
        if operation == "reconstruct":
            assert self.last_campaign_id is not None
            assert self.last_world_id is not None
            snapshot = self.snapshot(self.last_campaign_id, self.last_world_id)
            if self.reconstruction_drift:
                snapshot = {**snapshot, "revision": "fixture-2"}
            receipt["snapshot"] = snapshot
        return receipt


class CampaignLedgerTests(unittest.TestCase):
    def test_admission_is_idempotent_and_replay_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = CampaignLedger.admit(Path(directory) / "ledger", manifest(), recorded_at=TIME)
            first = ledger.projection()
            second = CampaignLedger.admit(
                Path(directory) / "ledger", manifest(), recorded_at=LATER
            ).projection()
            self.assertEqual(first, second)
            self.assertEqual(1, second.revision)
            self.assertEqual("admitted", second.phase)
            self.assertEqual(
                second,
                replay_campaign(ledger.manifest(), [event.to_dict() for event in ledger.events()]),
            )

    def test_manifest_identity_cannot_be_rebound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ledger"
            CampaignLedger.admit(root, manifest(), recorded_at=TIME)
            other = manifest()
            other["campaign"]["name"] = "other bytes"
            other["identity"]["manifest_digest"] = manifest_digest(other)
            with self.assertRaises(LedgerConflict):
                CampaignLedger.admit(root, other, recorded_at=LATER)

    def test_event_tampering_blocks_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = CampaignLedger.admit(Path(directory) / "ledger", manifest(), recorded_at=TIME)
            ledger.set_phase("preparing", reason="test", recorded_at=LATER)
            path = ledger.events_root / "00000000000000000002.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["data"]["reason"] = "tampered"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(LedgerCorrupt, "event_hash"):
                ledger.projection()

    def test_invalid_operation_transition_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = CampaignLedger.admit(Path(directory) / "ledger", manifest(), recorded_at=TIME)
            with self.assertRaisesRegex(LedgerCorrupt, "cannot transition operation"):
                ledger.transition_operation(
                    operation_id="urn:ordivon:security:operation:freeze:link:test",
                    operation="freeze",
                    component="link",
                    state="succeeded",
                    recorded_at=LATER,
                )
            self.assertEqual(1, ledger.projection().revision)

    def test_final_outcome_requires_destroyed_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = CampaignLedger.admit(Path(directory) / "ledger", manifest(), recorded_at=TIME)
            with self.assertRaisesRegex(LedgerConflict, "must be destroyed"):
                ledger.record_outcome(
                    classification="success",
                    evidence_quality="conclusive",
                    reason_codes=[],
                    evidence_refs=["evidence://fixture"],
                    recorded_at=LATER,
                )

    def test_event_timestamp_must_be_a_real_calendar_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(LedgerCorrupt, "real UTC calendar"):
                CampaignLedger.admit(
                    Path(directory) / "ledger",
                    manifest(),
                    recorded_at="2026-02-30T00:00:00Z",
                )

    def test_component_binding_preserves_native_identity_layer(self) -> None:
        data = manifest()
        binding = ComponentBinding.create(
            project="link",
            campaign_id=data["campaign"]["id"],
            world_id=data["world"]["id"],
            native_id="nw1-native-content-address",
            revision="manifest-revision-1",
            root_digest=digest({"observer_head": "abc"}),
            metadata={"observer_event_count": 3},
        )
        self.assertNotEqual(binding.world_id, binding.native_id)
        self.assertEqual(binding, ComponentBinding.from_dict(binding.to_dict()))


class CoordinatorTests(unittest.TestCase):
    def _coordinator(
        self, directory: str, ports: Sequence[ScriptedPort]
    ) -> CampaignCoordinator:
        ledger = CampaignLedger.admit(Path(directory) / "ledger", manifest(), recorded_at=TIME)
        coordinator = CampaignCoordinator(ledger, ports)
        coordinator.bind_components(recorded_at=TIME)
        return coordinator

    def test_ambiguous_destroy_is_reconciled_without_redispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            edge = ScriptedPort("edge", ambiguous_once={"destroy"})
            coordinator = self._coordinator(directory, [edge])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            first = coordinator.run_fixed("destroy", recorded_at=LATER)
            self.assertEqual("unknown", first.results[0].state)
            operation_id = first.results[0].operation_id
            reconciled = coordinator.reconcile(operation_id, recorded_at=LATER)
            self.assertEqual("succeeded", reconciled.state)
            self.assertEqual(
                1, len([item for item in edge.execute_calls if item[0] == "destroy"])
            )
            self.assertEqual(1, len(edge.reconcile_calls))

    def test_observer_loss_is_not_translated_into_campaign_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = ScriptedPort("link", observer_unavailable={"freeze"})
            coordinator = self._coordinator(directory, [link])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            coordinator.run_fixed("start", recorded_at=TIME)
            freeze = coordinator.run_fixed("freeze", recorded_at=LATER)
            self.assertEqual("unknown", freeze.results[0].state)
            destroyed = coordinator.run_fixed("destroy", recorded_at=LATER)
            self.assertEqual("destroyed", destroyed.projection.phase)
            outcome = coordinator.finalize_infrastructure_outcome(
                recorded_at=LATER,
                evidence_refs=["evidence://observer-loss"],
            )
            self.assertEqual("observer_loss", outcome.outcome["classification"])
            self.assertEqual("inconclusive", outcome.outcome["evidence_quality"])

    def test_unexpected_residual_state_is_containment_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            edge = ScriptedPort(
                "edge",
                residuals=[
                    ResidualCheck(
                        component="edge",
                        subject_id="edge-node:fixture",
                        status="unexpected_residual",
                        detail="node body remains after destroy",
                    )
                ],
            )
            coordinator = self._coordinator(directory, [edge])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            coordinator.run_fixed("destroy", recorded_at=LATER)
            report = coordinator.assess_residuals(recorded_at=LATER)
            self.assertEqual("residual_failure", report.classification)
            outcome = coordinator.finalize_infrastructure_outcome(
                recorded_at=LATER,
                evidence_refs=["evidence://residual-report"],
            )
            self.assertEqual("containment_failure", outcome.outcome["classification"])

    def test_lost_node_residual_is_inconclusive_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            edge = ScriptedPort(
                "edge",
                residuals=[
                    ResidualCheck(
                        component="edge",
                        subject_id="edge-node:lost",
                        status="unknown",
                        detail="node disappeared before independent destruction proof",
                    )
                ],
            )
            coordinator = self._coordinator(directory, [edge])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            coordinator.run_fixed("destroy", recorded_at=LATER)
            report = coordinator.assess_residuals(recorded_at=LATER)
            self.assertEqual("inconclusive", report.classification)
            self.assertEqual(1, report.counts["unknown"])

    def test_reconstruction_compares_the_original_native_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            edge = ScriptedPort("edge")
            coordinator = self._coordinator(directory, [edge])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            reconstructed = coordinator.run_fixed("reconstruct", recorded_at=LATER)
            self.assertEqual("succeeded", reconstructed.results[0].state)
            self.assertIn("snapshot", reconstructed.results[0].receipt["native"])

        with tempfile.TemporaryDirectory() as directory:
            drifted = ScriptedPort("edge", reconstruction_drift=True)
            coordinator = self._coordinator(directory, [drifted])
            coordinator.run_fixed("prepare", recorded_at=TIME)
            reconstructed = coordinator.run_fixed("reconstruct", recorded_at=LATER)
            self.assertEqual("failed", reconstructed.results[0].state)
            self.assertIn("differs from admission", reconstructed.results[0].detail)

    def test_full_lifecycle_produces_receipts_bundle_and_clean_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ports = [
                ScriptedPort(
                    project,
                    residuals=[
                        ResidualCheck(
                            component=project,
                            subject_id=f"{project}:fixture",
                            status="clean",
                            detail="declared component state is absent or terminal",
                        )
                    ],
                )
                for project in ("link", "edge", "runtime")
            ]
            coordinator = self._coordinator(directory, ports)
            self.assertEqual("ready", coordinator.run_fixed("prepare", recorded_at=TIME).projection.phase)
            self.assertEqual("running", coordinator.run_fixed("start", recorded_at=TIME).projection.phase)
            self.assertEqual("frozen", coordinator.run_fixed("freeze", recorded_at=LATER).projection.phase)
            bundle = coordinator.export(
                str(root / "evidence-bundle"),
                bundle_id="urn:ordivon:security:evidence-bundle:fixture-1",
                recorded_at=LATER,
                attachments=[
                    EvidenceAttachment("components/observer-summary.json", b'{"events":3}\n')
                ],
            )
            self.assertEqual(bundle, verify_evidence_bundle(root / "evidence-bundle"))
            self.assertEqual("ready", coordinator.run_fixed("reset", recorded_at=LATER).projection.phase)
            self.assertEqual("destroyed", coordinator.run_fixed("destroy", recorded_at=LATER).projection.phase)
            report = coordinator.assess_residuals(recorded_at=LATER)
            self.assertEqual("clean", report.classification)
            outcome = coordinator.finalize_infrastructure_outcome(
                recorded_at=LATER,
                evidence_refs=[f"evidence://{bundle.bundle_digest}"],
            )
            self.assertEqual("success", outcome.outcome["classification"])
            operations = outcome.operations.values()
            for operation in ("freeze", "export", "reset", "destroy"):
                receipts = [
                    item
                    for item in operations
                    if item["operation"] == operation and item["state"] == "succeeded"
                ]
                self.assertTrue(receipts, operation)
                self.assertTrue(all(item["receipt"] for item in receipts))


class BundleTests(unittest.TestCase):
    def test_bundle_is_idempotent_and_tamper_detecting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = CampaignLedger.admit(root / "ledger", manifest(), recorded_at=TIME)
            destination = root / "bundle"
            first = export_evidence_bundle(
                ledger,
                destination,
                bundle_id="urn:ordivon:security:evidence-bundle:idempotent",
            )
            second = export_evidence_bundle(
                ledger,
                destination,
                bundle_id="urn:ordivon:security:evidence-bundle:idempotent",
            )
            self.assertEqual(first, second)
            projection = destination / "campaign/projection.json"
            projection.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(BundleError):
                verify_evidence_bundle(destination)

    def test_attachment_cannot_escape_or_replace_control_files(self) -> None:
        for path in ("../escape", "/absolute", "campaign/events.json", "bundle-seal.json"):
            with self.subTest(path=path):
                with self.assertRaises(BundleError):
                    EvidenceAttachment(path, b"x")

    def test_read_only_clis_verify_real_ledger_and_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = CampaignLedger.admit(root / "ledger", manifest(), recorded_at=TIME)
            ledger.set_phase(
                "destroyed",
                reason="CLI test closes empty admitted fixture",
                recorded_at=LATER,
            )
            export_evidence_bundle(
                ledger,
                root / "bundle",
                bundle_id="urn:ordivon:security:evidence-bundle:cli-test",
            )
            inspected = subprocess.run(
                [
                    sys.executable,
                    "scripts/inspect_campaign_ledger.py",
                    str(root / "ledger"),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, inspected.returncode, inspected.stderr)
            self.assertEqual(
                "destroyed", json.loads(inspected.stdout)["projection"]["phase"]
            )
            verified = subprocess.run(
                [
                    sys.executable,
                    "scripts/verify_evidence_bundle.py",
                    str(root / "bundle"),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertEqual(
                "urn:ordivon:security:evidence-bundle:cli-test",
                json.loads(verified.stdout)["bundle_id"],
            )

    def test_residual_report_round_trip(self) -> None:
        data = manifest()
        report = ResidualReport.create(
            campaign_id=data["campaign"]["id"],
            world_id=data["world"]["id"],
            checks=[
                ResidualCheck(
                    component="link",
                    subject_id="link:observer-history",
                    status="expected_retained",
                    detail="observer history retained outside disposable world",
                )
            ],
        )
        self.assertEqual(report, ResidualReport.from_dict(report.to_dict()))
        self.assertEqual("clean", report.classification)


if __name__ == "__main__":
    unittest.main()
