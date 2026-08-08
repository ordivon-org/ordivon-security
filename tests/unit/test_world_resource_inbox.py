from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_bytes, canonical_digest
from ordivon_security.evaluation.world_resource import (
    WorldResourceIdentityConflict,
    WorldResourceInbox,
    WorldResourcePolicyRejected,
)

SOURCE = "game-run:w2:A"
DESTINATION = "security-world:w2:B"
KIND = "station-zero-v3-item"


def payload(*, item_id: str = "research-core") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.w2.portable-resource",
        "itemId": item_id,
    }


def evidence() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.w2.source-evidence",
        "factId": "fact:w2:item-extracted",
    }


def plan(
    *,
    transfer_id: str = "transfer:w2:research-core",
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    resource = payload() if body is None else body
    source = evidence()
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.prepared-resource-transfer",
        "transferId": transfer_id,
        "sourceWorldId": SOURCE,
        "destinationWorldId": DESTINATION,
        "resourceKind": KIND,
        "sourceEvidenceDigest": canonical_digest(source),
        "payloadDigest": canonical_digest(resource),
    }


def materialize_request(
    *,
    transfer_id: str = "transfer:w2:research-core",
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    resource = payload() if body is None else body
    prepared = plan(transfer_id=transfer_id, body=resource)
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.resource-transfer-destination-request",
        "operation": "materialize",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
        "sourceEvidence": evidence(),
        "payload": resource,
    }


def reconcile_request(prepared: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.resource-transfer-destination-request",
        "operation": "reconcile",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
    }


class WorldResourceInboxTests(unittest.TestCase):
    def create_inbox(self, root: Path) -> WorldResourceInbox:
        return WorldResourceInbox(
            root,
            destination_world_id=DESTINATION,
            allowed_source_world_ids=(SOURCE,),
            allowed_resource_kinds=(KIND,),
        )

    def test_materialize_exact_retry_retains_one_transfer_specific_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            request = materialize_request()
            first = inbox.handle(request)
            second = inbox.handle(request)
            self.assertEqual(first, second)
            self.assertEqual(first["status"], "materialized")
            receipt = first["receipt"]
            self.assertTrue(receipt["destinationEvidence"]["transferSpecificAdmission"])
            self.assertFalse(receipt["destinationEvidence"]["currentPresenceImplied"])
            self.assertEqual(receipt["payloadDigest"], request["plan"]["payloadDigest"])
            self.assertEqual(len(list(inbox.transfers_root.glob("*.json"))), 1)
            self.assertEqual(len(list(inbox.vault.objects_root.glob("*/*/sample.bin"))), 1)

    def test_preexisting_same_cas_payload_does_not_forge_transfer_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            prepared = plan()
            sample = inbox.vault.import_bytes(
                canonical_bytes(payload()),
                media_type="application/vnd.ordivon.world.resource+json",
                original_name="preexisting.json",
            )
            self.assertEqual(sample.sha256, prepared["payloadDigest"])
            reconciled = inbox.handle(reconcile_request(prepared))
            self.assertEqual(reconciled["status"], "not_committed")
            self.assertTrue(reconciled["evidence"]["exclusiveTransferLockHeldAtObservation"])
            self.assertTrue(reconciled["evidence"]["exactOriginalRetrySafe"])
            self.assertEqual(len(list(inbox.transfers_root.glob("*.json"))), 0)

    def test_same_transfer_identity_with_changed_meaning_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            inbox.handle(materialize_request())
            with self.assertRaises(WorldResourceIdentityConflict):
                inbox.handle(materialize_request(body=payload(item_id="medkit")))
            self.assertEqual(len(list(inbox.transfers_root.glob("*.json"))), 1)

    def test_historical_admission_receipt_survives_current_sample_purge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            request = materialize_request()
            committed = inbox.handle(request)
            sample_value = committed["receipt"]["destinationEvidence"]["sample"]
            from ordivon_security.evaluation.models import SampleIdentity

            sample = SampleIdentity(
                sample_id=sample_value["sampleId"],
                sha256=sample_value["sha256"],
                byte_length=sample_value["byteLength"],
                media_type=sample_value["mediaType"],
                original_name=sample_value["originalName"],
            )
            inbox.vault.purge(sample)
            with self.assertRaises(FileNotFoundError):
                inbox.vault.resolve(sample)
            reconciled = inbox.handle(reconcile_request(request["plan"]))
            self.assertEqual(reconciled, committed)

    def test_concurrent_exact_materialization_serializes_per_transfer_identity(self) -> None:
        import concurrent.futures

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = materialize_request()

            def run_once() -> dict[str, object]:
                return self.create_inbox(root).handle(request)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                responses = list(pool.map(lambda _index: run_once(), range(16)))
            self.assertTrue(all(response == responses[0] for response in responses))
            inbox = self.create_inbox(root)
            self.assertEqual(len(list(inbox.transfers_root.glob("*.json"))), 1)
            self.assertEqual(len(list(inbox.vault.objects_root.glob("*/*/sample.bin"))), 1)
            self.assertEqual(len(list(inbox.locks_root.glob("*.lock"))), 1)

    def test_destination_and_source_policy_fail_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = self.create_inbox(root)
            wrong_destination = materialize_request()
            wrong_destination["plan"] = {
                **wrong_destination["plan"],
                "destinationWorldId": "security-world:other",
            }
            wrong_destination["planDigest"] = canonical_digest(wrong_destination["plan"])
            with self.assertRaises(WorldResourcePolicyRejected):
                inbox.handle(wrong_destination)
            wrong_source = materialize_request()
            wrong_source["plan"] = {
                **wrong_source["plan"],
                "sourceWorldId": "game-run:other",
            }
            wrong_source["planDigest"] = canonical_digest(wrong_source["plan"])
            with self.assertRaises(WorldResourcePolicyRejected):
                inbox.handle(wrong_source)
            self.assertEqual(len(list(inbox.transfers_root.glob("*.json"))), 0)

    def test_cli_emits_wire_receipt_without_importing_ordivon_world(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request = materialize_request()
            process = subprocess.run(
                [
                    "/usr/bin/python",
                    "-m",
                    "ordivon_security.cli_world_resource",
                    "--root",
                    directory,
                    "--destination-world-id",
                    DESTINATION,
                    "--allow-source-world",
                    SOURCE,
                    "--allow-resource-kind",
                    KIND,
                ],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                env={"PYTHONPATH": "src"},
                check=True,
            )
            response = json.loads(process.stdout)
            self.assertEqual(response["status"], "materialized")
            self.assertEqual(response["receipt"]["kind"], "ordivon.world.resource-transfer-receipt")


if __name__ == "__main__":
    unittest.main()
