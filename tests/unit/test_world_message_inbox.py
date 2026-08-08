from __future__ import annotations

import concurrent.futures
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest
from ordivon_security.evaluation.world_message import (
    WorldMessageIdentityConflict,
    WorldMessageInbox,
    WorldMessagePolicyRejected,
    WorldMessageRequestError,
)

SOURCE = "run:w2-message:A"
DESTINATION = "security-world:w2-message:B"
KIND = "station-zero-v3-fact-claim"


def provenance() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.game.station-zero-v3-message-provenance",
        "sourceWorldId": SOURCE,
        "turnBatchId": "turn-batch:w2-message:1",
        "turnRecordDigest": "sha256:" + "1" * 64,
        "worldEventId": "world-event:w2-message:1",
        "worldEventDigest": "sha256:" + "2" * 64,
        "factId": "fact:w2-message:1",
        "factDigest": "sha256:" + "3" * 64,
        "sourceFactionId": "rescue",
        "visibleToSourceFaction": True,
    }


def payload(*, state: str = "unstable") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.game.station-zero-v3-fact-claim",
        "fact": {"factId": "fact:w2-message:1", "kind": "system_changed", "state": state},
        "sourceEpistemicStatus": "observed-in-source-world",
    }


def issuance(
    *,
    message_id: str = "message:w2-message:1",
    destination_world_id: str = DESTINATION,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    p = provenance()
    b = payload() if body is None else body
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.message-issuance-receipt",
        "messageId": message_id,
        "sourceWorldId": SOURCE,
        "destinationWorldId": destination_world_id,
        "messageKind": KIND,
        "provenanceDigest": canonical_digest(p),
        "payloadDigest": canonical_digest(b),
        "sourceOccurrenceId": "message-source:w2-message:fact-1",
        "sourceOccurrenceDigest": canonical_digest({"factId": "fact:w2-message:1"}),
        "authority": {
            "authorityId": "ordivon.game.station-zero-v3:run:w2-message:A:faction:rescue",
            "mechanism": "station-zero-v3-visible-retained-fact.v1",
            "evidence": {"factId": "fact:w2-message:1", "retainedReplayVerified": True},
        },
    }


def plan(
    *,
    message_id: str = "message:w2-message:1",
    destination_world_id: str = DESTINATION,
    body: dict[str, object] | None = None,
) -> dict[str, object]:
    b = payload() if body is None else body
    issue = issuance(message_id=message_id, destination_world_id=destination_world_id, body=b)
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.prepared-message-delivery",
        "messageId": message_id,
        "sourceWorldId": SOURCE,
        "destinationWorldId": destination_world_id,
        "messageKind": KIND,
        "provenanceDigest": canonical_digest(provenance()),
        "payloadDigest": canonical_digest(b),
        "sourceIssuance": issue,
    }


def deliver_request(
    *, message_id: str = "message:w2-message:1", body: dict[str, object] | None = None
) -> dict[str, object]:
    b = payload() if body is None else body
    prepared = plan(message_id=message_id, body=b)
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.message-delivery-destination-request",
        "operation": "deliver",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
        "provenance": provenance(),
        "payload": b,
    }


def reconcile_request(prepared: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "ordivon.world.message-delivery-destination-request",
        "operation": "reconcile",
        "plan": prepared,
        "planDigest": canonical_digest(prepared),
    }


class WorldMessageInboxTests(unittest.TestCase):
    def create_inbox(self, root: Path) -> WorldMessageInbox:
        return WorldMessageInbox(
            root,
            destination_world_id=DESTINATION,
            allowed_source_world_ids=(SOURCE,),
            allowed_message_kinds=(KIND,),
        )

    def test_exact_retry_retains_one_message_specific_admission_without_truth_promotion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            request = deliver_request()
            first = inbox.handle(request)
            second = inbox.handle(request)
            self.assertEqual(first, second)
            self.assertEqual(first["status"], "delivered")
            evidence = first["receipt"]["destinationEvidence"]
            self.assertTrue(evidence["messageSpecificAdmission"])
            self.assertTrue(evidence["sourceIssuanceStructurallyBound"])
            self.assertEqual(evidence["sourceAuthorityAuthentication"], "caller-trust-boundary")
            self.assertEqual(evidence["classification"], "management")
            self.assertFalse(evidence["knowledgePromoted"])
            self.assertFalse(evidence["worldTruthPromoted"])
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 1)

    def test_reconcile_without_admission_proves_exact_original_retry_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            prepared = plan()
            response = inbox.handle(reconcile_request(prepared))
            self.assertEqual(response["status"], "not_committed")
            self.assertTrue(response["evidence"]["exclusiveMessageLockHeldAtObservation"])
            self.assertTrue(response["evidence"]["exactOriginalRetrySafe"])
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 0)

    def test_same_message_identity_with_changed_payload_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            inbox.handle(deliver_request())
            with self.assertRaises(WorldMessageIdentityConflict):
                inbox.handle(deliver_request(body=payload(state="stable")))
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 1)

    def test_source_issuance_is_required_and_must_match_exact_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            missing = deliver_request()
            missing["plan"] = {
                key: value for key, value in missing["plan"].items() if key != "sourceIssuance"
            }
            missing["planDigest"] = canonical_digest(missing["plan"])
            with self.assertRaises(WorldMessageRequestError):
                inbox.handle(missing)
            changed = deliver_request()
            changed["plan"]["sourceIssuance"] = {
                **changed["plan"]["sourceIssuance"],
                "destinationWorldId": "security-world:forged",
            }
            changed["planDigest"] = canonical_digest(changed["plan"])
            with self.assertRaisesRegex(WorldMessageRequestError, "destinationWorldId differs"):
                inbox.handle(changed)
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 0)

    def test_destination_source_and_kind_policy_fail_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inbox = self.create_inbox(Path(directory))
            wrong_destination = deliver_request()
            wrong_destination["plan"] = plan(destination_world_id="security-world:other")
            wrong_destination["planDigest"] = canonical_digest(wrong_destination["plan"])
            with self.assertRaises(WorldMessagePolicyRejected):
                inbox.handle(wrong_destination)
            wrong_source = deliver_request()
            wrong_source["plan"] = {**wrong_source["plan"], "sourceWorldId": "run:other"}
            wrong_source["plan"]["sourceIssuance"] = {
                **wrong_source["plan"]["sourceIssuance"],
                "sourceWorldId": "run:other",
            }
            wrong_source["planDigest"] = canonical_digest(wrong_source["plan"])
            with self.assertRaises(WorldMessagePolicyRejected):
                inbox.handle(wrong_source)
            wrong_kind = deliver_request()
            wrong_kind["plan"] = {**wrong_kind["plan"], "messageKind": "other-kind"}
            wrong_kind["plan"]["sourceIssuance"] = {
                **wrong_kind["plan"]["sourceIssuance"],
                "messageKind": "other-kind",
            }
            wrong_kind["planDigest"] = canonical_digest(wrong_kind["plan"])
            with self.assertRaises(WorldMessagePolicyRejected):
                inbox.handle(wrong_kind)
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 0)

    def test_concurrent_exact_delivery_serializes_per_message_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = deliver_request()

            def run_once() -> dict[str, object]:
                return self.create_inbox(root).handle(request)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                responses = list(pool.map(lambda _index: run_once(), range(16)))
            self.assertTrue(all(response == responses[0] for response in responses))
            inbox = self.create_inbox(root)
            self.assertEqual(len(list(inbox.messages_root.glob("*.json"))), 1)
            self.assertEqual(len(list(inbox.locks_root.glob("*.lock"))), 1)

    def test_cli_emits_message_receipt_without_importing_ordivon_world(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.run(
                [
                    "/usr/bin/python",
                    "-m",
                    "ordivon_security.cli_world_message",
                    "--root",
                    directory,
                    "--destination-world-id",
                    DESTINATION,
                    "--allow-source-world",
                    SOURCE,
                    "--allow-message-kind",
                    KIND,
                ],
                input=json.dumps(deliver_request()),
                text=True,
                capture_output=True,
                env={"PYTHONPATH": "src"},
                check=True,
            )
            response = json.loads(process.stdout)
            self.assertEqual(response["status"], "delivered")
            self.assertEqual(response["receipt"]["kind"], "ordivon.world.message-delivery-receipt")


if __name__ == "__main__":
    unittest.main()
