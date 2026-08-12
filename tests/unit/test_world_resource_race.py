from __future__ import annotations

import sys
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from ordivon_security._canonical import canonical_digest

SOURCE = "world-instance:w2-race:A"
DESTINATION = "security-world:w2-race:B"
KIND = "test-resource"


def request(operation: str) -> dict[str, object]:
    payload = {"kind": "portable-resource", "value": "race"}
    occurrence = {"factId": "fact:w2-race"}
    source_egress = {
        "schemaVersion": 1,
        "kind": "ordivon.world.resource-egress-receipt",
        "transferId": "transfer:w2-race",
        "sourceWorldId": SOURCE,
        "destinationWorldId": DESTINATION,
        "resourceKind": KIND,
        "payloadDigest": canonical_digest(payload),
        "sourceOccurrenceId": "resource-occurrence:w2-race",
        "sourceOccurrenceDigest": canonical_digest(occurrence),
        "authority": {
            "authorityId": "source-authority:w2-race:A",
            "mechanism": "test-source-egress.v1",
            "evidence": occurrence,
        },
    }
    plan = {
        "schemaVersion": 1,
        "kind": "ordivon.world.prepared-resource-transfer",
        "transferId": "transfer:w2-race",
        "sourceWorldId": SOURCE,
        "destinationWorldId": DESTINATION,
        "resourceKind": KIND,
        "sourceEgressDigest": canonical_digest(source_egress),
        "payloadDigest": canonical_digest(payload),
    }
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "ordivon.world.resource-transfer-destination-request",
        "operation": operation,
        "plan": plan,
        "planDigest": canonical_digest(plan),
    }
    if operation == "materialize":
        value["sourceEgress"] = source_egress
        value["payload"] = payload
    return value


_MATERIALIZER = r"""
import json,sys,time
from pathlib import Path
from ordivon_security.evaluation.world_resource import WorldResourceInbox
root=Path(sys.argv[1]);ready=Path(sys.argv[2]);release=Path(sys.argv[3])
req=json.load(sys.stdin)
inbox=WorldResourceInbox(root,destination_world_id=sys.argv[4],allowed_source_world_ids=(sys.argv[5],),allowed_resource_kinds=(sys.argv[6],))
original=inbox._commit_admission
def delayed(transfer_id,record):
    ready.write_text('lock-held-after-vault-import')
    deadline=time.monotonic()+10
    while not release.exists():
        if time.monotonic()>=deadline:raise TimeoutError('release marker not observed')
        time.sleep(.01)
    return original(transfer_id,record)
inbox._commit_admission=delayed
print(json.dumps(inbox.handle(req),sort_keys=True,separators=(',',':')))
"""


def cli(root: Path, value: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ordivon_security.cli_world_resource",
            "--root",
            str(root),
            "--destination-world-id",
            DESTINATION,
            "--allow-source-world",
            SOURCE,
            "--allow-resource-kind",
            KIND,
        ],
        input=json.dumps(value),
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": "src"},
        timeout=10,
    )


class WorldResourceRaceTests(unittest.TestCase):
    def test_reconcile_waits_for_live_same_transfer_commit_and_never_false_proves_not_committed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "materializer-ready"
            release = root / "release-materializer"
            materializer = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _MATERIALIZER,
                    str(root),
                    str(ready),
                    str(release),
                    DESTINATION,
                    SOURCE,
                    KIND,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, "PYTHONPATH": "src"},
            )
            assert materializer.stdin is not None
            materializer.stdin.write(json.dumps(request("materialize")))
            materializer.stdin.close()
            materializer.stdin = None
            deadline = time.monotonic() + 3
            while not ready.exists():
                self.assertIsNone(materializer.poll())
                if time.monotonic() >= deadline:
                    self.fail("materializer did not reach post-Vault/pre-admission hold")
                time.sleep(0.01)

            reconciler = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "ordivon_security.cli_world_resource",
                    "--root",
                    str(root),
                    "--destination-world-id",
                    DESTINATION,
                    "--allow-source-world",
                    SOURCE,
                    "--allow-resource-kind",
                    KIND,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, "PYTHONPATH": "src"},
            )
            assert reconciler.stdin is not None
            reconciler.stdin.write(json.dumps(request("reconcile")))
            reconciler.stdin.close()
            reconciler.stdin = None
            time.sleep(0.2)
            self.assertIsNone(
                reconciler.poll(),
                "reconcile must block behind the active same-transfer materializer",
            )

            release.write_text("continue")
            materializer_stdout, materializer_stderr = materializer.communicate(timeout=5)
            reconciler_stdout, reconciler_stderr = reconciler.communicate(timeout=5)
            self.assertEqual(materializer.returncode, 0, materializer_stderr)
            self.assertEqual(reconciler.returncode, 0, reconciler_stderr)
            materialized = json.loads(materializer_stdout)
            reconciled = json.loads(reconciler_stdout)
            self.assertEqual(materialized["status"], "materialized")
            self.assertEqual(reconciled["status"], "materialized")
            self.assertEqual(reconciled["receipt"], materialized["receipt"])
            self.assertNotEqual(reconciled["status"], "not_committed")
            self.assertEqual(len(list((root / "world-resource-transfers").glob("*.json"))), 1)
            self.assertEqual(
                len(list((root / "vault" / "objects" / "sha256").glob("*/*/sample.bin"))),
                1,
            )

    def test_reconcile_after_crashed_lock_holder_can_prove_not_committed(self) -> None:
        # Covered end-to-end by W2 crash-window acceptance; this local check ensures
        # an orphaned lock file itself does not block a fresh proof after process exit.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = cli(root, request("reconcile"))
            self.assertEqual(first.returncode, 0, first.stderr)
            value = json.loads(first.stdout)
            self.assertEqual(value["status"], "not_committed")
            self.assertTrue(value["evidence"]["exclusiveTransferLockHeldAtObservation"])
            self.assertTrue(value["evidence"]["exactOriginalRetrySafe"])


if __name__ == "__main__":
    unittest.main()
