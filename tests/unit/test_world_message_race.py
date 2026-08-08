from __future__ import annotations

import concurrent.futures
import tempfile
import threading
import unittest
from pathlib import Path

from ordivon_security.evaluation.world_message import WorldMessageInbox
from tests.unit.test_world_message_inbox import (
    DESTINATION,
    KIND,
    SOURCE,
    deliver_request,
    plan,
    reconcile_request,
)


class _BlockingCommitInbox(WorldMessageInbox):
    def __init__(self, *args, entered: threading.Event, release: threading.Event, **kwargs):
        super().__init__(*args, **kwargs)
        self.entered = entered
        self.release = release

    def _commit_admission(self, message_id, record):
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("test did not release live Message commit")
        return super()._commit_admission(message_id, record)


def inbox(root: Path) -> WorldMessageInbox:
    return WorldMessageInbox(
        root,
        destination_world_id=DESTINATION,
        allowed_source_world_ids=(SOURCE,),
        allowed_message_kinds=(KIND,),
    )


class WorldMessageRaceTests(unittest.TestCase):
    def test_reconcile_waits_for_live_same_message_commit_and_never_false_proves_not_committed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entered = threading.Event()
            release = threading.Event()
            writer = _BlockingCommitInbox(
                root,
                destination_world_id=DESTINATION,
                allowed_source_world_ids=(SOURCE,),
                allowed_message_kinds=(KIND,),
                entered=entered,
                release=release,
            )
            reader = inbox(root)
            request = deliver_request()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                delivery = pool.submit(writer.handle, request)
                self.assertTrue(entered.wait(timeout=5))
                reconciliation = pool.submit(reader.handle, reconcile_request(plan()))
                # Reader must be blocked on the same Message lock while writer has not committed.
                with self.assertRaises(concurrent.futures.TimeoutError):
                    reconciliation.result(timeout=0.1)
                release.set()
                delivered = delivery.result(timeout=5)
                observed = reconciliation.result(timeout=5)
            self.assertEqual(delivered["status"], "delivered")
            self.assertEqual(observed, delivered)
            self.assertNotEqual(observed["status"], "not_committed")
            self.assertEqual(len(list(reader.messages_root.glob("*.json"))), 1)

    def test_reconcile_after_lock_holder_exits_without_admission_can_prove_not_committed(
        self,
    ) -> None:
        import fcntl
        import multiprocessing
        import os

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reader = inbox(root)
            message_id = plan()["messageId"]
            lock_path = reader._lock_path(message_id)

            def hold_then_exit(path: str) -> None:
                fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                os._exit(0)

            process = multiprocessing.Process(target=hold_then_exit, args=(str(lock_path),))
            process.start()
            process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)
            response = reader.handle(reconcile_request(plan()))
            self.assertEqual(response["status"], "not_committed")
            self.assertTrue(response["evidence"]["exclusiveMessageLockHeldAtObservation"])
            self.assertTrue(response["evidence"]["exactOriginalRetrySafe"])
            self.assertEqual(len(list(reader.messages_root.glob("*.json"))), 0)


if __name__ == "__main__":
    unittest.main()
