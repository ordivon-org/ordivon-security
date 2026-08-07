from __future__ import annotations

import hashlib
import subprocess
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ordivon_security.range.model import RangeSessionSpec
from ordivon_security.range.protocol import RangeSessionInstance
from ordivon_security.range.windows_fabric import WindowsIsolatedFabricRange
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange


class _Process:
    def __init__(self, code: int | None) -> None:
        self.code = code
        self.pid = 4242

    def poll(self) -> int | None:
        return self.code


class WindowsTopologyChurnRangeTests(unittest.TestCase):
    def _backend(self) -> WindowsTopologyChurnRange:
        backend = object.__new__(WindowsTopologyChurnRange)
        backend.config = SimpleNamespace(
            ip_path=Path("/usr/bin/ip"),
            canary_path=Path("/tmp/canary.exe"),
            canary_digest="sha256:" + "1" * 64,
        )
        backend._controller_stops = {}
        backend._controller_threads = {}
        return backend

    @staticmethod
    def _run(*, peer_exit: int | None = 0) -> SimpleNamespace:
        instance = RangeSessionInstance(
            instance_id="range-instance:s6-deadbeef",
            session_id="range-session:s6-unit-test",
        )
        return SimpleNamespace(
            instance=instance,
            state={
                "rangeSpecDigest": "sha256:" + "2" * 64,
                "fabricNamespace": "s6fdeadbeef",
                "peerNamespace": "s6pdeadbeef",
                "bridgeName": "bdeadbeef",
                "tapName": "tdeadbeef",
                "peerVethName": "pdeadbeef",
                "fabricVethName": "vdeadbeef",
                "peerPid": 123,
                "peerStartTime": 456,
                "capturePid": 789,
                "captureStartTime": 1011,
                "fabricTruth": {
                    "phase": "peer-a-present",
                    "currentPeerAddress": "10.253.70.3",
                },
                "topologyHistory": [
                    {
                        "phase": "peer-a-present",
                        "currentPeerAddress": "10.253.70.3",
                    }
                ],
            },
            process=_Process(None),
            peer_process=_Process(peer_exit),
            events=[],
            lock=threading.RLock(),
        )

    def test_inspect_is_read_only_with_respect_to_topology_progression(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=0)
        with (
            patch.object(backend, "_run_for", return_value=run),
            patch.object(
                WindowsIsolatedFabricRange,
                "inspect",
                return_value={"instanceId": run.instance.instance_id, "running": True},
            ),
            patch.object(backend, "_replace_peer_if_ready") as replace,
        ):
            result = backend.inspect(run.instance)
        replace.assert_not_called()
        self.assertIs(result["running"], True)
        self.assertIs(result["topologyChurnCompleted"], False)
        self.assertEqual(result["topologyHistory"][0]["phase"], "peer-a-present")

    def test_namespace_candidates_use_full_32_bit_session_hash(self) -> None:
        backend = self._backend()
        session_id = "range-session:s6-1234567890abcdef"
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        self.assertEqual(
            backend._owned_namespace_candidates(session_id),
            (f"s6f{token}", f"s6p{token}", f"s6q{token}"),
        )

    def test_initial_truth_is_phase_aware_without_second_event(self) -> None:
        backend = self._backend()
        state = {
            "fabricTruth": {
                "bridgeL3Addresses": 0,
                "externalRouteAbsent": True,
            }
        }
        truth = backend._initial_fabric_truth(state)
        self.assertEqual(truth["phase"], "peer-a-present")
        self.assertEqual(truth["currentPeerAddress"], "10.253.70.3")
        self.assertEqual(state["topologyPhase"], "peer-a-present")
        self.assertEqual(state["currentPeerAddress"], "10.253.70.3")

    def test_successful_peer_a_exit_persists_removed_and_added_resource_truth(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=0)
        persisted: list[tuple[str, object, object]] = []
        token = hashlib.sha256(run.instance.session_id.encode("utf-8")).hexdigest()[:8]
        peer_b = _Process(None)
        peer_b.pid = 7777

        def start_peer_b(value: SimpleNamespace) -> _Process:
            value.state["peerNamespace"] = f"s6q{token}"
            value.state["peerVethName"] = f"q{token}"
            value.state["fabricVethName"] = f"w{token}"
            value.state["peerPid"] = 7777
            value.state["peerStartTime"] = 8888
            value.state["peerBRoutes"] = []
            return peer_b

        def persist(value: SimpleNamespace) -> None:
            persisted.append(
                (
                    str(value.state.get("topologyPhase")),
                    value.state.get("peerNamespace"),
                    value.state.get("currentPeerAddress"),
                )
            )

        snapshots = [
            {
                "phase": "peer-a-removed",
                "portNames": ["tdeadbeef"],
                "bridgePorts": [],
                "fabricRoutes": [],
                "externalRouteAbsent": True,
            },
            {
                "phase": "peer-b-present",
                "portNames": ["tdeadbeef", f"w{token}"],
                "bridgePorts": [],
                "fabricRoutes": [],
                "externalRouteAbsent": True,
            },
        ]
        with (
            patch(
                "ordivon_security.range.windows_topology_churn._run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            patch.object(backend, "_snapshot", side_effect=snapshots),
            patch.object(backend, "_start_peer_b", side_effect=start_peer_b),
            patch.object(backend, "_persist_running_state", side_effect=persist),
        ):
            changed = backend._replace_peer_if_ready(run)

        self.assertIs(changed, True)
        self.assertEqual(
            persisted,
            [
                ("peer-a-removed", None, None),
                ("peer-b-present", f"s6q{token}", "10.253.70.4"),
            ],
        )
        self.assertEqual(
            [item["phase"] for item in run.state["topologyHistory"]],
            ["peer-a-present", "peer-a-removed", "peer-b-present"],
        )
        self.assertIs(run.state["topologyChurnCompleted"], True)
        self.assertEqual(run.state["peerPid"], 7777)
        self.assertIn(
            "fabric.peer-replacement-completed",
            [event.event_type for event in run.events],
        )

    def test_nonzero_peer_a_exit_is_not_promoted_to_topology_change(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=9)
        with patch(
            "ordivon_security.range.windows_topology_churn._run"
        ) as physical_mutation:
            changed = backend._replace_peer_if_ready(run)
        self.assertIs(changed, False)
        physical_mutation.assert_not_called()
        self.assertEqual(
            run.state["topologyControllerError"],
            {"reason": "peer-a-exited-nonzero", "exitCode": 9},
        )
        self.assertEqual(run.events[-1].event_type, "fabric.peer-a-failed")

    def test_range_ledger_extra_binds_processes_and_all_owned_namespace_candidates(self) -> None:
        backend = self._backend()
        spec = RangeSessionSpec(
            session_id="range-session:s6-unit-test",
            revision="1",
            range_id=backend.range_id,
            actor_ids=(),
        )
        state = {
            "fabricNamespace": "fabric",
            "peerNamespace": "peer",
            "bridgeName": "bridge",
            "tapName": "tap",
            "peerPid": 11,
            "peerStartTime": 22,
            "capturePid": 33,
            "captureStartTime": 44,
            "topologyPhase": "peer-b-present",
            "currentPeerAddress": "10.253.70.4",
        }
        extra = backend._ledger_extra(spec, state)
        self.assertEqual(extra["peerPid"], 11)
        self.assertEqual(extra["capturePid"], 33)
        self.assertEqual(extra["topologyPhase"], "peer-b-present")
        self.assertEqual(extra["currentPeerAddress"], "10.253.70.4")
        self.assertEqual(len(extra["ownedNamespaceCandidates"]), 3)


if __name__ == "__main__":
    unittest.main()
