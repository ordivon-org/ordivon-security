from __future__ import annotations

import hashlib
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ordivon_security.range.model import RangeEffectAdmission, RangeSessionSpec
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
        backend.replacement_trigger = "backend-owned"
        backend._controller_stops = {}
        backend._controller_threads = {}
        return backend

    @staticmethod
    def _admission(
        *,
        admitted: bool = True,
        zone_ref: str = "zone:s6-fabric",
        capability: str = "fabric.peer-replacement",
        effect_type: str = "fabric.replace-peer-a-with-peer-b",
    ) -> RangeEffectAdmission:
        return RangeEffectAdmission(
            request_id="range-effect-request:c1-replace-peer",
            request_digest="sha256:" + "3" * 64,
            actor_id="actor:c1-red",
            authority_id="range-authority:c1-red",
            authority_digest="sha256:" + "4" * 64,
            zone_ref=zone_ref,
            capability=capability,
            effect_type=effect_type,
            admitted=admitted,
            reason="admitted" if admitted else "capability-not-granted",
        )

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
            guest_claim={"claim": "peer-a"},
            sensor_observation={"seen": "peer-a"},
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

    def test_inspect_snapshot_is_not_retroactively_mutated(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=0)
        base = object.__new__(WindowsIsolatedFabricRange)
        with (
            patch.object(base, "_run_for", return_value=run),
            patch.object(base, "_record_exit_if_needed", return_value=None),
        ):
            base_snapshot = WindowsIsolatedFabricRange.inspect(base, run.instance)
        with (
            patch.object(backend, "_run_for", return_value=run),
            patch.object(
                WindowsIsolatedFabricRange,
                "inspect",
                return_value={
                    "instanceId": run.instance.instance_id,
                    "running": True,
                    "fabricTruth": run.state["fabricTruth"],
                },
            ),
        ):
            topology_snapshot = backend.inspect(run.instance)

        run.state["fabricTruth"]["phase"] = "future-phase"
        run.state["topologyHistory"].append(
            {"phase": "peer-b-present", "currentPeerAddress": "10.253.70.4"}
        )
        run.state["actorReplacementRequest"] = {"requestId": "future-request"}
        run.guest_claim["claim"] = "future-claim"
        run.sensor_observation["seen"] = "future-sensor"

        self.assertEqual(base_snapshot["fabricTruth"]["phase"], "peer-a-present")
        self.assertEqual(base_snapshot["guestClaim"]["claim"], "peer-a")
        self.assertEqual(base_snapshot["sensorObservation"]["seen"], "peer-a")
        self.assertEqual(len(topology_snapshot["topologyHistory"]), 1)
        self.assertIsNone(topology_snapshot["actorReplacementRequest"])

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

    def test_actor_authorized_mode_does_not_replace_peer_without_request(self) -> None:
        backend = self._backend()
        backend.replacement_trigger = "actor-authorized"
        run = self._run(peer_exit=0)
        with patch("ordivon_security.range.windows_topology_churn._run") as physical_mutation:
            changed = backend._replace_peer_if_ready(run)
        self.assertIs(changed, False)
        physical_mutation.assert_not_called()
        self.assertIsNone(run.state.get("actorReplacementRequest"))
        self.assertEqual(run.state["fabricTruth"]["phase"], "peer-a-present")

    def test_actor_replacement_request_binds_admission_and_exact_replay_is_idempotent(self) -> None:
        backend = self._backend()
        backend.replacement_trigger = "actor-authorized"
        run = self._run(peer_exit=0)
        with (
            patch.object(backend, "_run_for", return_value=run),
            patch.object(backend, "_persist_running_state") as persist,
        ):
            first = backend.request_peer_replacement(run.instance, self._admission())
            event_count = len(run.events)
            second = backend.request_peer_replacement(run.instance, self._admission())
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "accepted-pending-execution")
        self.assertIs(first["worldEffectVerified"], False)
        self.assertEqual(len(run.events), event_count)
        self.assertEqual(run.events[-1].event_type, "fabric.peer-replacement-request-bound")
        persist.assert_called_once()

    def test_actor_replacement_request_rejects_unadmitted_or_wrong_effect_scope(self) -> None:
        backend = self._backend()
        backend.replacement_trigger = "actor-authorized"
        run = self._run(peer_exit=0)
        with patch.object(backend, "_run_for", return_value=run):
            cases = (
                self._admission(admitted=False),
                self._admission(zone_ref="zone:other"),
                self._admission(capability="fabric.observe"),
                self._admission(effect_type="fabric.add-peer-c"),
            )
            for admission in cases:
                with self.assertRaises(ValueError):
                    backend.request_peer_replacement(run.instance, admission)
        self.assertIsNone(run.state.get("actorReplacementRequest"))

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

    def test_peer_removal_waits_for_host_truth_convergence(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=0)
        snapshots = [
            {
                "phase": "peer-a-removal-pending",
                "portNames": ["tdeadbeef", "vdeadbeef"],
            },
            {
                "phase": "peer-a-removal-pending",
                "portNames": ["tdeadbeef"],
            },
        ]
        with (
            patch.object(backend, "_snapshot", side_effect=snapshots) as snapshot,
            patch("ordivon_security.range.windows_topology_churn.time.sleep") as sleep,
        ):
            observed = backend._wait_for_port_absent(run, "vdeadbeef", timeout_seconds=1.0)
        self.assertEqual(snapshot.call_count, 2)
        sleep.assert_called_once_with(0.05)
        self.assertEqual(observed["phase"], "peer-a-removed")
        self.assertEqual(observed["portNames"], ["tdeadbeef"])

    def test_peer_b_exit_zero_before_identity_sample_has_no_live_process_to_recover(
        self,
    ) -> None:
        backend = self._backend()
        backend.config = SimpleNamespace(
            ip_path=Path("/usr/bin/ip"),
            bridge_path=Path("/usr/bin/bridge"),
            sysctl_path=Path("/usr/bin/sysctl"),
            python_path=Path("/usr/bin/python3"),
            machine=SimpleNamespace(
                setpriv_path=Path("/usr/bin/setpriv"),
                run_user="qemu",
                run_group="qemu",
            ),
        )
        run = self._run(peer_exit=0)
        completed = _Process(0)
        completed.pid = 7777
        with tempfile.TemporaryDirectory() as temporary:
            run.state["runPath"] = temporary

            def command(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                output = "[]" if "route" in arguments else ""
                return subprocess.CompletedProcess(arguments, 0, output, "")

            with (
                patch(
                    "ordivon_security.range.windows_topology_churn._run",
                    side_effect=command,
                ),
                patch(
                    "ordivon_security.range.windows_topology_churn.subprocess.Popen",
                    return_value=completed,
                ),
                patch("ordivon_security.range.windows_topology_churn.time.sleep"),
                patch(
                    "ordivon_security.range.windows_topology_churn._process_start_time"
                ) as process_start_time,
            ):
                returned = backend._start_peer_b(run)

        self.assertIs(returned, completed)
        process_start_time.assert_not_called()
        self.assertEqual(run.state["peerPid"], 0)
        self.assertIsNone(run.state["peerStartTime"])
        self.assertTrue(str(run.state["peerNamespace"]).startswith("s6q"))

    def test_nonzero_peer_a_exit_is_not_promoted_to_topology_change(self) -> None:
        backend = self._backend()
        run = self._run(peer_exit=9)
        with patch("ordivon_security.range.windows_topology_churn._run") as physical_mutation:
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
        self.assertEqual(len(extra["ownedHostLinkCandidates"]), 2)
        self.assertTrue(extra["ownedHostLinkCandidates"][0].startswith("q"))
        self.assertTrue(extra["ownedHostLinkCandidates"][1].startswith("w"))


if __name__ == "__main__":
    unittest.main()
