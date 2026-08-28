from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, validate_json
from ordivon_security.providers.windows_kvm import process_start_time as _process_start_time

from .model import RangeEffectAdmission, RangeSessionSpec
from .protocol import RangeSessionInstance
from .windows_fabric import (
    WindowsFabricRangeConfig,
    WindowsIsolatedFabricRange,
)
from .windows_fabric import (
    WindowsFabricRun as _FabricRun,
)
from .windows_fabric import (
    digest_fabric_path as _digest,
)
from .windows_fabric import (
    run_fabric_command as _run,
)
from .windows_fabric import (
    stop_fabric_process as _stop_process,
)

_RANGE_ID = "range:windows-topology-churn-s6"
_PEER_B_ADDRESS = "10.253.70.4"
_PEER_B_BANNER = "ORDIVON-S6-PEER-B"
_EFFECT_ZONE = "zone:s6-fabric"
_EFFECT_CAPABILITY = "fabric.peer-replacement"
_EFFECT_TYPE = "fabric.replace-peer-a-with-peer-b"
_REPLACEMENT_TRIGGERS = {"backend-owned", "actor-authorized"}


class WindowsTopologyChurnRange(WindowsIsolatedFabricRange):
    """S6: replace one lightweight peer while the Windows Guest remains alive."""

    range_id = _RANGE_ID
    stage_label = "S6"
    namespace_prefix = "s6"
    fixture_id = "ordivon-s6-topology-churn-canary-v1"
    semantic_action = "connect-peer-a-observe-replacement-connect-peer-b-v1"
    guest_address = "10.253.70.2"
    peer_address = "10.253.70.3"
    prefix_length = 24
    peer_port = 48080
    peer_banner = "ORDIVON-S6-PEER-A"
    guest_runner_source_id = "guest:s6-runner"
    guest_canary_source_id = "guest:s6-topology-churn-canary"
    peer_b_address = _PEER_B_ADDRESS
    peer_b_banner = _PEER_B_BANNER

    def __init__(
        self,
        config: WindowsFabricRangeConfig,
        *,
        replacement_trigger: str = "backend-owned",
    ) -> None:
        if replacement_trigger not in _REPLACEMENT_TRIGGERS:
            raise ValueError("S6 replacement trigger is unsupported")
        super().__init__(config)
        self.replacement_trigger = replacement_trigger
        self._controller_stops: dict[str, threading.Event] = {}
        self._controller_threads: dict[str, threading.Thread] = {}

    @property
    def execution_identity(self) -> JsonObject:
        identity = super().execution_identity
        identity["kind"] = "ordivon.security.windows-topology-churn-range"
        identity["implementationRevision"] = "6"
        identity["network"] = {
            "guestAddress": self.guest_address,
            "peerAAddress": self.peer_address,
            "peerBAddress": self.peer_b_address,
            "prefixLength": self.prefix_length,
            "peerPort": self.peer_port,
            "uplink": "absent",
            "fabricL3": "disabled-ipv4-and-ipv6",
            "topologyChange": "peer-a-removed-then-peer-b-added",
        }
        identity["materialization"] = {
            "guest": "windows-kvm",
            "peerA": "linux-network-namespace-process",
            "peerB": "linux-network-namespace-process",
            "fabric": "linux-network-namespace-bridge-tap-veth",
        }
        identity["replacementTrigger"] = self.replacement_trigger
        identity["actorEffect"] = {
            "zoneRef": _EFFECT_ZONE,
            "capability": _EFFECT_CAPABILITY,
            "effectType": _EFFECT_TYPE,
        }
        validate_json(identity)
        return identity

    def _owned_namespace_candidates(self, session_id: str) -> tuple[str, ...]:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        return (f"s6f{token}", f"s6p{token}", f"s6q{token}")

    def _owned_host_link_candidates(self, session_id: str) -> tuple[str, ...]:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        return (f"q{token}", f"w{token}")

    def _ledger_extra(self, spec: RangeSessionSpec, state: JsonObject) -> JsonObject:
        extra = super()._ledger_extra(spec, state)
        extra["topologyPhase"] = state.get("topologyPhase", "peer-a-present")
        extra["currentPeerAddress"] = state.get("currentPeerAddress", self.peer_address)
        extra["ownedHostLinkCandidates"] = list(self._owned_host_link_candidates(spec.session_id))
        return extra

    def _run_ledger_extra(self, run: _FabricRun) -> JsonObject:
        extra = super()._run_ledger_extra(run)
        extra["topologyPhase"] = run.state.get("topologyPhase", "peer-a-present")
        extra["currentPeerAddress"] = run.state.get("currentPeerAddress", self.peer_address)
        extra["actorReplacementRequest"] = deepcopy(run.state.get("actorReplacementRequest"))
        extra["actorReplacementReceipt"] = deepcopy(run.state.get("actorReplacementReceipt"))
        extra["ownedHostLinkCandidates"] = list(
            self._owned_host_link_candidates(run.instance.session_id)
        )
        return extra

    def _initial_fabric_truth(self, state: JsonObject) -> JsonObject:
        initial = {
            **super()._initial_fabric_truth(state),
            "phase": "peer-a-present",
            "currentPeerAddress": self.peer_address,
        }
        state["topologyPhase"] = "peer-a-present"
        state["currentPeerAddress"] = self.peer_address
        validate_json(initial)
        return initial

    def _persist_running_state(self, run: _FabricRun) -> None:
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        self.machine_provider.persist_state(
            instance_id=run.instance.instance_id,
            generation=generation,
            state=run.state,
            phase="executing",
            extra=self._run_ledger_extra(run),
        )

    def _snapshot(self, run: _FabricRun, *, phase: str) -> JsonObject:
        fabric_ns = cast(str, run.state["fabricNamespace"])
        bridge_name = cast(str, run.state["bridgeName"])
        bridge_state = json.loads(
            _run(
                [
                    str(self.config.ip_path),
                    "-n",
                    fabric_ns,
                    "-j",
                    "addr",
                    "show",
                    bridge_name,
                ]
            ).stdout
        )[0]
        routes = json.loads(
            _run([str(self.config.ip_path), "-n", fabric_ns, "-j", "route"]).stdout or "[]"
        )
        ports = json.loads(
            _run(
                [
                    str(self.config.ip_path),
                    "netns",
                    "exec",
                    fabric_ns,
                    str(self.config.bridge_path),
                    "-j",
                    "link",
                    "show",
                    "master",
                    bridge_name,
                ]
            ).stdout
        )
        if bridge_state.get("addr_info") != []:
            raise RuntimeError("S6 fabric bridge unexpectedly acquired an L3 address")
        if routes:
            raise RuntimeError("S6 fabric namespace unexpectedly acquired a route")
        snapshot: JsonObject = {
            "phase": phase,
            "bridgeL3Addresses": 0,
            "fabricRoutes": routes,
            "bridgePorts": cast(list[JsonValue], ports),
            "portNames": cast(list[JsonValue], [str(item.get("ifname")) for item in ports]),
            "externalRouteAbsent": True,
        }
        validate_json(snapshot)
        return snapshot

    def _wait_for_port_absent(
        self,
        run: _FabricRun,
        port_name: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> JsonObject:
        deadline = time.monotonic() + timeout_seconds
        last: JsonObject | None = None
        while True:
            last = self._snapshot(run, phase="peer-a-removal-pending")
            if port_name not in cast(list[JsonValue], last["portNames"]):
                last["phase"] = "peer-a-removed"
                validate_json(last)
                return last
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "S6 retired peer port remained attached past the topology convergence bound"
                )
            time.sleep(0.05)

    def _start_peer_b(self, run: _FabricRun) -> subprocess.Popen[bytes]:
        suffix = hashlib.sha256(run.instance.session_id.encode("utf-8")).hexdigest()[:8]
        fabric_ns = cast(str, run.state["fabricNamespace"])
        bridge_name = cast(str, run.state["bridgeName"])
        peer_ns = f"s6q{suffix}"
        peer_veth = f"q{suffix}"
        fabric_veth = f"w{suffix}"
        run_path = Path(cast(str, run.state["runPath"]))
        created = False
        process: subprocess.Popen[bytes] | None = None
        try:
            _run([str(self.config.ip_path), "netns", "add", peer_ns])
            created = True
            for key in ("all", "default"):
                _run(
                    [
                        str(self.config.ip_path),
                        "netns",
                        "exec",
                        peer_ns,
                        str(self.config.sysctl_path),
                        "-q",
                        "-w",
                        f"net.ipv6.conf.{key}.disable_ipv6=1",
                    ]
                )
            _run(
                [
                    str(self.config.ip_path),
                    "link",
                    "add",
                    peer_veth,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    fabric_veth,
                ]
            )
            _run([str(self.config.ip_path), "link", "set", peer_veth, "netns", peer_ns])
            _run([str(self.config.ip_path), "link", "set", fabric_veth, "netns", fabric_ns])
            _run(
                [
                    str(self.config.ip_path),
                    "-n",
                    fabric_ns,
                    "link",
                    "set",
                    fabric_veth,
                    "master",
                    bridge_name,
                ]
            )
            _run([str(self.config.ip_path), "-n", fabric_ns, "link", "set", fabric_veth, "up"])
            _run([str(self.config.ip_path), "-n", peer_ns, "link", "set", "lo", "up"])
            _run([str(self.config.ip_path), "-n", peer_ns, "link", "set", peer_veth, "up"])
            _run(
                [
                    str(self.config.ip_path),
                    "-n",
                    peer_ns,
                    "addr",
                    "add",
                    f"{self.peer_b_address}/{self.prefix_length}",
                    "dev",
                    peer_veth,
                ]
            )
            peer_routes = json.loads(
                _run([str(self.config.ip_path), "-n", peer_ns, "-j", "route"]).stdout or "[]"
            )
            if any(item.get("dst") == "default" for item in peer_routes):
                raise RuntimeError("S6 replacement peer unexpectedly has a default route")
            stdout_handle = (run_path / "peer-b.stdout.log").open("xb")
            stderr_handle = (run_path / "peer-b.stderr.log").open("xb")
            script = (
                "import socket; "
                f"s=socket.socket(); s.settimeout(300); "
                f"s.bind(('{self.peer_b_address}',{self.peer_port})); "
                "s.listen(1); c,a=s.accept(); "
                f"c.sendall({(self.peer_b_banner + chr(10)).encode()!r}); c.close(); s.close()"
            )
            process = subprocess.Popen(
                [
                    str(self.config.ip_path),
                    "netns",
                    "exec",
                    peer_ns,
                    str(self.config.machine.setpriv_path),
                    "--reuid",
                    self.config.machine.run_user,
                    "--regid",
                    self.config.machine.run_group,
                    "--init-groups",
                    "--",
                    str(self.config.python_path),
                    "-c",
                    script,
                ],
                stdout=stdout_handle,
                stderr=stderr_handle,
            )
            stdout_handle.close()
            stderr_handle.close()
            time.sleep(0.25)
            exit_code = process.poll()
            if exit_code is not None and exit_code != 0:
                stderr_path = run_path / "peer-b.stderr.log"
                detail = stderr_path.read_text(encoding="utf-8", errors="replace")[:2048]
                raise RuntimeError(
                    f"S6 replacement peer failed during startup: exit={exit_code}; "
                    f"stderr={detail!r}"
                )
            if exit_code == 0:
                peer_pid = 0
                peer_start_time = None
            else:
                peer_pid = process.pid
                peer_start_time = _process_start_time(peer_pid)
                if peer_start_time is None:
                    raise RuntimeError(
                        "S6 live replacement peer process identity was not observable"
                    )
            run.state["peerNamespace"] = peer_ns
            run.state["peerVethName"] = peer_veth
            run.state["fabricVethName"] = fabric_veth
            run.state["peerPid"] = peer_pid
            run.state["peerStartTime"] = peer_start_time
            run.state["peerBAddress"] = self.peer_b_address
            run.state["peerBRoutes"] = cast(list[JsonValue], peer_routes)
            return process
        except BaseException:
            _stop_process(process)
            if created:
                _run([str(self.config.ip_path), "netns", "del", peer_ns], check=False)
            raise

    def _replace_peer_if_ready(self, run: _FabricRun) -> bool:
        with run.lock:
            if run.state.get("topologyChurnCompleted") is True or run.process.poll() is not None:
                return False
            peer_a_exit = run.peer_process.poll()
            if peer_a_exit is None:
                return False
            run.state["peerAExitCode"] = peer_a_exit
            if peer_a_exit != 0:
                run.state["topologyControllerError"] = {
                    "reason": "peer-a-exited-nonzero",
                    "exitCode": peer_a_exit,
                }
                self._emit(
                    run,
                    logical_time=1,
                    plane="management",
                    source_id="security:s6-topology-controller",
                    event_type="fabric.peer-a-failed",
                    payload={"exitCode": peer_a_exit, "qemuRunning": True},
                )
                return False
            if (
                self.replacement_trigger == "actor-authorized"
                and run.state.get("actorReplacementRequest") is None
            ):
                return False
            old_namespace = cast(str, run.state["peerNamespace"])
            old_veth = cast(str, run.state["fabricVethName"])
            request_binding = run.state.get("actorReplacementRequest")
            started_payload: JsonObject = {
                "peerAAddress": self.peer_address,
                "peerAExitCode": peer_a_exit,
                "peerBAddress": self.peer_b_address,
                "qemuRunning": True,
                "replacementTrigger": self.replacement_trigger,
            }
            if isinstance(request_binding, dict):
                started_payload["effectRequestId"] = request_binding.get("requestId")
                started_payload["effectId"] = request_binding.get("effectId")
                started_payload["admissionDigest"] = request_binding.get("admissionDigest")
            self._emit(
                run,
                logical_time=1,
                plane="management",
                source_id="security:s6-topology-controller",
                event_type="fabric.peer-replacement-started",
                payload=started_payload,
            )
            _run([str(self.config.ip_path), "netns", "del", old_namespace])
            removed = self._wait_for_port_absent(run, old_veth)
            run.state["peerNamespace"] = None
            run.state["peerVethName"] = None
            run.state["fabricVethName"] = None
            run.state["peerPid"] = 0
            run.state["peerStartTime"] = None
            run.state["topologyPhase"] = "peer-a-removed"
            run.state["currentPeerAddress"] = None
            removed["currentPeerAddress"] = None
            run.state["fabricTruth"] = removed
            history = cast(list[JsonValue], run.state.get("topologyHistory", []))
            history.append(removed)
            run.state["topologyHistory"] = history
            self._persist_running_state(run)
            self._emit(
                run,
                logical_time=1,
                plane="world-truth",
                source_id="host:linux-netlink",
                event_type="world.fabric-topology-observed",
                payload=removed,
            )
            peer_b = self._start_peer_b(run)
            run.peer_process = peer_b
            added = self._snapshot(run, phase="peer-b-present")
            tap_name = cast(str, run.state["tapName"])
            new_veth = cast(str, run.state["fabricVethName"])
            if set(cast(list[str], added["portNames"])) != {tap_name, new_veth}:
                raise RuntimeError(
                    "S6 replacement topology differs from the declared TAP plus peer-B set"
                )
            added["currentPeerAddress"] = self.peer_b_address
            added["peerRoutes"] = cast(list[JsonValue], run.state["peerBRoutes"])
            run.state["fabricTruth"] = added
            history = cast(list[JsonValue], run.state.get("topologyHistory", []))
            history.append(added)
            run.state["topologyHistory"] = history
            run.state["topologyPhase"] = "peer-b-present"
            run.state["currentPeerAddress"] = self.peer_b_address
            run.state["topologyChurnCompleted"] = True
            self._persist_running_state(run)
            self._emit(
                run,
                logical_time=1,
                plane="world-truth",
                source_id="host:linux-netlink",
                event_type="world.fabric-topology-observed",
                payload=added,
            )
            completed_payload: JsonObject = {
                "peerAAddress": self.peer_address,
                "peerBAddress": self.peer_b_address,
                "qemuRunning": run.process.poll() is None,
                "replacementTrigger": self.replacement_trigger,
            }
            if isinstance(request_binding, dict):
                completed_payload["effectRequestId"] = request_binding.get("requestId")
                completed_payload["effectId"] = request_binding.get("effectId")
                completed_payload["admissionDigest"] = request_binding.get("admissionDigest")
            self._emit(
                run,
                logical_time=1,
                plane="management",
                source_id="security:s6-topology-controller",
                event_type="fabric.peer-replacement-completed",
                payload=completed_payload,
            )
            return True

    def request_peer_replacement(
        self,
        instance: RangeSessionInstance,
        admission: RangeEffectAdmission,
    ) -> JsonObject:
        """Bind one admitted C1 Actor request to the existing S6 replacement effect.

        This method consumes Security admission; it does not decide authority itself and its
        receipt does not claim that the physical topology has changed.
        """

        if self.replacement_trigger != "actor-authorized":
            raise RuntimeError("S6 backend-owned profile does not consume Actor effect requests")
        if not admission.admitted:
            raise ValueError("S6 Actor-requested replacement requires admitted Security authority")
        if admission.zone_ref != _EFFECT_ZONE:
            raise ValueError("S6 Actor-requested replacement requires the fabric zone")
        if admission.capability != _EFFECT_CAPABILITY:
            raise ValueError("S6 Actor-requested replacement requires peer-replacement capability")
        if admission.effect_type != _EFFECT_TYPE:
            raise ValueError("S6 Actor-requested replacement effect type is unsupported")

        run = self._run_for(instance)
        effect_id = f"range-effect:{admission.request_digest.removeprefix('sha256:')[:24]}"
        binding: JsonObject = {
            "requestId": admission.request_id,
            "requestDigest": admission.request_digest,
            "admissionDigest": admission.digest,
            "authorityId": admission.authority_id,
            "authorityDigest": admission.authority_digest,
            "actorId": admission.actor_id,
            "zoneRef": admission.zone_ref,
            "capability": admission.capability,
            "effectType": admission.effect_type,
            "effectId": effect_id,
        }
        receipt: JsonObject = {
            "effectId": effect_id,
            "requestId": admission.request_id,
            "admissionDigest": admission.digest,
            "status": "accepted-pending-execution",
            "worldEffectVerified": False,
        }
        with run.lock:
            existing = run.state.get("actorReplacementRequest")
            if existing is not None:
                if existing != binding:
                    raise ValueError("S6 replacement effect is already bound to another request")
                existing_receipt = run.state.get("actorReplacementReceipt")
                if not isinstance(existing_receipt, dict):
                    raise RuntimeError("S6 replacement request binding is missing its receipt")
                return cast(JsonObject, existing_receipt)
            run.state["actorReplacementRequest"] = binding
            run.state["actorReplacementReceipt"] = receipt
            self._persist_running_state(run)
            self._emit(
                run,
                logical_time=1,
                plane="management",
                source_id="security:s6-topology-controller",
                event_type="fabric.peer-replacement-request-bound",
                payload=receipt,
            )
            return receipt

    def _controller_loop(self, run: _FabricRun, stop: threading.Event) -> None:
        while not stop.wait(0.1):
            if run.state.get("topologyChurnCompleted") is True or run.process.poll() is not None:
                return
            peer_exit = run.peer_process.poll()
            if peer_exit is None:
                continue
            if (
                peer_exit == 0
                and self.replacement_trigger == "actor-authorized"
                and run.state.get("actorReplacementRequest") is None
            ):
                continue
            try:
                changed = self._replace_peer_if_ready(run)
            except BaseException as error:
                with run.lock:
                    run.state["topologyControllerError"] = {
                        "reason": "replacement-failed",
                        "errorType": type(error).__name__,
                        "errorMessage": str(error),
                    }
                    self._emit(
                        run,
                        logical_time=1,
                        plane="management",
                        source_id="security:s6-topology-controller",
                        event_type="fabric.peer-replacement-failed",
                        payload=cast(JsonObject, run.state["topologyControllerError"]),
                    )
                return
            if changed or peer_exit != 0:
                return

    def _start_controller(self, run: _FabricRun) -> None:
        stop = threading.Event()
        thread = threading.Thread(
            target=self._controller_loop,
            args=(run, stop),
            name=f"ordivon-s6-topology-{run.instance.instance_id.rsplit(':', 1)[-1]}",
            daemon=True,
        )
        self._controller_stops[run.instance.instance_id] = stop
        self._controller_threads[run.instance.instance_id] = thread
        thread.start()

    def _stop_controller(self, instance_id: str) -> None:
        stop = self._controller_stops.pop(instance_id, None)
        thread = self._controller_threads.pop(instance_id, None)
        if stop is not None:
            stop.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("S6 topology controller did not stop before Range closure")

    def _record_sensor(self, run: _FabricRun) -> JsonObject:
        if run.sensor_recorded:
            return run.sensor_observation or {}
        run.sensor_recorded = True
        _stop_process(run.capture_process)
        pcap = Path(cast(str, run.state["pcapPath"]))
        lines: list[str] = []
        pcap_digest: str | None = None
        if pcap.is_file():
            pcap_digest = _digest(pcap)
            output = _run(
                [str(self.config.tcpdump_path), "-nn", "-r", str(pcap)], check=False
            ).stdout
            lines = [
                line
                for line in output.splitlines()
                if line.strip() and not line.startswith("reading from file ")
            ]
        peer_a = any(self.guest_address in line and self.peer_address in line for line in lines)
        peer_b = any(self.guest_address in line and self.peer_b_address in line for line in lines)
        observation: JsonObject = {
            "authority": "external-packet-sensor-not-world-truth",
            "pcapDigest": pcap_digest,
            "packetLineCount": len(lines),
            "peerATrafficObserved": peer_a,
            "peerBTrafficObserved": peer_b,
            "matchedChallengeTraffic": peer_a and peer_b,
            "sampleLines": cast(list[JsonValue], lines[:40]),
        }
        run.sensor_observation = observation
        self._emit(
            run,
            logical_time=3,
            plane="sensor",
            source_id="sensor:host-tcpdump",
            event_type="sensor.topology-churn-traffic-observed",
            payload=observation,
        )
        return observation

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        run = self._run_for(instance)
        with run.lock:
            state = super().inspect(instance)
            state["topologyChurnCompleted"] = run.state.get("topologyChurnCompleted") is True
            state["topologyHistory"] = deepcopy(run.state.get("topologyHistory"))
            state["topologyControllerError"] = deepcopy(run.state.get("topologyControllerError"))
            state["replacementTrigger"] = self.replacement_trigger
            peer_a_exit = run.state.get("peerAExitCode")
            if peer_a_exit is None and run.state.get("topologyChurnCompleted") is not True:
                peer_a_exit = run.peer_process.poll()
            state["peerAExitCode"] = peer_a_exit
            state["actorReplacementRequest"] = deepcopy(run.state.get("actorReplacementRequest"))
            state["actorReplacementReceipt"] = deepcopy(run.state.get("actorReplacementReceipt"))
            return state

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        instance = super().create(spec)
        run = self._run_for(instance)
        with run.lock:
            initial = cast(JsonObject, run.state["fabricTruth"])
            run.state["topologyHistory"] = cast(list[JsonValue], [initial])
            run.state["replacementTrigger"] = self.replacement_trigger
        self._persist_running_state(run)
        self._start_controller(run)
        return instance

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        self._stop_controller(instance.instance_id)
        return super().terminate(instance, reason)

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        self._stop_controller(instance.instance_id)
        return super().destroy(instance)
