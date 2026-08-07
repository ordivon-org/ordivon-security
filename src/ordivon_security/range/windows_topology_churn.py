from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, validate_json

from .model import RangeSessionSpec
from .protocol import RangeSessionInstance
from .windows_fabric import (
    WindowsFabricRangeConfig,
    WindowsIsolatedFabricRange,
    _digest,
    _FabricRun,
    _run,
    _stop_process,
)

_RANGE_ID = "range:windows-topology-churn-s6"
_PEER_B_ADDRESS = "10.253.70.4"
_PEER_B_BANNER = "ORDIVON-S6-PEER-B"


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

    def __init__(self, config: WindowsFabricRangeConfig) -> None:
        super().__init__(config)

    @property
    def execution_identity(self) -> JsonObject:
        identity = super().execution_identity
        identity["kind"] = "ordivon.security.windows-topology-churn-range"
        identity["implementationRevision"] = "1"
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
        validate_json(identity)
        return identity

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

    def _start_peer_b(self, run: _FabricRun) -> subprocess.Popen[bytes]:
        suffix = run.instance.session_id.encode("utf-8").hex()[-8:]
        fabric_ns = cast(str, run.state["fabricNamespace"])
        bridge_name = cast(str, run.state["bridgeName"])
        peer_ns = f"s6q{suffix}"
        peer_veth = f"q{suffix}"
        fabric_veth = f"w{suffix}"
        run_path = Path(cast(str, run.state["runPath"]))
        created = False
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
            run.state["peerNamespace"] = peer_ns
            run.state["peerVethName"] = peer_veth
            run.state["fabricVethName"] = fabric_veth
            run.state["peerBAddress"] = self.peer_b_address
            run.state["peerBRoutes"] = cast(list[JsonValue], peer_routes)
            return process
        except BaseException:
            if created:
                _run([str(self.config.ip_path), "netns", "del", peer_ns], check=False)
            raise

    def _replace_peer_if_ready(self, run: _FabricRun) -> None:
        if run.state.get("topologyChurnCompleted") is True:
            return
        if run.process.poll() is not None or run.peer_process.poll() is None:
            return
        old_namespace = cast(str, run.state["peerNamespace"])
        old_veth = cast(str, run.state["fabricVethName"])
        self._emit(
            run,
            logical_time=1,
            plane="management",
            source_id="security:s6-topology-controller",
            event_type="fabric.peer-replacement-started",
            payload={
                "peerAAddress": self.peer_address,
                "peerBAddress": self.peer_b_address,
                "qemuRunning": True,
            },
        )
        _run([str(self.config.ip_path), "netns", "del", old_namespace])
        removed = self._snapshot(run, phase="peer-a-removed")
        removed["currentPeerAddress"] = None
        run.state["fabricTruth"] = removed
        history = cast(list[JsonValue], run.state.get("topologyHistory", []))
        history.append(removed)
        run.state["topologyHistory"] = history
        if old_veth in cast(list[JsonValue], removed["portNames"]):
            raise RuntimeError("S6 retired peer port remained attached after namespace deletion")
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
        run.state["topologyChurnCompleted"] = True
        self._emit(
            run,
            logical_time=1,
            plane="world-truth",
            source_id="host:linux-netlink",
            event_type="world.fabric-topology-observed",
            payload=added,
        )
        self._emit(
            run,
            logical_time=1,
            plane="management",
            source_id="security:s6-topology-controller",
            event_type="fabric.peer-replacement-completed",
            payload={
                "peerAAddress": self.peer_address,
                "peerBAddress": self.peer_b_address,
                "qemuRunning": run.process.poll() is None,
            },
        )

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
        self._replace_peer_if_ready(run)
        state = super().inspect(instance)
        state["topologyChurnCompleted"] = run.state.get("topologyChurnCompleted") is True
        state["topologyHistory"] = run.state.get("topologyHistory")
        return state

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        instance = super().create(spec)
        run = self._run_for(instance)
        initial = {
            **cast(JsonObject, run.state["fabricTruth"]),
            "phase": "peer-a-present",
            "currentPeerAddress": self.peer_address,
        }
        validate_json(initial)
        run.state["fabricTruth"] = initial
        run.state["topologyHistory"] = cast(list[JsonValue], [initial])
        self._emit(
            run,
            logical_time=0,
            plane="world-truth",
            source_id="host:linux-netlink",
            event_type="world.fabric-topology-observed",
            payload=initial,
        )
        return instance
