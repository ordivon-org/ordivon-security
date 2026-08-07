from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, validate_json
from ordivon_security.identity import security_source_identity
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
    _set_owner,
    windows_kvm_machine_base_arguments,
)

from .model import RangeSessionSpec
from .protocol import BackendCheckpoint, PendingRangeEvent, RangeSessionInstance

_RANGE_ID = "range:windows-isolated-fabric-s5"
_RUN_LABEL = "ORDIVON_RUN"
_CANARY_ID = "ordivon-s5-fabric-canary-v1"
_PEER_ADDRESS = "10.253.60.3"
_GUEST_ADDRESS = "10.253.60.2"
_PREFIX_LENGTH = 24
_PEER_PORT = 48080


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _run(
    arguments: list[str], *, timeout: int = 30, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )


def _stop_process(process: subprocess.Popen[bytes] | None) -> bool:
    if process is None or process.poll() is not None:
        return True
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    return process.poll() is not None


@dataclass(frozen=True, slots=True)
class WindowsFabricRangeConfig:
    machine: WindowsKvmMachineConfig
    canary_path: Path
    canary_digest: str
    ip_path: Path = Path("/usr/bin/ip")
    bridge_path: Path = Path("/usr/bin/bridge")
    tcpdump_path: Path = Path("/usr/bin/tcpdump")
    python_path: Path = Path("/usr/bin/python3")
    sysctl_path: Path = Path("/usr/bin/sysctl")
    mkfs_fat_path: Path = Path("/usr/bin/mkfs.fat")
    mcopy_path: Path = Path("/usr/bin/mcopy")
    run_disk_mib: int = 128
    max_runtime_seconds: int = 6 * 60

    def __post_init__(self) -> None:
        if self.canary_path.is_symlink() or not self.canary_path.is_file():
            raise ValueError("S5 fabric canary is missing or unsafe")
        if _digest(self.canary_path) != self.canary_digest:
            raise ValueError("S5 fabric canary digest differs")
        for path in (
            self.ip_path,
            self.bridge_path,
            self.tcpdump_path,
            self.python_path,
            self.sysctl_path,
            self.mkfs_fat_path,
            self.mcopy_path,
        ):
            if not path.resolve().is_file():
                raise ValueError(f"S5 fabric tool is missing or unsafe: {path}")
        if min(self.run_disk_mib, self.max_runtime_seconds) < 1:
            raise ValueError("S5 Range limits must be positive")


@dataclass(slots=True)
class _FabricRun:
    instance: RangeSessionInstance
    state: JsonObject
    process: subprocess.Popen[bytes]
    peer_process: subprocess.Popen[bytes]
    capture_process: subprocess.Popen[bytes]
    events: list[PendingRangeEvent] = field(default_factory=list)
    exit_recorded: bool = False
    guest_claim_recorded: bool = False
    sensor_recorded: bool = False
    guest_claim: JsonObject | None = None
    sensor_observation: JsonObject | None = None


class WindowsIsolatedFabricRange:
    """S5 first slice: one Windows VM plus one lightweight peer on an isolated L2 fabric."""

    range_id = _RANGE_ID

    def __init__(self, config: WindowsFabricRangeConfig) -> None:
        self.config = config
        self.machine_provider = WindowsKvmMachineProvider(config.machine)
        self._runs: dict[str, _FabricRun] = {}

    @property
    def execution_identity(self) -> JsonObject:
        tools: JsonObject = {}
        for name, path in (
            ("ip", self.config.ip_path),
            ("bridge", self.config.bridge_path),
            ("tcpdump", self.config.tcpdump_path),
            ("python", self.config.python_path),
            ("sysctl", self.config.sysctl_path),
            ("mkfsFat", self.config.mkfs_fat_path),
            ("mcopy", self.config.mcopy_path),
        ):
            tools[name] = {
                "path": str(path),
                "resolvedPath": str(path.resolve()),
                "digest": _digest(path.resolve()),
            }
        identity: JsonObject = {
            "kind": "ordivon.security.windows-isolated-fabric-range",
            "rangeId": self.range_id,
            "implementationRevision": "1",
            "securitySource": security_source_identity(),
            "machineProvider": self.machine_provider.execution_identity,
            "canary": {
                "canaryId": _CANARY_ID,
                "digest": self.config.canary_digest,
                "byteLength": self.config.canary_path.stat().st_size,
            },
            "materialization": {
                "guest": "windows-kvm",
                "peer": "linux-network-namespace-process",
                "fabric": "linux-network-namespace-bridge-tap-veth",
            },
            "network": {
                "guestAddress": _GUEST_ADDRESS,
                "peerAddress": _PEER_ADDRESS,
                "prefixLength": _PREFIX_LENGTH,
                "peerPort": _PEER_PORT,
                "uplink": "absent",
                "fabricL3": "disabled-ipv4-and-ipv6",
            },
            "tools": tools,
        }
        validate_json(identity)
        return identity

    def _emit(
        self,
        run: _FabricRun,
        *,
        logical_time: int,
        plane: str,
        source_id: str,
        event_type: str,
        payload: JsonObject,
    ) -> None:
        run.events.append(
            PendingRangeEvent(
                cursor=len(run.events),
                logical_time=logical_time,
                plane=plane,
                source_id=source_id,
                event_type=event_type,
                payload=payload,
            )
        )

    def _ledger_extra(self, spec: RangeSessionSpec, state: JsonObject) -> JsonObject:
        return {
            "rangeSessionId": spec.session_id,
            "rangeSpecDigest": spec.digest,
            "rangeId": self.range_id,
            "networkMode": "isolated-l2-no-uplink",
            "fabricNamespace": state.get("fabricNamespace"),
            "peerNamespace": state.get("peerNamespace"),
            "bridgeName": state.get("bridgeName"),
            "tapName": state.get("tapName"),
        }

    def _stage_run_disk(self, state: JsonObject, spec: RangeSessionSpec) -> None:
        run_path = Path(cast(str, state["runPath"]))
        run_disk = run_path / "ordivon-run.img"
        with run_disk.open("xb") as handle:
            handle.truncate(self.config.run_disk_mib * 1024 * 1024)
        _run([str(self.config.mkfs_fat_path), "-n", _RUN_LABEL, str(run_disk)], timeout=120)
        manifest: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-run",
            "runId": spec.session_id,
            "sampleDigest": self.config.canary_digest,
            "sampleByteLength": self.config.canary_path.stat().st_size,
            "action": "execute-benign-fixture",
            "maxRuntimeMs": self.config.max_runtime_seconds * 1000,
            "fixtureId": _CANARY_ID,
            "fabricRange": True,
            "semanticAction": "connect-maintained-range-peer-v1",
        }
        manifest_path = run_path / "ordivon-run.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}
        for source, destination in (
            (self.config.canary_path, "::/fixture.exe"),
            (manifest_path, "::/ordivon-run.json"),
        ):
            subprocess.run(
                [str(self.config.mcopy_path), "-o", "-i", str(run_disk), str(source), destination],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                timeout=120,
            )
        run_disk.chmod(0o600)
        _set_owner(run_disk, user=self.config.machine.run_user, group=self.config.machine.run_group)
        state["runDiskPath"] = str(run_disk)

    def _create_fabric(
        self, state: JsonObject, token: str
    ) -> tuple[subprocess.Popen[bytes], subprocess.Popen[bytes]]:
        suffix = token[:8]
        fabric_ns = f"s5f{suffix}"
        peer_ns = f"s5p{suffix}"
        bridge_name = f"b{suffix}"
        tap_name = f"t{suffix}"
        peer_veth = f"p{suffix}"
        fabric_veth = f"v{suffix}"
        run_path = Path(cast(str, state["runPath"]))
        pcap_path = run_path / "fabric.pcap"
        created: list[str] = []
        peer: subprocess.Popen[bytes] | None = None
        capture: subprocess.Popen[bytes] | None = None
        try:
            _run([str(self.config.ip_path), "netns", "add", fabric_ns])
            created.append(fabric_ns)
            _run([str(self.config.ip_path), "netns", "add", peer_ns])
            created.append(peer_ns)
            for namespace in (fabric_ns, peer_ns):
                _run(
                    [
                        str(self.config.ip_path),
                        "netns",
                        "exec",
                        namespace,
                        str(self.config.sysctl_path),
                        "-q",
                        "-w",
                        "net.ipv6.conf.all.disable_ipv6=1",
                    ]
                )
                _run(
                    [
                        str(self.config.ip_path),
                        "netns",
                        "exec",
                        namespace,
                        str(self.config.sysctl_path),
                        "-q",
                        "-w",
                        "net.ipv6.conf.default.disable_ipv6=1",
                    ]
                )
            _run(
                [
                    str(self.config.ip_path),
                    "-n",
                    fabric_ns,
                    "link",
                    "add",
                    bridge_name,
                    "type",
                    "bridge",
                ]
            )
            _run([str(self.config.ip_path), "-n", fabric_ns, "link", "set", bridge_name, "up"])
            _run(
                [
                    str(self.config.ip_path),
                    "netns",
                    "exec",
                    fabric_ns,
                    str(self.config.ip_path),
                    "tuntap",
                    "add",
                    "dev",
                    tap_name,
                    "mode",
                    "tap",
                    "user",
                    self.config.machine.run_user,
                ]
            )
            _run(
                [
                    str(self.config.ip_path),
                    "-n",
                    fabric_ns,
                    "link",
                    "set",
                    tap_name,
                    "master",
                    bridge_name,
                ]
            )
            _run([str(self.config.ip_path), "-n", fabric_ns, "link", "set", tap_name, "up"])
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
                    f"{_PEER_ADDRESS}/{_PREFIX_LENGTH}",
                    "dev",
                    peer_veth,
                ]
            )

            bridge_state = json.loads(
                _run(
                    [str(self.config.ip_path), "-n", fabric_ns, "-j", "addr", "show", bridge_name]
                ).stdout
            )[0]
            routes = json.loads(
                _run([str(self.config.ip_path), "-n", fabric_ns, "-j", "route"]).stdout or "[]"
            )
            peer_routes = json.loads(
                _run([str(self.config.ip_path), "-n", peer_ns, "-j", "route"]).stdout or "[]"
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
            port_names = {str(item.get("ifname")) for item in ports}
            if bridge_state.get("addr_info") != []:
                raise RuntimeError("S5 fabric bridge unexpectedly has an L3 address")
            if routes:
                raise RuntimeError("S5 fabric namespace unexpectedly has a route")
            if any(item.get("dst") == "default" for item in peer_routes):
                raise RuntimeError("S5 peer namespace unexpectedly has a default route")
            if port_names != {tap_name, fabric_veth}:
                raise RuntimeError(
                    "S5 fabric bridge topology differs from the declared two-port fabric"
                )

            state.update(
                {
                    "fabricNamespace": fabric_ns,
                    "peerNamespace": peer_ns,
                    "bridgeName": bridge_name,
                    "tapName": tap_name,
                    "peerVethName": peer_veth,
                    "fabricVethName": fabric_veth,
                    "pcapPath": str(pcap_path),
                    "fabricTruth": {
                        "bridgeL3Addresses": 0,
                        "fabricRoutes": routes,
                        "peerRoutes": peer_routes,
                        "bridgePorts": ports,
                        "declaredPortsPresent": True,
                        "externalRouteAbsent": True,
                    },
                }
            )

            capture_stdout = (run_path / "tcpdump.stdout.log").open("xb")
            capture_stderr = (run_path / "tcpdump.stderr.log").open("xb")
            capture = subprocess.Popen(
                [
                    str(self.config.ip_path),
                    "netns",
                    "exec",
                    fabric_ns,
                    str(self.config.tcpdump_path),
                    "-Z",
                    "root",
                    "-i",
                    bridge_name,
                    "-n",
                    "-U",
                    "-w",
                    str(pcap_path),
                    "tcp",
                    "port",
                    str(_PEER_PORT),
                ],
                stdout=capture_stdout,
                stderr=capture_stderr,
            )
            capture_stdout.close()
            capture_stderr.close()

            peer_stdout = (run_path / "peer.stdout.log").open("xb")
            peer_stderr = (run_path / "peer.stderr.log").open("xb")
            script = (
                "import socket; "
                f"s=socket.socket(); s.settimeout(300); s.bind(('{_PEER_ADDRESS}',{_PEER_PORT})); "
                "s.listen(1); c,a=s.accept(); "
                "c.sendall(b'ORDIVON-S5-PEER\\n'); c.close(); s.close()"
            )
            peer = subprocess.Popen(
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
                stdout=peer_stdout,
                stderr=peer_stderr,
            )
            peer_stdout.close()
            peer_stderr.close()
            time.sleep(0.25)
            if capture.poll() is not None:
                raise RuntimeError("S5 external packet sensor exited during startup")
            if peer.poll() is not None:
                raise RuntimeError("S5 synthetic peer exited during startup")
            return peer, capture
        except BaseException:
            _stop_process(capture)
            _stop_process(peer)
            for namespace in reversed(created):
                _run([str(self.config.ip_path), "netns", "del", namespace], check=False)
            raise

    def _qemu_arguments(self, state: JsonObject, instance_id: str) -> list[str]:
        run_disk = Path(cast(str, state["runDiskPath"]))
        tap_name = cast(str, state["tapName"])
        arguments = windows_kvm_machine_base_arguments(
            config=self.config.machine,
            state=state,
            name=instance_id,
        )
        arguments.extend(
            [
                "-drive",
                f"file={run_disk},if=none,format=raw,cache=none,aio=threads,id=rundisk",
                "-device",
                f"usb-storage,drive=rundisk,bus=xhci.0,removable=on,serial={_RUN_LABEL}",
                "-netdev",
                f"tap,id=range0,ifname={tap_name},script=no,downscript=no",
                "-device",
                "e1000,netdev=range0,mac=52:54:00:53:35:01",
            ]
        )
        return arguments

    def create(self, spec: RangeSessionSpec) -> RangeSessionInstance:
        if spec.range_id != self.range_id:
            raise ValueError("S5 Range specification targets another Range")
        token = hashlib.sha256(spec.session_id.encode("utf-8")).hexdigest()[:8]
        instance = RangeSessionInstance(
            instance_id=f"range-instance:s5-{token}", session_id=spec.session_id
        )
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        state = self.machine_provider.create_state(
            token=f"s5-{token}", instance_id=instance.instance_id, generation=generation
        )
        state["rangeSpecDigest"] = spec.digest
        peer: subprocess.Popen[bytes] | None = None
        capture: subprocess.Popen[bytes] | None = None
        try:
            self._stage_run_disk(state, spec)
            peer, capture = self._create_fabric(state, token)
            extra = self._ledger_extra(spec, state)
            self.machine_provider.persist_state(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                phase="fabric-created",
                extra=extra,
            )
            self.machine_provider.start_swtpm(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                ledger_extra=extra,
            )
            run_path = Path(cast(str, state["runPath"]))
            process = self.machine_provider.start_qemu(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                arguments=self._qemu_arguments(state, instance.instance_id),
                stdout_path=run_path / "qemu.stdout.log",
                stderr_path=run_path / "qemu.stderr.log",
                ledger_extra=extra,
                network_namespace=cast(str, state["fabricNamespace"]),
                ip_path=self.config.ip_path,
            )
            run = _FabricRun(
                instance=instance,
                state=state,
                process=process,
                peer_process=peer,
                capture_process=capture,
            )
            self._runs[instance.instance_id] = run
            topology = self.machine_provider.inspect_qmp(state)
            devices = topology.get("networkDevices")
            if (
                topology.get("networkDevicePresent") is not True
                or not isinstance(devices, list)
                or len(devices) != 1
            ):
                raise RuntimeError(
                    "S5 Windows Guest must expose exactly one QMP-observed network device"
                )
            post_qemu_ports = json.loads(
                _run(
                    [
                        str(self.config.ip_path),
                        "netns",
                        "exec",
                        cast(str, state["fabricNamespace"]),
                        str(self.config.bridge_path),
                        "-j",
                        "link",
                        "show",
                        "master",
                        cast(str, state["bridgeName"]),
                    ]
                ).stdout
            )
            tap_name = cast(str, state["tapName"])
            tap_state = next(
                (item for item in post_qemu_ports if item.get("ifname") == tap_name), None
            )
            tap_carrier = (
                isinstance(tap_state, dict)
                and tap_state.get("state") == "forwarding"
                and "LOWER_UP" in tap_state.get("flags", [])
            )
            if not tap_carrier:
                raise RuntimeError("S5 QEMU TAP did not become an active forwarding fabric port")
            fabric_truth = cast(JsonObject, state["fabricTruth"])
            fabric_truth["bridgePorts"] = cast(list[JsonValue], post_qemu_ports)
            fabric_truth["tapCarrierObserved"] = True
            self._emit(
                run,
                logical_time=0,
                plane="management",
                source_id="provider:windows-kvm:qmp",
                event_type="machine.network-device-confirmed",
                payload={"authority": "qmp-query-pci", "networkDeviceCount": len(devices)},
            )
            self._emit(
                run,
                logical_time=0,
                plane="world-truth",
                source_id="host:linux-netlink",
                event_type="world.fabric-topology-observed",
                payload=fabric_truth,
            )
            return instance
        except BaseException:
            if capture is not None:
                _stop_process(capture)
            if peer is not None:
                _stop_process(peer)
            self.machine_provider.destroy_state(
                instance_id=instance.instance_id,
                generation=generation,
                state=state,
                ledger_extra=self._ledger_extra(spec, state),
            )
            self._delete_namespaces(state)
            self._runs.pop(instance.instance_id, None)
            raise

    def _delete_namespaces(self, state: JsonObject) -> JsonObject:
        requested: list[str] = []
        for key in ("peerNamespace", "fabricNamespace"):
            value = state.get(key)
            if isinstance(value, str):
                requested.append(value)
                _run([str(self.config.ip_path), "netns", "del", value], check=False)
        listed = _run([str(self.config.ip_path), "netns", "list"], check=False).stdout.splitlines()
        remaining_names = {line.split()[0] for line in listed if line.strip()}
        residual = [name for name in requested if name in remaining_names]
        return {
            "requestedNamespaces": requested,
            "residualNamespaces": residual,
            "clean": not residual,
        }

    def _run_for(self, instance: RangeSessionInstance) -> _FabricRun:
        try:
            return self._runs[instance.instance_id]
        except KeyError as error:
            raise KeyError(f"unknown S5 Range instance: {instance.instance_id}") from error

    def _extract_guest_claim(self, run: _FabricRun) -> JsonObject | None:
        if run.guest_claim_recorded:
            return run.guest_claim
        run.guest_claim_recorded = True
        run_disk = Path(cast(str, run.state["runDiskPath"]))
        run_path = Path(cast(str, run.state["runPath"]))
        environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}

        def copy_file(source: str, destination_name: str) -> Path | None:
            destination = run_path / destination_name
            completed = subprocess.run(
                [
                    str(self.config.mcopy_path),
                    "-i",
                    str(run_disk),
                    source,
                    str(destination),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                timeout=30,
            )
            if completed.returncode != 0 or not destination.is_file():
                return None
            return destination

        def copy_json(source: str, destination_name: str) -> JsonObject | None:
            destination = copy_file(source, destination_name)
            if destination is None:
                return None
            value = json.loads(destination.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                return None
            validate_json(value)
            return cast(JsonObject, value)

        claim = copy_json("::/ordivon-result.json", "guest-result.json")
        raw_fixture = copy_json("::/fixture-result.json", "guest-fixture-result.json")
        runner_log_path = copy_file("::/guest-runner.log", "guest-runner.log")
        runner_log = None
        if runner_log_path is not None:
            runner_log = runner_log_path.read_text(encoding="utf-8", errors="replace")[:4096]
        diagnostic: JsonObject = {
            "authority": "guest-diagnostic-not-world-truth",
            "outerResultPresent": claim is not None,
            "fixtureResultPresent": raw_fixture is not None,
            "runnerLogPresent": runner_log is not None,
            "runnerLog": runner_log,
            "rawFixtureResult": raw_fixture,
        }
        run.state["guestDiagnostic"] = diagnostic
        self._emit(
            run,
            logical_time=2,
            plane="contested",
            source_id="guest:s5-runner",
            event_type="guest.runner-diagnostic-observed",
            payload=diagnostic,
        )
        if claim is None:
            return None
        if raw_fixture is not None and "fixtureResult" not in claim:
            claim["rawFixtureResult"] = raw_fixture
        run.guest_claim = claim
        self._emit(
            run,
            logical_time=2,
            plane="contested",
            source_id="guest:s5-fabric-canary",
            event_type="guest.fabric-connectivity-claim",
            payload={"authority": "guest-claim-not-world-truth", "claim": claim},
        )
        return claim

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
        matched = any(_GUEST_ADDRESS in line and _PEER_ADDRESS in line for line in lines)
        observation: JsonObject = {
            "authority": "external-packet-sensor-not-world-truth",
            "pcapDigest": pcap_digest,
            "packetLineCount": len(lines),
            "matchedChallengeTraffic": matched,
            "sampleLines": cast(list[JsonValue], lines[:20]),
        }
        run.sensor_observation = observation
        self._emit(
            run,
            logical_time=3,
            plane="sensor",
            source_id="sensor:host-tcpdump",
            event_type="sensor.range-traffic-observed",
            payload=observation,
        )
        return observation

    def _record_exit_if_needed(self, run: _FabricRun) -> int | None:
        exit_code = run.process.poll()
        if exit_code is None or run.exit_recorded:
            return exit_code
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        self.machine_provider.record_qemu_exit(
            instance_id=run.instance.instance_id,
            generation=generation,
            state=run.state,
            exit_code=exit_code,
            ledger_extra={
                "rangeSessionId": run.instance.session_id,
                "rangeSpecDigest": cast(str, run.state["rangeSpecDigest"]),
                "rangeId": self.range_id,
                "networkMode": "isolated-l2-no-uplink",
                "fabricNamespace": run.state.get("fabricNamespace"),
                "peerNamespace": run.state.get("peerNamespace"),
                "bridgeName": run.state.get("bridgeName"),
                "tapName": run.state.get("tapName"),
            },
        )
        run.exit_recorded = True
        self._extract_guest_claim(run)
        self._record_sensor(run)
        self._emit(
            run,
            logical_time=4,
            plane="management",
            source_id="provider:windows-kvm",
            event_type="machine.qemu-exited",
            payload={"exitCode": exit_code},
        )
        return exit_code

    def inspect(self, instance: RangeSessionInstance) -> JsonObject:
        run = self._run_for(instance)
        exit_code = self._record_exit_if_needed(run)
        return {
            "instanceId": instance.instance_id,
            "running": exit_code is None,
            "qemuExitCode": exit_code,
            "networkDevicePresent": run.state.get("networkDevicePresent"),
            "fabricTruth": run.state.get("fabricTruth"),
            "guestClaim": run.guest_claim,
            "guestDiagnostic": run.state.get("guestDiagnostic"),
            "sensorObservation": run.sensor_observation,
        }

    def events(
        self, instance: RangeSessionInstance, *, after_cursor: int
    ) -> tuple[PendingRangeEvent, ...]:
        run = self._run_for(instance)
        return tuple(event for event in run.events if event.cursor > after_cursor)

    def checkpoint(self, instance: RangeSessionInstance, label: str) -> BackendCheckpoint:
        self._run_for(instance)
        raise NotImplementedError("S5 first-slice Range does not implement checkpoints")

    def terminate(self, instance: RangeSessionInstance, reason: str) -> JsonObject:
        run = self._run_for(instance)
        if run.process.poll() is None:
            try:
                self.machine_provider.qmp_execute(run.state, "quit", timeout_seconds=5)
            except Exception:
                run.process.terminate()
            try:
                run.process.wait(timeout=self.config.machine.shutdown_grace_seconds)
            except subprocess.TimeoutExpired:
                run.process.kill()
                run.process.wait(timeout=10)
        exit_code = self._record_exit_if_needed(run)
        return {"reason": reason, "qemuExitCode": exit_code}

    def destroy(self, instance: RangeSessionInstance) -> JsonObject:
        run = self._run_for(instance)
        self._record_exit_if_needed(run)
        _stop_process(run.capture_process)
        _stop_process(run.peer_process)
        generation = f"windows-kvm:{self.machine_provider.base.environment_image_digest[-16:]}"
        machine = self.machine_provider.destroy_state(
            instance_id=instance.instance_id,
            generation=generation,
            state=run.state,
            ledger_extra={
                "rangeSessionId": run.instance.session_id,
                "rangeSpecDigest": cast(str, run.state["rangeSpecDigest"]),
                "rangeId": self.range_id,
                "networkMode": "isolated-l2-no-uplink",
                "fabricNamespace": run.state.get("fabricNamespace"),
                "peerNamespace": run.state.get("peerNamespace"),
                "bridgeName": run.state.get("bridgeName"),
                "tapName": run.state.get("tapName"),
            },
        )
        fabric = self._delete_namespaces(run.state)
        self._runs.pop(instance.instance_id, None)
        clean = machine.clean and fabric.get("clean") is True
        return {"clean": clean, "machine": machine.details, "fabric": fabric}
