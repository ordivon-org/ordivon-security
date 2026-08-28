from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, validate_json
from ordivon_security.acceptance_support import git_revision, write_receipt
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineProvider,
    _load_object,
    _process_start_time,
    _replace_private_json,
    _terminate_pid,
)
from ordivon_security.range import (
    RangeAuthority,
    RangeEffectRequest,
    RangeSession,
    RangeSessionSpec,
)
from ordivon_security.range.windows_fabric import WindowsFabricRangeConfig, _run
from ordivon_security.range.windows_fabric_reconcile import (
    _identity_alive,
    _root_link_kinds,
    _validated_range_ledger,
    reconcile_windows_fabric_range_runs,
)
from ordivon_security.windows_kvm_acceptance_support import (
    compile_topology_churn_canary,
    topology_guest_claim_passes,
)
from ordivon_security.windows_kvm_partial_world_fixture import (
    PARTIAL_MATERIALIZATION_FAULT_POINT,
    KillAfterRootVethRange,
    partial_link_names,
    root_link_truth,
)
from ordivon_security.windows_kvm_recovery_acceptance_support import (
    host_namespace_truth,
    ledger_semantic_binding,
    process_truth,
    windows_kvm_machine_config,
)

_ACTOR_ID = "actor:fresh-controller-continuation"
_AUTHORITY_ID = "range-authority:fresh-controller-continuation"
_ZONE_REF = "zone:s6-fabric"
_CAPABILITY = "fabric.peer-replacement"
_EFFECT_TYPE = "fabric.replace-peer-a-with-peer-b"
_PEER_B_ADDRESS = "10.253.70.4"
_PEER_B_BANNER = "ORDIVON-S6-PEER-B"
_PEER_PORT = 48080
_PREFIX_LENGTH = 24


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _namespace_link_names(
    namespace: str,
    *,
    ip_path: Path = Path("/usr/bin/ip"),
) -> list[str]:
    completed = subprocess.run(
        [str(ip_path), "-n", namespace, "-j", "link", "show"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        return []
    data = json.loads(completed.stdout or "[]")
    return sorted(
        str(item.get("ifname"))
        for item in data
        if isinstance(item, dict) and item.get("ifname") is not None
    )


def _namespace_addresses(
    namespace: str,
    link_name: str,
    *,
    ip_path: Path = Path("/usr/bin/ip"),
) -> list[str]:
    completed = subprocess.run(
        [str(ip_path), "-n", namespace, "-j", "addr", "show", link_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        return []
    data = json.loads(completed.stdout or "[]")
    result: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        for addr in item.get("addr_info", []):
            if not isinstance(addr, dict):
                continue
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if isinstance(local, str) and isinstance(prefix, int):
                result.append(f"{local}/{prefix}")
    return sorted(result)


def _bridge_truth(
    *,
    fabric_namespace: str,
    bridge_name: str,
    bridge_path: Path = Path("/usr/bin/bridge"),
    ip_path: Path = Path("/usr/bin/ip"),
) -> JsonObject:
    ports_result = subprocess.run(
        [
            str(ip_path),
            "netns",
            "exec",
            fabric_namespace,
            str(bridge_path),
            "-j",
            "link",
            "show",
            "master",
            bridge_name,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    ports_data = json.loads(ports_result.stdout or "[]") if ports_result.returncode == 0 else []
    ports = sorted(
        str(item.get("ifname"))
        for item in ports_data
        if isinstance(item, dict) and item.get("ifname") is not None
    )
    bridge_addr = subprocess.run(
        [str(ip_path), "-n", fabric_namespace, "-j", "addr", "show", bridge_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    bridge_data = json.loads(bridge_addr.stdout or "[]") if bridge_addr.returncode == 0 else []
    address_count = 0
    if bridge_data and isinstance(bridge_data[0], dict):
        info = bridge_data[0].get("addr_info")
        address_count = len(info) if isinstance(info, list) else 0
    routes_result = subprocess.run(
        [str(ip_path), "-n", fabric_namespace, "-j", "route"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    routes = json.loads(routes_result.stdout or "[]") if routes_result.returncode == 0 else []
    truth: JsonObject = {
        "authority": "host-linux-netlink-bridge-observation",
        "fabricNamespace": fabric_namespace,
        "bridgeName": bridge_name,
        "portNames": ports,
        "bridgeL3AddressCount": address_count,
        "fabricRoutes": cast(list[JsonValue], routes),
        "externalRouteAbsent": not routes,
    }
    validate_json(truth)
    return truth


def _peer_route_truth(
    namespace: str,
    *,
    ip_path: Path = Path("/usr/bin/ip"),
) -> JsonObject:
    result = subprocess.run(
        [str(ip_path), "-n", namespace, "-j", "route"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    routes = json.loads(result.stdout or "[]") if result.returncode == 0 else []
    truth: JsonObject = {
        "authority": "host-linux-peer-route-observation",
        "namespace": namespace,
        "routes": cast(list[JsonValue], routes),
        "defaultRouteAbsent": not any(
            isinstance(item, dict) and item.get("dst") == "default" for item in routes
        ),
    }
    validate_json(truth)
    return truth


def _wait_identity_gone(
    *,
    pid: int,
    start_time: int,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _identity_alive(pid, start_time):
            return True
        time.sleep(0.25)
    return not _identity_alive(pid, start_time)


def _extract_guest_claim(
    *,
    run_path: Path,
    mcopy_path: Path = Path("/usr/bin/mcopy"),
) -> JsonObject:
    run_disk = run_path / "ordivon-run.img"
    if run_disk.is_symlink() or not run_disk.is_file():
        raise RuntimeError("fresh controller cannot identify the exact Guest run disk")
    environment = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}

    def copy_json(source: str, name: str) -> JsonObject | None:
        destination = run_path / name
        completed = subprocess.run(
            [str(mcopy_path), "-i", str(run_disk), source, str(destination)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            timeout=30,
        )
        if completed.returncode != 0 or not destination.is_file():
            return None
        value = json.loads(destination.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
        validate_json(value)
        return cast(JsonObject, value)

    claim = copy_json("::/ordivon-result.json", "fresh-controller-guest-result.json")
    fixture = copy_json("::/fixture-result.json", "fresh-controller-fixture-result.json")
    if claim is None:
        raise RuntimeError("fresh controller could not recover the Guest result after QEMU exit")
    if fixture is not None and "fixtureResult" not in claim:
        claim["fixtureResult"] = fixture
    validate_json(claim)
    return claim


def _sensor_truth(
    *,
    run_path: Path,
    capture_pid: int,
    capture_start_time: int,
    tcpdump_path: Path = Path("/usr/bin/tcpdump"),
) -> JsonObject:
    capture_closed = _terminate_pid(
        capture_pid,
        expected_fragment="tcpdump",
        expected_start_time=capture_start_time,
    )
    pcap = run_path / "fabric.pcap"
    lines: list[str] = []
    digest: str | None = None
    if pcap.is_file():
        raw = pcap.read_bytes()
        digest = digest_bytes(raw)
        completed = subprocess.run(
            [str(tcpdump_path), "-nn", "-r", str(pcap)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        lines = [
            line
            for line in completed.stdout.splitlines()
            if line.strip() and not line.startswith("reading from file ")
        ]
    truth: JsonObject = {
        "authority": "external-packet-sensor-not-world-truth",
        "captureClosed": capture_closed,
        "pcapDigest": digest,
        "packetLineCount": len(lines),
        "peerATrafficObserved": any(
            "10.253.70.2" in line and "10.253.70.3" in line for line in lines
        ),
        "peerBTrafficObserved": any(
            "10.253.70.2" in line and "10.253.70.4" in line for line in lines
        ),
        "sampleLines": lines[:24],
    }
    validate_json(truth)
    return truth


def _persist_continued_ledger(
    *,
    ledger_path: Path,
    ledger: JsonObject,
    peer_namespace: str,
    peer_pid: int,
    peer_start_time: int | None,
) -> JsonObject:
    before_binding = ledger_semantic_binding(ledger)
    before_receipt = ledger.get("actorReplacementReceipt")
    updated = dict(ledger)
    updated["updatedAtNs"] = time.time_ns()
    updated["peerNamespace"] = peer_namespace
    updated["peerPid"] = peer_pid
    updated["peerStartTime"] = peer_start_time
    updated["topologyPhase"] = "peer-b-present"
    updated["currentPeerAddress"] = _PEER_B_ADDRESS
    validate_json(updated)
    _replace_private_json(ledger_path, cast(JsonObject, updated))
    reread = _load_object(ledger_path, "fresh-controller continued Range ledger")
    if ledger_semantic_binding(reread) != before_binding:
        raise RuntimeError("fresh controller changed the admitted semantic effect binding")
    if reread.get("actorReplacementReceipt") != before_receipt:
        raise RuntimeError("fresh controller changed the non-truth backend receipt")
    return reread


def _continue_peer_b_from_root_veth(
    *,
    args: argparse.Namespace,
    ledger_path: Path,
    ledger: JsonObject,
) -> tuple[JsonObject, subprocess.Popen[bytes]]:
    validated = _validated_range_ledger(
        args.state_root,
        args.state_root / "runs",
        ledger_path,
        ledger,
    )
    if validated is None:
        raise RuntimeError("fresh controller refuses an unsafe S6 ledger")
    run_path, namespaces, host_links, _ = validated
    if len(namespaces) != 3 or len(host_links) != 2:
        raise RuntimeError("fresh controller expected exact S6 continuation identities")
    fabric_ns, _, peer_b_ns = namespaces
    peer_veth, fabric_veth = host_links
    bridge_name = ledger.get("bridgeName")
    tap_name = ledger.get("tapName")
    if not isinstance(bridge_name, str) or not isinstance(tap_name, str):
        raise RuntimeError("fresh controller lacks durable bridge/TAP identity")
    if (
        ledger.get("topologyPhase") != "peer-a-removed"
        or ledger.get("currentPeerAddress") is not None
    ):
        raise RuntimeError("fresh controller refuses a non-partial S6 topology phase")
    root_kinds = _root_link_kinds(Path("/usr/bin/ip"), host_links)
    if root_kinds != {peer_veth: "veth", fabric_veth: "veth"}:
        raise RuntimeError(f"fresh controller refuses unexpected root-link truth: {root_kinds!r}")
    namespace_truth = host_namespace_truth(ledger)
    if set(cast(list[str], namespace_truth.get("ownedNamespacesPresent", []))) != {
        fabric_ns,
        peer_b_ns,
    }:
        raise RuntimeError("fresh controller refuses unexpected namespace placement")
    before_peer_links = _namespace_link_names(peer_b_ns)
    before_fabric_links = _namespace_link_names(fabric_ns)
    if peer_veth in before_peer_links or fabric_veth in before_fabric_links:
        raise RuntimeError("fresh controller fault point is already past root-veth placement")
    before_bridge = _bridge_truth(fabric_namespace=fabric_ns, bridge_name=bridge_name)
    if before_bridge.get("portNames") != [tap_name]:
        raise RuntimeError("fresh controller expected only the Windows TAP before continuation")

    _run(["/usr/bin/ip", "link", "set", peer_veth, "netns", peer_b_ns])
    _run(["/usr/bin/ip", "link", "set", fabric_veth, "netns", fabric_ns])
    _run(["/usr/bin/ip", "-n", fabric_ns, "link", "set", fabric_veth, "master", bridge_name])
    _run(["/usr/bin/ip", "-n", fabric_ns, "link", "set", fabric_veth, "up"])
    _run(["/usr/bin/ip", "-n", peer_b_ns, "link", "set", "lo", "up"])
    _run(["/usr/bin/ip", "-n", peer_b_ns, "link", "set", peer_veth, "up"])
    _run(
        [
            "/usr/bin/ip",
            "-n",
            peer_b_ns,
            "addr",
            "add",
            f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}",
            "dev",
            peer_veth,
        ]
    )

    peer_routes = _peer_route_truth(peer_b_ns)
    if peer_routes.get("defaultRouteAbsent") is not True:
        raise RuntimeError("fresh controller created an unexpected peer-B default route")
    peer_addresses = _namespace_addresses(peer_b_ns, peer_veth)
    if f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}" not in peer_addresses:
        raise RuntimeError("fresh controller did not establish peer-B address truth")
    after_bridge = _bridge_truth(fabric_namespace=fabric_ns, bridge_name=bridge_name)
    if set(cast(list[str], after_bridge.get("portNames", []))) != {tap_name, fabric_veth}:
        raise RuntimeError("fresh controller did not establish TAP plus peer-B bridge truth")
    if (
        after_bridge.get("bridgeL3AddressCount") != 0
        or after_bridge.get("externalRouteAbsent") is not True
    ):
        raise RuntimeError("fresh controller violated isolated fabric L3 truth")
    if root_link_truth(names=host_links).get("presentNames") != []:
        raise RuntimeError("fresh controller left continued veth links in the Host root namespace")

    stdout_path = run_path / "peer-b.stdout.log"
    stderr_path = run_path / "peer-b.stderr.log"
    if stdout_path.exists() or stderr_path.exists():
        raise RuntimeError("fresh controller refuses pre-existing peer-B service logs")
    stdout_handle = stdout_path.open("xb")
    stderr_handle = stderr_path.open("xb")
    script = (
        "import socket; "
        "s=socket.socket(); s.settimeout(300); "
        f"s.bind(('{_PEER_B_ADDRESS}',{_PEER_PORT})); "
        "s.listen(1); c,a=s.accept(); "
        f"c.sendall({(_PEER_B_BANNER + chr(10)).encode()!r}); c.close(); s.close()"
    )
    process = subprocess.Popen(
        [
            "/usr/bin/ip",
            "netns",
            "exec",
            peer_b_ns,
            "/usr/bin/setpriv",
            "--reuid",
            "qemu",
            "--regid",
            "qemu",
            "--init-groups",
            "--",
            "/usr/bin/python3",
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
        detail = stderr_path.read_text(encoding="utf-8", errors="replace")[:2048]
        raise RuntimeError(
            f"fresh controller peer-B service failed: exit={exit_code}; stderr={detail!r}"
        )
    if exit_code == 0:
        peer_pid = 0
        peer_start_time = None
    else:
        peer_pid = process.pid
        peer_start_time = _process_start_time(peer_pid)
        if peer_start_time is None:
            process.terminate()
            raise RuntimeError("fresh controller cannot observe peer-B process identity")

    continued_ledger = _persist_continued_ledger(
        ledger_path=ledger_path,
        ledger=ledger,
        peer_namespace=peer_b_ns,
        peer_pid=peer_pid,
        peer_start_time=peer_start_time,
    )
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.fresh-controller-peer-b-continuation",
        "sourceTopologyPhase": ledger.get("topologyPhase"),
        "targetTopologyPhase": "peer-b-present",
        "semanticEffectBinding": ledger_semantic_binding(continued_ledger),
        "backendReceipt": continued_ledger.get("actorReplacementReceipt"),
        "resourceIdentity": {
            "fabricNamespace": fabric_ns,
            "peerBNamespace": peer_b_ns,
            "peerVeth": peer_veth,
            "fabricVeth": fabric_veth,
            "bridgeName": bridge_name,
            "tapName": tap_name,
        },
        "before": {
            "rootLinkKinds": root_kinds,
            "namespaceTruth": namespace_truth,
            "peerBNamespaceLinks": before_peer_links,
            "fabricNamespaceLinks": before_fabric_links,
            "bridgeTruth": before_bridge,
        },
        "after": {
            "rootLinkTruth": root_link_truth(names=host_links),
            "namespaceTruth": host_namespace_truth(continued_ledger),
            "peerBNamespaceLinks": _namespace_link_names(peer_b_ns),
            "fabricNamespaceLinks": _namespace_link_names(fabric_ns),
            "bridgeTruth": after_bridge,
            "peerAddresses": peer_addresses,
            "peerRoutes": peer_routes,
        },
        "peerProcess": {
            "pid": peer_pid,
            "startTime": peer_start_time,
            "initialExitCode": exit_code,
        },
        "durableLedger": {
            "topologyPhase": continued_ledger.get("topologyPhase"),
            "currentPeerAddress": continued_ledger.get("currentPeerAddress"),
            "peerNamespace": continued_ledger.get("peerNamespace"),
            "peerPid": continued_ledger.get("peerPid"),
            "peerStartTime": continued_ledger.get("peerStartTime"),
        },
    }
    validate_json(receipt)
    return receipt, process


def _owner(args: argparse.Namespace) -> None:
    token = args.token
    canary_root = args.state_root / "canaries"
    canary_path = canary_root / f"ordivon-fresh-controller-{token}.exe"
    compilation = compile_topology_churn_canary(canary_path)
    authority = RangeAuthority(
        authority_id=_AUTHORITY_ID,
        revision="1",
        actor_id=_ACTOR_ID,
        zone_refs=(_ZONE_REF,),
        capabilities=(_CAPABILITY,),
        external_boundary="denied",
        metadata={"purpose": "fresh-controller-continuation"},
    )
    backend = KillAfterRootVethRange(
        WindowsFabricRangeConfig(
            machine=windows_kvm_machine_config(args),
            canary_path=canary_path,
            canary_digest=str(compilation["canaryDigest"]),
            max_runtime_seconds=args.max_runtime_seconds,
        ),
        replacement_trigger="actor-authorized",
        gate_path=args.gate,
    )
    session = RangeSession(
        backend,
        RangeSessionSpec(
            session_id=f"range-session:fresh-controller-{token}",
            revision="1",
            range_id=backend.range_id,
            actor_ids=(_ACTOR_ID,),
            authorities=(authority,),
            metadata={
                "purpose": "fresh-controller-continuation",
                "faultPoint": PARTIAL_MATERIALIZATION_FAULT_POINT,
                "externalNetwork": "structurally-unrouted",
                "guestDrivenPeerA": True,
            },
        ),
    )
    session.start()
    session.update_actor_presence(_ACTOR_ID, "active", logical_time=1)
    request = RangeEffectRequest(
        request_id=f"range-effect-request:fresh-controller-{token}",
        actor_id=_ACTOR_ID,
        authority_id=_AUTHORITY_ID,
        zone_ref=_ZONE_REF,
        capability=_CAPABILITY,
        effect_type=_EFFECT_TYPE,
        payload={"source": "fresh-controller-continuation-probe"},
    )
    admission = session.admit_effect(request, logical_time=2)
    if not admission.admitted:
        raise RuntimeError(f"fresh-controller effect was rejected: {admission.reason}")
    receipt = backend.request_peer_replacement(session.instance, admission)
    if receipt.get("worldEffectVerified") is not False:
        raise RuntimeError("fresh-controller backend receipt unexpectedly claims world truth")
    deadline = time.monotonic() + args.owner_wait_seconds
    while time.monotonic() < deadline:
        time.sleep(0.25)
    raise TimeoutError("Guest never drove the owner to the partial-materialization kill gate")


def _supervisor(args: argparse.Namespace) -> None:
    security_revision = git_revision(Path.cwd(), "Security")
    args.state_root.mkdir(parents=True, exist_ok=False)
    args.state_root.chmod(0o755)
    args.gate.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "ordivon_security.cli_windows_kvm_fresh_controller_continuation_acceptance",
        "--owner",
        "--base-manifest",
        str(args.base_manifest),
        "--state-root",
        str(args.state_root),
        "--gate",
        str(args.gate),
        "--token",
        args.token,
        "--memory-mib",
        str(args.memory_mib),
        "--vcpus",
        str(args.vcpus),
        "--max-runtime-seconds",
        str(args.max_runtime_seconds),
        "--owner-wait-seconds",
        str(args.owner_wait_seconds),
    ]
    started = time.monotonic()
    owner = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = owner.communicate(timeout=args.owner_wait_seconds + 60)
    except subprocess.TimeoutExpired as error:
        owner.kill()
        stdout, stderr = owner.communicate(timeout=15)
        raise TimeoutError("fresh-controller owner did not reach the SIGKILL gate") from error
    owner_elapsed_ms = int((time.monotonic() - started) * 1000)

    ledgers = sorted((args.state_root / "run-ledgers").glob("*.json"))
    if len(ledgers) != 1:
        raise RuntimeError(f"fresh controller expected one surviving ledger, found {len(ledgers)}")
    ledger_path = ledgers[0]
    ledger_bytes = ledger_path.read_bytes()
    ledger = _load_object(ledger_path, "fresh-controller inherited Range ledger")
    gate = _load_object(args.gate, "fresh-controller owner-loss gate")
    semantic_binding = ledger_semantic_binding(ledger)
    process_truth_before = process_truth(ledger)
    host_truth_before = host_namespace_truth(ledger)
    expected_peer_ns, peer_veth, fabric_veth = partial_link_names(
        cast(str, ledger["rangeSessionId"])
    )
    root_truth_before = root_link_truth(names=(peer_veth, fabric_veth))
    machine = WindowsKvmMachineProvider(windows_kvm_machine_config(args))
    qmp_before = machine.inspect_qmp(ledger)

    continuation, peer_process = _continue_peer_b_from_root_veth(
        args=args,
        ledger_path=ledger_path,
        ledger=ledger,
    )
    continued_ledger_bytes = ledger_path.read_bytes()
    continued_ledger = _load_object(ledger_path, "fresh-controller continued ledger")
    qmp_after = machine.inspect_qmp(continued_ledger)
    process_truth_after = process_truth(continued_ledger)

    qemu_pid = continued_ledger.get("qemuPid")
    qemu_start = continued_ledger.get("qemuStartTime")
    if not isinstance(qemu_pid, int) or not isinstance(qemu_start, int):
        raise RuntimeError("fresh controller lacks exact QEMU identity")
    guest_completed = _wait_identity_gone(
        pid=qemu_pid,
        start_time=qemu_start,
        timeout_seconds=args.guest_completion_timeout_seconds,
    )
    if not guest_completed:
        peer_process.terminate()
        raise TimeoutError("Windows Guest did not finish after fresh-controller continuation")
    peer_exit = peer_process.poll()
    if peer_exit is None:
        try:
            peer_exit = peer_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            peer_process.terminate()
            peer_exit = peer_process.wait(timeout=10)

    run_path = Path(cast(str, continued_ledger["runPath"]))
    guest_claim = _extract_guest_claim(run_path=run_path)
    capture_pid = continued_ledger.get("capturePid")
    capture_start = continued_ledger.get("captureStartTime")
    if not isinstance(capture_pid, int) or not isinstance(capture_start, int):
        raise RuntimeError("fresh controller lacks exact packet-sensor identity")
    sensor = _sensor_truth(
        run_path=run_path,
        capture_pid=capture_pid,
        capture_start_time=capture_start,
    )
    host_truth_completed = host_namespace_truth(continued_ledger)
    bridge_completed = _bridge_truth(
        fabric_namespace=cast(str, continued_ledger["fabricNamespace"]),
        bridge_name=cast(str, continued_ledger["bridgeName"]),
    )
    peer_addresses_completed = _namespace_addresses(expected_peer_ns, peer_veth)
    peer_routes_completed = _peer_route_truth(expected_peer_ns)

    reconciliation_path = (
        args.state_root / "receipts" / f"fresh-controller-reconcile-{args.token}.json"
    )
    reconciliation = reconcile_windows_fabric_range_runs(
        args.state_root,
        receipt_path=reconciliation_path,
    )
    closure_namespace_truth = host_namespace_truth(continued_ledger)
    closure_root_truth = root_link_truth(names=(peer_veth, fabric_veth))
    closure_process_truth = process_truth(continued_ledger)

    network_devices_before = qmp_before.get("networkDevices")
    network_devices_after = qmp_after.get("networkDevices")
    gates = {
        "ownerKilledAtExactPartialGate": owner.returncode == -signal.SIGKILL
        and gate.get("faultPoint") == PARTIAL_MATERIALIZATION_FAULT_POINT,
        "semanticEffectIdentityInherited": isinstance(semantic_binding, dict)
        and semantic_binding == ledger_semantic_binding(continued_ledger),
        "stablePhaseWasPeerARemoved": ledger.get("topologyPhase") == "peer-a-removed"
        and ledger.get("currentPeerAddress") is None,
        "partialWorldObservedBeforeContinuation": set(
            cast(list[str], host_truth_before.get("ownedNamespacesPresent", []))
        )
        == {cast(str, ledger["fabricNamespace"]), expected_peer_ns}
        and set(cast(list[str], root_truth_before.get("presentNames", [])))
        == {peer_veth, fabric_veth},
        "oldOwnerDeadButGuestSubstrateLive": process_truth_before.get("ownerAlive") is False
        and process_truth_before.get("qemuAlive") is True
        and process_truth_before.get("swtpmAlive") is True
        and process_truth_before.get("captureAlive") is True,
        "singleWindowsNicSurvivedControllerReplacement": isinstance(network_devices_before, list)
        and len(network_devices_before) == 1
        and isinstance(network_devices_after, list)
        and len(network_devices_after) == 1,
        "freshControllerReachedPeerBPresent": continued_ledger.get("topologyPhase")
        == "peer-b-present"
        and continued_ledger.get("currentPeerAddress") == _PEER_B_ADDRESS,
        "freshControllerDurablyPublishedPeerIdentity": continued_ledger.get("peerNamespace")
        == expected_peer_ns
        and isinstance(continued_ledger.get("peerPid"), int),
        "backendReceiptStillDoesNotClaimWorldTruth": isinstance(
            continued_ledger.get("actorReplacementReceipt"), dict
        )
        and cast(dict[str, object], continued_ledger["actorReplacementReceipt"]).get(
            "worldEffectVerified"
        )
        is False,
        "guestCompletedAfterFreshController": guest_completed,
        "guestObservedBothPeers": topology_guest_claim_passes(guest_claim),
        "peerBServiceCompleted": peer_exit == 0,
        "sensorObservedBothFlows": sensor.get("peerATrafficObserved") is True
        and sensor.get("peerBTrafficObserved") is True,
        "completedWorldStillPeerB": set(
            cast(list[str], host_truth_completed.get("ownedNamespacesPresent", []))
        )
        == {cast(str, continued_ledger["fabricNamespace"]), expected_peer_ns}
        and set(cast(list[str], bridge_completed.get("portNames", [])))
        == {cast(str, continued_ledger["tapName"]), fabric_veth}
        and f"{_PEER_B_ADDRESS}/{_PREFIX_LENGTH}" in peer_addresses_completed
        and peer_routes_completed.get("defaultRouteAbsent") is True,
        "reconcilerClosedContinuedWorld": reconciliation.get("status") == "passed"
        and reconciliation.get("reconciled") == 1
        and reconciliation.get("attentionRequired") == 0,
        "closureHasZeroNamespaces": not cast(
            list[object], closure_namespace_truth.get("ownedNamespacesPresent", [])
        ),
        "closureHasZeroRootLinks": not cast(
            list[object], closure_root_truth.get("presentNames", [])
        ),
        "closureHasZeroManagedProcesses": closure_process_truth.get("qemuAlive") is False
        and closure_process_truth.get("swtpmAlive") is False
        and closure_process_truth.get("peerAlive") is False
        and closure_process_truth.get("captureAlive") is False,
    }
    passed = all(gates.values())
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.fresh-controller-continuation-acceptance",
        "status": "accepted" if passed else "failed",
        "securityRevision": security_revision,
        "faultPoint": PARTIAL_MATERIALIZATION_FAULT_POINT,
        "owner": {
            "returnCode": owner.returncode,
            "elapsedMs": owner_elapsed_ms,
            "stdoutTail": stdout[-2000:],
            "stderrTail": stderr[-2000:],
        },
        "inheritedLedger": {
            "sha256": digest_bytes(ledger_bytes),
            "byteLength": len(ledger_bytes),
            "topologyPhase": ledger.get("topologyPhase"),
            "currentPeerAddress": ledger.get("currentPeerAddress"),
            "semanticEffectBinding": semantic_binding,
        },
        "continuedLedger": {
            "sha256": digest_bytes(continued_ledger_bytes),
            "byteLength": len(continued_ledger_bytes),
            "topologyPhase": continued_ledger.get("topologyPhase"),
            "currentPeerAddress": continued_ledger.get("currentPeerAddress"),
            "peerNamespace": continued_ledger.get("peerNamespace"),
            "peerPid": continued_ledger.get("peerPid"),
            "peerStartTime": continued_ledger.get("peerStartTime"),
        },
        "preContinuation": {
            "processTruth": process_truth_before,
            "hostTruth": host_truth_before,
            "rootLinkTruth": root_truth_before,
            "qmp": qmp_before,
        },
        "continuation": continuation,
        "postContinuation": {
            "processTruth": process_truth_after,
            "qmp": qmp_after,
        },
        "guestClaim": guest_claim,
        "sensorObservation": sensor,
        "completedWorldTruth": {
            "hostTruth": host_truth_completed,
            "bridgeTruth": bridge_completed,
            "peerAddresses": peer_addresses_completed,
            "peerRoutes": peer_routes_completed,
        },
        "reconciliation": reconciliation,
        "closureTruth": {
            "namespaceTruth": closure_namespace_truth,
            "rootLinkTruth": closure_root_truth,
            "processTruth": closure_process_truth,
        },
        "gates": gates,
        "interpretation": {
            "oldPythonRangeObjectRecovered": False,
            "oldRangeEventStreamRecovered": False,
            "durableSubstepStateConsumed": False,
            "worldObservationUsedAsProgressState": True,
            "wholeRangeClosedBeforeContinuation": False,
            "automaticGenericExactlyOnceProved": False,
        },
    }
    validate_json(receipt)
    write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Kill one S6 controller inside peer-B materialization, then let a fresh process "
            "continue from durable effect/resource identity plus Host world observation."
        )
    )
    parser.add_argument("--owner", action="store_true")
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--token", default="fresh-controller")
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=360)
    parser.add_argument("--owner-wait-seconds", type=float, default=180.0)
    parser.add_argument("--guest-completion-timeout-seconds", type=float, default=180.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.owner:
        _owner(args)
        return
    if args.receipt is None:
        raise ValueError("fresh-controller supervisor requires --receipt")
    _supervisor(args)


if __name__ == "__main__":
    main()
