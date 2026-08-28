from __future__ import annotations

import hashlib
import subprocess
from importlib.resources import files
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def compile_topology_churn_canary(output_path: Path) -> JsonObject:
    source_path = Path(
        str(
            files("ordivon_security").joinpath(
                "resources", "windows_kvm", "topology_churn_canary.c"
            )
        )
    )
    compiler = Path("/usr/bin/x86_64-w64-mingw32-gcc")
    objdump = Path("/usr/bin/x86_64-w64-mingw32-objdump")
    for path in (source_path, compiler, objdump):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"S6 canary dependency is missing or unsafe: {path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    subprocess.run(
        [
            str(compiler),
            "-municode",
            "-Os",
            "-s",
            "-static",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            "-Wl,--no-insert-timestamp",
            "-o",
            str(output_path),
            str(source_path),
            "-lws2_32",
        ],
        check=True,
        timeout=120,
    )
    output_path.chmod(0o600)
    imports = subprocess.run(
        [str(objdump), "-p", str(output_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    ).stdout.lower()
    if "ws2_32.dll" not in imports:
        raise ValueError("S6 canary does not bind the expected Winsock import")
    compiler_version = subprocess.run(
        [str(compiler), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    ).stdout.splitlines()[0]
    result: JsonObject = {
        "canaryId": "ordivon-s6-topology-churn-canary-v1",
        "sourceDigest": _digest(source_path),
        "canaryDigest": _digest(output_path),
        "canaryByteLength": output_path.stat().st_size,
        "compilerPath": str(compiler),
        "compilerDigest": _digest(compiler),
        "compilerVersion": compiler_version,
        "declaredGuestEffects": [
            "configure-one-range-local-static-ipv4-address",
            "connect-maintained-peer-a",
            "observe-peer-a-banner",
            "wait-for-management-owned-topology-change",
            "connect-maintained-peer-b",
            "observe-peer-b-banner",
            "request-no-external-network",
        ],
    }
    result["compilationDigest"] = canonical_digest(result)
    return result



def topology_guest_claim_passes(value: object) -> bool:
    if not isinstance(value, dict) or value.get("status") != "completed":
        return False
    fixture = value.get("fixtureResult")
    if not isinstance(fixture, dict):
        return False
    return (
        fixture.get("completed") is True
        and fixture.get("configuredStaticIpv4") is True
        and fixture.get("rangeRoutePresent") is True
        and fixture.get("guestNicMac") == "52-54-00-53-35-01"
        and fixture.get("peerAConnected") is True
        and fixture.get("peerABannerMatched") is True
        and fixture.get("peerBConnected") is True
        and fixture.get("peerBBannerMatched") is True
        and fixture.get("externalNetworkRequested") is False
    )


def topology_phases(events: list[JsonObject]) -> set[str]:
    phases: set[str] = set()
    for event in events:
        if event.get("eventType") != "world.fabric-topology-observed":
            continue
        payload = event.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("phase"), str):
            phases.add(str(payload["phase"]))
    return phases


def range_backend_state(session: object) -> JsonObject:
    inspect = getattr(session, "inspect", None)
    if not callable(inspect):
        raise TypeError("Range session does not expose inspect()")
    inspected = inspect()
    if not isinstance(inspected, dict):
        raise RuntimeError("Range inspection is not a JSON object")
    value = inspected.get("backendState")
    if not isinstance(value, dict):
        raise RuntimeError("Range backend state is unavailable")
    return value


def world_still_peer_a(value: JsonObject) -> bool:
    truth = value.get("fabricTruth")
    return (
        value.get("topologyChurnCompleted") is False
        and value.get("actorReplacementRequest") is None
        and isinstance(truth, dict)
        and truth.get("phase") == "peer-a-present"
        and truth.get("currentPeerAddress") == "10.253.70.3"
    )
