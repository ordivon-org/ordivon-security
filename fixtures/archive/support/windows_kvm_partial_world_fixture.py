from __future__ import annotations

import copy
import hashlib
import json
import os
import signal
import subprocess
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.providers.windows_kvm import _replace_private_json
from ordivon_security.range.windows_fabric import _run
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange
from ordivon_security.windows_kvm_recovery_acceptance_support import digest_bytes

PARTIAL_MATERIALIZATION_FAULT_POINT = "after-peer-b-root-veth-created-before-placement"


def partial_link_names(session_id: str) -> tuple[str, str, str]:
    suffix = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
    return f"s6q{suffix}", f"q{suffix}", f"w{suffix}"


def root_link_truth(
    *,
    names: tuple[str, ...],
    ip_path: Path = Path("/usr/bin/ip"),
) -> JsonObject:
    completed = subprocess.run(
        [str(ip_path), "-j", "link", "show"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    data = json.loads(completed.stdout or "[]")
    present: list[JsonObject] = []
    for item in data:
        if not isinstance(item, dict) or item.get("ifname") not in names:
            continue
        present.append(
            cast(
                JsonObject,
                {
                    "ifname": item.get("ifname"),
                    "ifindex": item.get("ifindex"),
                    "linkIndex": item.get("link_index"),
                    "linkType": item.get("link_type"),
                    "flags": item.get("flags", []),
                },
            )
        )
    truth: JsonObject = {
        "authority": "host-linux-root-netlink-observation",
        "candidateNames": list(names),
        "present": present,
        "presentNames": sorted(str(item["ifname"]) for item in present),
    }
    validate_json(truth)
    return truth


class KillAfterRootVethRange(WindowsTopologyChurnRange):
    """Create the accepted C1-C partial physical world, then kill the owner."""

    def __init__(self, *args: object, gate_path: Path, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._partial_gate_path = gate_path

    def _start_peer_b(self, run):  # type: ignore[no-untyped-def]
        peer_ns, peer_veth, fabric_veth = partial_link_names(run.instance.session_id)
        _run([str(self.config.ip_path), "netns", "add", peer_ns])
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
        ledger_path = Path(cast(str, run.state["runStatePath"]))
        ledger_bytes = ledger_path.read_bytes()
        payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.partial-materialization-owner-loss-gate",
            "faultPoint": PARTIAL_MATERIALIZATION_FAULT_POINT,
            "ownerPid": os.getpid(),
            "sessionId": run.instance.session_id,
            "instanceId": run.instance.instance_id,
            "topologyPhase": run.state.get("topologyPhase"),
            "currentPeerAddress": run.state.get("currentPeerAddress"),
            "expectedPeerNamespace": peer_ns,
            "expectedRootLinks": [peer_veth, fabric_veth],
            "actorReplacementRequest": copy.deepcopy(run.state.get("actorReplacementRequest")),
            "actorReplacementReceipt": copy.deepcopy(run.state.get("actorReplacementReceipt")),
            "ledgerSha256AtGate": digest_bytes(ledger_bytes),
            "ledgerByteLengthAtGate": len(ledger_bytes),
        }
        validate_json(payload)
        _replace_private_json(self._partial_gate_path, payload)
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError("partial-materialization owner survived SIGKILL injection")
