"""First live infrastructure-only Security/Link/Edge/Runtime composition."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .bundle import EvidenceAttachment, export_evidence_bundle, verify_evidence_bundle
from .campaign import (
    canonical_bytes,
    digest,
    envelope_digest,
    load_json,
    manifest_digest,
    validate_campaign,
)
from .coordinator import CampaignCoordinator, LifecycleRun
from .ledger import CampaignLedger
from .process_ports import (
    EdgeJsonLinePort,
    LinkCliPort,
    LinkPortPaths,
    RuntimeFixturePort,
)

EDGE_ENTRYPOINT = b"""set -e
if [ -n "${CLOUDFLARE_API_TOKEN-}" ]; then exit 20; fi
if [ -e /proc/self ] || [ -e /dev/null ]; then exit 21; fi
if (printf x > /experiment/write-test) 2>/dev/null; then exit 22; fi
if (: > /dev/tcp/127.0.0.1/1) 2>/dev/null; then exit 23; fi
printf 'edge-campaign-ok\\n'
"""


@dataclass(frozen=True, slots=True)
class LiveCompositionConfig:
    campaign_template: Path
    link_manifest_template: Path
    link_security_executable: Path
    link_world_executable: Path
    edge_command: tuple[str, ...]
    edge_cwd: Path
    output_root: Path
    runtime_workspace_id: str
    runtime_source_revision: str
    runtime_client_request_id: str
    security_source_revision: str


class _Timestamps:
    def __init__(self) -> None:
        self._current = datetime.now(timezone.utc).replace(microsecond=0)

    def next(self) -> str:
        value = self._current.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._current += timedelta(seconds=1)
        return value


def run_live_composition(config: LiveCompositionConfig) -> dict[str, Any]:
    output_root = config.output_root.resolve()
    if output_root == Path(output_root.anchor):
        raise ValueError("output_root must not be a filesystem root")
    if output_root.exists():
        if any(output_root.iterdir()):
            raise ValueError("output_root must not contain prior acceptance state")
    else:
        output_root.mkdir(parents=True, mode=0o700)

    base_campaign = load_json(config.campaign_template)
    campaign_id = base_campaign["campaign"]["id"]
    security_world_id = base_campaign["world"]["id"]
    link_manifest_path, fixture_addresses = _materialize_link_manifest(
        config.link_manifest_template, output_root / "inputs/link-world.json"
    )
    link_paths = LinkPortPaths(
        manifest=link_manifest_path,
        authority_root=output_root / "link/authority",
        observer_root=output_root / "link/observer",
        actor_root=output_root / "link/actor",
        operation_root=output_root / "link/operations",
        reconstruction_root=output_root / "link/reconstruction",
    )
    (output_root / "link").mkdir(parents=True, exist_ok=True, mode=0o700)
    link_port = LinkCliPort(config.link_security_executable, link_paths)
    link_snapshot = link_port.snapshot(campaign_id, security_world_id)
    link_world_id = str(link_snapshot["native_id"])

    runtime_port = RuntimeFixturePort(
        link_world_executable=config.link_world_executable,
        link_paths=link_paths,
        world_id=link_world_id,
        fixture_addresses=fixture_addresses,
        runtime_workspace_id=config.runtime_workspace_id,
        runtime_source_revision=config.runtime_source_revision,
        runtime_client_request_id=config.runtime_client_request_id,
    )
    runtime_snapshot = runtime_port.snapshot(campaign_id, security_world_id)
    timestamps = _Timestamps()

    edge_port = EdgeJsonLinePort(
        config.edge_command,
        cwd=config.edge_cwd,
        root=output_root / "edge/provider",
    )
    try:
        edge_input = _edge_identity_input(campaign_id, security_world_id)
        declaration = edge_port.declare(edge_input, EDGE_ENTRYPOINT)
        edge_snapshot = _require_object(declaration.get("snapshot"), "Edge declaration snapshot")
        campaign = materialize_campaign(
            base_campaign,
            link_snapshot=link_snapshot,
            edge_snapshot=edge_snapshot,
            runtime_snapshot=runtime_snapshot,
            security_source_revision=config.security_source_revision,
        )
        campaign_path = output_root / "inputs/campaign.json"
        campaign_path.write_bytes(canonical_bytes(campaign) + b"\n")

        ledger = CampaignLedger.admit(
            output_root / "security/ledger", campaign, recorded_at=timestamps.next()
        )
        coordinator = CampaignCoordinator(ledger, [link_port, edge_port, runtime_port])
        coordinator.bind_components(recorded_at=timestamps.next())

        lifecycle: dict[str, LifecycleRun] = {}
        for operation in ("prepare", "start", "freeze", "reset", "destroy"):
            lifecycle[operation] = coordinator.run_fixed(
                operation, recorded_at=timestamps.next()
            )
            _require_success(lifecycle[operation])

        residual = coordinator.assess_residuals(recorded_at=timestamps.next())
        if residual.classification != "clean":
            raise RuntimeError(
                f"live composition residual state is {residual.classification}: "
                f"{residual.to_dict()}"
            )

        for operation in ("reconstruct", "verify"):
            lifecycle[operation] = coordinator.run_fixed(
                operation, recorded_at=timestamps.next()
            )
            _require_success(lifecycle[operation])

        projection = coordinator.finalize_infrastructure_outcome(
            recorded_at=timestamps.next(),
            evidence_refs=[
                "evidence://link/observer-head",
                "evidence://edge/generation",
                "evidence://runtime/fixture-process",
            ],
        )
        if projection.outcome is None or projection.outcome["classification"] != "success":
            raise RuntimeError(f"live composition did not close successfully: {projection.outcome}")

        component_summary = {
            "schema_version": 1,
            "campaign_id": projection.campaign_id,
            "security_world_id": projection.world_id,
            "link_world_id": link_world_id,
            "edge_node_id": edge_snapshot["native_id"],
            "runtime_workspace_id": config.runtime_workspace_id,
            "runtime_client_request_id": config.runtime_client_request_id,
            "bindings": sorted(projection.bindings.values(), key=lambda value: value["project"]),
            "operation_states": {
                identity: value["state"] for identity, value in sorted(projection.operations.items())
            },
            "residual_classification": residual.classification,
            "outcome": projection.outcome,
            "network_attachment": {
                "edge_attached_to_link_world": False,
                "reason": "P0-C composes lifecycle and evidence; P0-D owns a persistent data-plane attachment.",
            },
            "evaluated_agent_executed": False,
        }
        final_bundle = export_evidence_bundle(
            ledger,
            output_root / "evidence/final-bundle",
            bundle_id=(
                "urn:ordivon:security:evidence-bundle:live-composition-"
                + hashlib.sha256(projection.head_hash.encode("utf-8")).hexdigest()[:24]
            ),
            residual_report=residual,
            attachments=[
                EvidenceAttachment(
                    "components/live-composition-summary.json",
                    canonical_bytes(component_summary) + b"\n",
                ),
                EvidenceAttachment(
                    "components/link-world-manifest.json",
                    link_manifest_path.read_bytes(),
                ),
                EvidenceAttachment(
                    "components/edge-declaration.json",
                    canonical_bytes(declaration) + b"\n",
                ),
            ],
        )
        verified = verify_evidence_bundle(output_root / "evidence/final-bundle")
        if verified.bundle_digest != final_bundle.bundle_digest:
            raise RuntimeError("final evidence verification changed the bundle digest")

        result = {
            "schema_version": 1,
            "status": "succeeded",
            "campaign_id": projection.campaign_id,
            "security_world_id": projection.world_id,
            "link_world_id": link_world_id,
            "edge_node_id": edge_snapshot["native_id"],
            "runtime_workspace_id": config.runtime_workspace_id,
            "runtime_client_request_id": config.runtime_client_request_id,
            "outcome": projection.outcome,
            "residual": residual.to_dict(),
            "ledger_revision": projection.revision,
            "ledger_head": projection.head_hash,
            "bundle": final_bundle.to_dict(),
            "output_root": str(output_root),
            "claims": {
                "real_link_world": True,
                "real_link_loopback_fixture": True,
                "real_edge_local_unshare_body": True,
                "runtime_held_fixture_process": True,
                "edge_link_network_attachment": False,
                "red_blue_agents": False,
            },
        }
        (output_root / "acceptance-result.json").write_bytes(
            canonical_bytes(result) + b"\n"
        )
        return result
    finally:
        runtime_port.close()
        edge_port.close()


def materialize_campaign(
    base: dict[str, Any],
    *,
    link_snapshot: dict[str, Any],
    edge_snapshot: dict[str, Any],
    runtime_snapshot: dict[str, Any],
    security_source_revision: str,
) -> dict[str, Any]:
    manifest = copy.deepcopy(base)
    manifest["campaign"]["name"] = "Live Link Edge Runtime infrastructure composition v0"
    manifest["world"]["link_ref"] = _typed_component_ref(
        "link", "network-world", link_snapshot
    )
    manifest["world"]["edge_ref"] = _typed_component_ref(
        "edge", "node", edge_snapshot
    )
    manifest["world"]["game_ref"] = {
        "project": "game",
        "id": "urn:ordivon:game:scenario:infrastructure-only-v0",
        "revision": "not-executed-v0",
        "digest": digest({"project": "game", "mode": "not-executed"}),
    }

    runtime_ref = _typed_component_ref("runtime", "workspace", runtime_snapshot)
    capability = manifest["capability_envelope"]
    capability["runtime_ref"] = runtime_ref
    capability["digest"] = envelope_digest(capability)
    manifest["authority"]["capability_envelope_ref"] = {
        "id": capability["id"],
        "revision": capability["revision"],
        "digest": capability["digest"],
    }
    manifest["provenance"]["source_ref"] = {
        "project": "source",
        "id": "urn:ordivon:source:tree:ordivon-security-live-composition-v0",
        "revision": security_source_revision,
        "digest": digest(
            {
                "project": "ordivon-security",
                "revision": security_source_revision,
                "slice": "live-component-composition-v0",
            }
        ),
    }
    manifest["objectives"][0]["description"] = (
        "Close one infrastructure-only Link, Edge, and Runtime lifecycle without an evaluated Agent."
    )
    manifest["objectives"][0]["success_criteria"] = [
        "Link, Edge, and Runtime native identities are bound to one Security Campaign.",
        "Prepare, start, freeze, reset, destroy, reconstruct, and verify produce receipts.",
        "Residual state is clean and the final evidence bundle replays independently.",
    ]
    manifest["objectives"][0]["evidence_refs"] = [
        "evidence://security/final-bundle"
    ]
    manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
    validate_campaign(manifest)
    return manifest


def _typed_component_ref(
    project: str, kind: str, snapshot: dict[str, Any]
) -> dict[str, Any]:
    native_id = str(snapshot["native_id"])
    return {
        "project": project,
        "id": f"urn:ordivon:{project}:{kind}:{native_id}",
        "revision": str(snapshot["revision"]),
        "digest": str(snapshot["root_digest"]),
    }


def _edge_identity_input(campaign_id: str, world_id: str) -> dict[str, Any]:
    source_digest = hashlib.sha256(EDGE_ENTRYPOINT).hexdigest()
    return {
        "node_class": "container",
        "provider": {
            "id": "local-unshare-v1",
            "kind": "local-unshare",
            "location": "range-local",
        },
        "source": {
            "kind": "fixture",
            "name": "security-live-composition-v0",
            "sha256": source_digest,
        },
        "capability": {
            "id": "security.live-composition.v0",
            "version": "1",
            "profile": "research",
            "consequence_scope": "range-local-only",
            "planes": ["experiment", "observation"],
            "budget": {
                "wall_time_ms": 5_000,
                "actions": 1,
                "artifact_bytes": 65_536,
            },
        },
        "policy_revision": {
            "id": "research-policy-v1",
            "sha256": "b" * 64,
            "profile": "research",
        },
        "resource_profile": {
            "id": "security-live-tiny",
            "cpu_millis": 250,
            "memory_bytes": 64 * 1024 * 1024,
            "storage_bytes": 16 * 1024 * 1024,
            "process_limit": 4,
        },
        "membership": {
            "campaign_id": campaign_id,
            "world_id": world_id,
            "generation": 1,
        },
        "profile": "research",
        "generation": 1,
    }


def _materialize_link_manifest(template: Path, destination: Path) -> tuple[Path, tuple[str, ...]]:
    with template.open("rb") as handle:
        manifest = tomllib.load(handle)
    listeners: list[socket.socket] = []
    addresses: list[str] = []
    try:
        for _ in range(3):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
            host, port = listener.getsockname()
            addresses.append(f"{host}:{port}")
        services = [
            service
            for node in manifest["nodes"]
            for service in node.get("services", [])
        ]
        if len(services) != len(addresses):
            raise ValueError("Link acceptance manifest must contain exactly three services")
        for service, address in zip(services, addresses, strict=True):
            service["fixture_address"] = address
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    finally:
        for listener in listeners:
            listener.close()
    return destination, tuple(addresses)


def _require_success(run: LifecycleRun) -> None:
    failed = [result for result in run.results if result.state != "succeeded"]
    if failed:
        raise RuntimeError(f"{run.operation} did not complete: {failed}")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value
