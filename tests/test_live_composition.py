from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path

from ordivon_security_contracts.campaign import load_json, validate_campaign
from ordivon_security_contracts.live_composition import materialize_campaign
from ordivon_security_contracts.process_ports import LinkPortPaths, RuntimeFixturePort

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/campaigns/valid/minimal-owned-range.json"


class LiveCompositionContractTests(unittest.TestCase):
    def test_materialized_campaign_binds_actual_component_references(self) -> None:
        base = load_json(FIXTURE)
        link = {
            "native_id": "nw1-" + "a" * 64,
            "revision": "sha256:" + "b" * 64,
            "root_digest": "sha256:" + "b" * 64,
            "metadata": {"effect_semantics": "fixture"},
        }
        edge = {
            "native_id": "edge-" + "c" * 32,
            "revision": "edge-node-v1:" + "d" * 64,
            "root_digest": "sha256:" + "d" * 64,
            "metadata": {"profile": "research"},
        }
        runtime = {
            "native_id": "runtime-workspace:acceptance",
            "revision": "e" * 40,
            "root_digest": "sha256:" + "f" * 64,
            "metadata": {"role": "link-fixture-holder"},
        }
        campaign = materialize_campaign(
            base,
            link_snapshot=link,
            edge_snapshot=edge,
            runtime_snapshot=runtime,
            security_source_revision="1" * 40,
        )
        validate_campaign(campaign)
        self.assertEqual(
            link["root_digest"], campaign["world"]["link_ref"]["digest"]
        )
        self.assertEqual(
            edge["native_id"],
            campaign["world"]["edge_ref"]["id"].rsplit(":", 1)[-1],
        )
        self.assertEqual(
            runtime["revision"],
            campaign["capability_envelope"]["runtime_ref"]["revision"],
        )

    def test_runtime_binding_is_stable_across_semantic_callers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = LinkPortPaths(
                manifest=root / "manifest.json",
                authority_root=root / "authority",
                observer_root=root / "observer",
                actor_root=root / "actor",
                operation_root=root / "operations",
                reconstruction_root=root / "reconstruction",
            )
            port = RuntimeFixturePort(
                link_world_executable="/bin/false",
                link_paths=paths,
                world_id="nw1-" + "a" * 64,
                fixture_addresses=(),
                runtime_workspace_id="workspace-1",
                runtime_source_revision="b" * 40,
                runtime_client_request_id="request-1",
            )
            self.assertEqual(
                port.snapshot("campaign-a", "world-a"),
                port.snapshot("campaign-b", "world-b"),
            )

    def test_runtime_residual_uses_listener_reachability_not_rebindability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            address = listener.getsockname()
            listener.listen(1)
            paths = LinkPortPaths(
                manifest=root / "manifest.json",
                authority_root=root / "authority",
                observer_root=root / "observer",
                actor_root=root / "actor",
                operation_root=root / "operations",
                reconstruction_root=root / "reconstruction",
            )
            port = RuntimeFixturePort(
                link_world_executable="/bin/false",
                link_paths=paths,
                world_id="nw1-" + "a" * 64,
                fixture_addresses=(f"{address[0]}:{address[1]}",),
                runtime_workspace_id="workspace-1",
                runtime_source_revision="b" * 40,
                runtime_client_request_id="request-1",
            )
            active = port.residual_checks()
            self.assertEqual("unexpected_residual", active[1].status)
            listener.close()
            clean = port.residual_checks()
            self.assertEqual("clean", clean[1].status)


if __name__ == "__main__":
    unittest.main()
