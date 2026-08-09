from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EC1 = ROOT / "research" / "experiments" / "ec1-derived-evidence-freshness"
CHECKER = EC1 / "applicability.py"
CURRENT = EC1 / "current-source.json"
PROJECTION_V1 = EC1 / "projection-v1.json"
PROJECTION_V2 = EC1 / "projection-v2.json"

PROJECTION_V1_FILE_SHA = "sha256:e72a7c67a942b304ba828549ff45c7b237f64ca44b786a87e52183397876d675"
PROJECTION_V2_FILE_SHA = "sha256:62e2557343b74695942f83c02231b74277c16ff26efb6d85b4929b284669c240"
PROJECTION_V1_DIGEST = "sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b"
PROJECTION_V2_DIGEST = "sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1"
A_HISTORY_DIGEST = "sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635"
B_HISTORY_DIGEST = "sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83"
SENSOR_DIGEST = "sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053"
PHASE1_SOURCE_ENVELOPE = "sha256:f3ba0ad8a09ac804ff0f692d471e099e067fc8ba226776c00fb903120cd73f0a"
PHASE2_SOURCE_ENVELOPE = "sha256:5f4c073f74e416662cbb30afc4c9d51ed1fb640d1bf4a8c715b24349d677c726"


def _file_sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _classify(*, projection: Path, source: Path | None = CURRENT) -> dict[str, object]:
    args = ["/usr/bin/python3", str(CHECKER), "--projection", str(projection)]
    if source is None:
        args.append("--source-unavailable")
    else:
        args.extend(["--source", str(source)])
    completed = subprocess.run(args, check=True, capture_output=True, timeout=10)
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise TypeError("EC1 result must be an object")
    return value


class EC1DerivedEvidenceFreshnessTests(unittest.TestCase):
    def test_old_and_new_projection_bytes_are_exact_ec0_runtime_outputs(self) -> None:
        self.assertEqual(_file_sha(PROJECTION_V1), PROJECTION_V1_FILE_SHA)
        self.assertEqual(_file_sha(PROJECTION_V2), PROJECTION_V2_FILE_SHA)
        old = json.loads(PROJECTION_V1.read_text())
        new = json.loads(PROJECTION_V2.read_text())
        self.assertEqual(old["projectionDigest"], PROJECTION_V1_DIGEST)
        self.assertEqual(new["projectionDigest"], PROJECTION_V2_DIGEST)
        self.assertEqual(old["derivation"]["historyDigest"], A_HISTORY_DIGEST)
        self.assertEqual(new["derivation"]["historyDigest"], B_HISTORY_DIGEST)
        self.assertEqual(old["derivation"]["currentSensorSetDigest"], SENSOR_DIGEST)
        self.assertEqual(new["derivation"]["currentSensorSetDigest"], SENSOR_DIGEST)

    def test_current_authority_is_semantic_generation_three(self) -> None:
        source = json.loads(CURRENT.read_text())
        self.assertEqual(source["generation"], "generation:3")
        self.assertTrue(source["metadata"]["semanticDependencyChange"])
        new = _classify(projection=PROJECTION_V2)
        self.assertEqual(new["projectionIntegrity"], "valid")
        self.assertEqual(new["applicability"], "APPLICABLE")
        self.assertEqual(new["currentDependencies"], {"historyDigest": B_HISTORY_DIGEST, "currentSensorSetDigest": SENSOR_DIGEST})

    def test_integrity_valid_old_projection_is_stale_against_advanced_history(self) -> None:
        old = _classify(projection=PROJECTION_V1)
        self.assertEqual(old["projectionIntegrity"], "valid")
        self.assertEqual(old["applicability"], "STALE_NOT_APPLICABLE")
        self.assertEqual(old["dependencyMatch"], {"history": False, "currentSensors": True})
        self.assertEqual(old["derivationDependencies"], {"historyDigest": A_HISTORY_DIGEST, "currentSensorSetDigest": SENSOR_DIGEST})
        self.assertEqual(old["currentDependencies"], {"historyDigest": B_HISTORY_DIGEST, "currentSensorSetDigest": SENSOR_DIGEST})

    def test_generation_or_envelope_identity_is_not_the_applicability_rule(self) -> None:
        # Phase 1 and phase 2 were physically executed from distinct committed source envelopes.
        self.assertNotEqual(PHASE1_SOURCE_ENVELOPE, PHASE2_SOURCE_ENVELOPE)
        # The current checker intentionally exposes generation/envelope only as evidence, not as match fields.
        current = _classify(projection=PROJECTION_V2)
        self.assertNotIn("generation", current["dependencyMatch"])
        self.assertNotIn("sourceEnvelope", current["dependencyMatch"])

    def test_unavailable_current_authority_is_unknown_not_fresh_or_stale(self) -> None:
        result = _classify(projection=PROJECTION_V1, source=None)
        self.assertEqual(result["projectionIntegrity"], "valid")
        self.assertEqual(result["applicability"], "UNKNOWN")
        self.assertEqual(result["reason"], "current-authoritative-source-unavailable")

    def test_tampered_projection_fails_before_applicability(self) -> None:
        projection = json.loads(PROJECTION_V1.read_text())
        projection["sourceMatchCounts"][0]["matchedAdjudicatedTruthCount"] = 3
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n")
            result = _classify(projection=path)
        self.assertEqual(result["projectionIntegrity"], "invalid")
        self.assertEqual(result["applicability"], "INVALID")
        self.assertEqual(result["reason"], "projection-digest-mismatch")


if __name__ == "__main__":
    unittest.main()
