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

PROJECTION_V1_FILE_SHA = "sha256:e72a7c67a942b304ba828549ff45c7b237f64ca44b786a87e52183397876d675"
PROJECTION_V1_DIGEST = "sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b"
A_HISTORY_DIGEST = "sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635"
SENSOR_DIGEST = "sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053"


def _file_sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _classify(*, projection: Path = PROJECTION_V1, source: Path | None = CURRENT) -> dict[str, object]:
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


class EC1DerivedEvidenceFreshnessMetadataAdvanceTests(unittest.TestCase):
    def test_old_projection_bytes_are_exact_ec0_runtime_output(self) -> None:
        self.assertEqual(_file_sha(PROJECTION_V1), PROJECTION_V1_FILE_SHA)
        projection = json.loads(PROJECTION_V1.read_text())
        self.assertEqual(projection["projectionDigest"], PROJECTION_V1_DIGEST)
        self.assertEqual(projection["derivation"]["historyDigest"], A_HISTORY_DIGEST)
        self.assertEqual(projection["derivation"]["currentSensorSetDigest"], SENSOR_DIGEST)

    def test_metadata_advanced_authoritative_source_accepts_unchanged_projection_dependencies(self) -> None:
        source = json.loads(CURRENT.read_text())
        self.assertEqual(source["generation"], "generation:2")
        self.assertFalse(source["metadata"]["semanticDependencyChange"])
        result = _classify()
        self.assertEqual(result["projectionIntegrity"], "valid")
        self.assertEqual(result["applicability"], "APPLICABLE")
        self.assertEqual(result["dependencyMatch"], {"history": True, "currentSensors": True})

    def test_unavailable_current_authority_is_unknown_not_fresh_or_stale(self) -> None:
        result = _classify(source=None)
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
