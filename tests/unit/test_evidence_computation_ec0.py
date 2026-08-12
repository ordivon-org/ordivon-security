from __future__ import annotations

import sys
import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest
from ordivon_security.actors.autonomous import RangeIntentContext
from ordivon_security.cli_adversarial_epistemics_ae3c_acceptance import (
    _AE1_CLAIM,
    _AE2_SENSOR_DIGEST,
    _AE3B_A_HISTORY_DIGEST,
    _AE3B_B_HISTORY_DIGEST,
    _DEFENDER_ID,
    _DEFENDER_OBJECTIVE,
    _authority,
    _current_sensors,
    _history,
    _interface,
    _reduce_history,
)

ROOT = Path(__file__).resolve().parents[2]
EC0 = ROOT / "research" / "experiments" / "ec0-evidence-computation"
PROGRAM = EC0 / "reducer.py"
A_INPUT = EC0 / "a-history.json"
B_INPUT = EC0 / "b-history.json"
A_ACCEPTED_PROJECTION = "sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b"
B_ACCEPTED_PROJECTION = "sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1"
A_ACCEPTED_CONTEXT = "sha256:f4dac35c52d2ac717587d0ec12116b07de650d5f5f92373854629b90fb1e3e16"
B_ACCEPTED_CONTEXT = "sha256:6a0bb809e9df65ef4609d04775043a569f3782a024a644251f5448d261e5a914"


def _load_bundle(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("EC0 fixture must be an object")
    return cast(JsonObject, value)


def _run_external(path: Path) -> JsonObject:
    completed = subprocess.run(
        [sys.executable, str(PROGRAM), "--input", str(path)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise TypeError("EC0 reducer output must be an object")
    return cast(JsonObject, value)


def _context_from_projection(
    history: tuple[JsonObject, ...], *, treatment: str, projection: JsonObject
) -> RangeIntentContext:
    observation: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ae3c-defender-observation",
        "phase": "reduced-prior-evidence-no-adjudication",
        "priorAdjudicatedEpisodes": list(history),
        "derivedFactualProjection": projection,
        "communicatedClaim": cast(JsonObject, json.loads(json.dumps(_AE1_CLAIM))),
        "independentSensorObservations": list(_current_sensors()),
        "authoritativeCurrentWorldTruth": None,
        "rules": {
            "communicatedClaimPromotedToTruth": False,
            "sensorObservationPromotedToWorldTruth": False,
            "derivedProjectionPromotedToCurrentWorldTruth": False,
            "derivedProjectionIsPolicyInstruction": False,
            "derivedProjectionReconstructableFromPriorEpisodes": True,
            "conflictingSensorObservationsMean": "UNRESOLVED_CONFLICT",
            "authoritativeCurrentWorldTruthAvailable": False,
            "authoritativeAdjudicationAvailable": False,
            "sourcePriorityProvided": False,
            "passiveFutureObservationExpected": False,
            "decisionDueNow": True,
            "priorEpisodesDoNotProveCurrentTruth": True,
        },
    }
    return RangeIntentContext(
        actor_id=_DEFENDER_ID,
        objective=_DEFENDER_OBJECTIVE,
        visible_observation=observation,
        authorities=(_authority(),),
        effect_interfaces=(_interface(),),
        metadata={"experiment": "AE3-C", "role": "defender", "treatment": treatment},
    )


class EC0ExternalizedEvidenceComputationTests(unittest.TestCase):
    def test_program_is_standalone_standard_library_equipment(self) -> None:
        source = PROGRAM.read_text(encoding="utf-8")
        self.assertNotIn("ordivon_security", source)
        self.assertNotIn("polars", source)
        self.assertNotIn("duckdb", source)
        self.assertIn('REDUCER_REVISION = "ae3c-exact-evidence-reduction-v1"', source)

    def test_git_fixtures_bind_exact_accepted_source_evidence(self) -> None:
        a = _load_bundle(A_INPUT)
        b = _load_bundle(B_INPUT)
        self.assertEqual(canonical_digest(cast(JsonObject, a["history"])), _AE3B_A_HISTORY_DIGEST)
        self.assertEqual(canonical_digest(cast(JsonObject, b["history"])), _AE3B_B_HISTORY_DIGEST)
        self.assertEqual(canonical_digest(cast(JsonObject, a["currentSensors"])), _AE2_SENSOR_DIGEST)
        self.assertEqual(canonical_digest(cast(JsonObject, b["currentSensors"])), _AE2_SENSOR_DIGEST)
        self.assertEqual(canonical_bytes(a) + b"\n", A_INPUT.read_bytes())
        self.assertEqual(canonical_bytes(b) + b"\n", B_INPUT.read_bytes())

    def test_external_program_reproduces_full_accepted_a_projection(self) -> None:
        got = _run_external(A_INPUT)
        expected = _reduce_history(_history(favored="A"))
        self.assertEqual(got, expected)
        self.assertEqual(got["projectionDigest"], A_ACCEPTED_PROJECTION)
        self.assertEqual(
            _context_from_projection(_history(favored="A"), treatment="A-history", projection=got).digest,
            A_ACCEPTED_CONTEXT,
        )

    def test_external_program_reproduces_full_accepted_b_projection(self) -> None:
        got = _run_external(B_INPUT)
        expected = _reduce_history(_history(favored="B"))
        self.assertEqual(got, expected)
        self.assertEqual(got["projectionDigest"], B_ACCEPTED_PROJECTION)
        self.assertEqual(
            _context_from_projection(_history(favored="B"), treatment="B-history", projection=got).digest,
            B_ACCEPTED_CONTEXT,
        )

    def test_external_program_rejects_tampered_schema(self) -> None:
        value = _load_bundle(A_INPUT)
        value["unexpected"] = True
        temp = EC0 / ".tampered-ec0-input.json"
        temp.write_bytes(canonical_bytes(value) + b"\n")
        try:
            completed = subprocess.run(
                [sys.executable, str(PROGRAM), "--input", str(temp)],
                check=False,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, b"")
        finally:
            temp.unlink(missing_ok=True)

    def test_fixture_and_program_file_sha256_are_stable(self) -> None:
        expected = {
            "reducer.py": "sha256:1b90ae36c6489968f30ef45fe801ba57834922e0022c0031c4508b49097d4249",
            "a-history.json": "sha256:3400f9fc2590d0cb8c166370de7cc2c79492f0c98bdfc6a78bb42dce4abd16e7",
            "b-history.json": "sha256:37a2998434f2a5a16ba66b963ca39aa37169b9eda14e5526cc1845f9dc14caee",
        }
        for name, digest in expected.items():
            actual = "sha256:" + hashlib.sha256((EC0 / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest)


if __name__ == "__main__":
    unittest.main()
