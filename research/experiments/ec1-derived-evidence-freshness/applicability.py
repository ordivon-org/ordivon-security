#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

RULE_REVISION = "ec1-exact-derivation-dependency-applicability-v1"
SOURCE_KIND = "ordivon.security.ec1-authoritative-evidence-source"
PROJECTION_KIND = "ordivon.security.ae3c-derived-factual-projection"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def projection_integrity(projection: dict[str, Any]) -> tuple[bool, str | None]:
    if projection.get("schemaVersion") != 1 or projection.get("kind") != PROJECTION_KIND:
        return False, "unsupported-projection-identity"
    claimed = projection.get("projectionDigest")
    if not isinstance(claimed, str) or not claimed.startswith("sha256:"):
        return False, "projection-digest-missing"
    body = dict(projection)
    body.pop("projectionDigest", None)
    if canonical_digest(body) != claimed:
        return False, "projection-digest-mismatch"
    derivation = projection.get("derivation")
    if not isinstance(derivation, dict):
        return False, "derivation-missing"
    for field in ("reducerRevision", "historyDigest", "currentSensorSetDigest", "episodeIds"):
        if field not in derivation:
            return False, f"derivation-{field}-missing"
    if not isinstance(derivation["historyDigest"], str) or not isinstance(derivation["currentSensorSetDigest"], str):
        return False, "derivation-digest-invalid"
    return True, None


def source_dependencies(source: dict[str, Any]) -> tuple[str, str]:
    required = {"schemaVersion", "kind", "authorityId", "generation", "history", "currentSensors", "metadata"}
    if set(source) != required:
        raise ValueError("authoritative source fields differ")
    if source["schemaVersion"] != 1 or source["kind"] != SOURCE_KIND:
        raise ValueError("authoritative source identity is unsupported")
    if not isinstance(source["authorityId"], str) or not source["authorityId"]:
        raise ValueError("authorityId is required")
    if not isinstance(source["generation"], str) or not source["generation"]:
        raise ValueError("generation is required")
    if not isinstance(source["history"], dict) or not isinstance(source["currentSensors"], dict):
        raise ValueError("source dependencies must be objects")
    if not isinstance(source["metadata"], dict):
        raise ValueError("metadata must be an object")
    return canonical_digest(source["history"]), canonical_digest(source["currentSensors"])


def classify(projection: dict[str, Any], source: dict[str, Any] | None) -> dict[str, Any]:
    integrity_ok, integrity_error = projection_integrity(projection)
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ec1-derived-evidence-applicability",
        "ruleRevision": RULE_REVISION,
        "projectionDigest": projection.get("projectionDigest"),
        "projectionIntegrity": "valid" if integrity_ok else "invalid",
        "currentAuthorityAvailable": source is not None,
    }
    if not integrity_ok:
        result.update({"applicability": "INVALID", "reason": integrity_error})
        return result
    derivation = projection["derivation"]
    assert isinstance(derivation, dict)
    if source is None:
        result.update({
            "applicability": "UNKNOWN",
            "reason": "current-authoritative-source-unavailable",
            "derivationDependencies": {
                "historyDigest": derivation["historyDigest"],
                "currentSensorSetDigest": derivation["currentSensorSetDigest"],
            },
        })
        return result

    current_history_digest, current_sensor_digest = source_dependencies(source)
    history_match = derivation["historyDigest"] == current_history_digest
    sensor_match = derivation["currentSensorSetDigest"] == current_sensor_digest
    result.update({
        "authorityId": source["authorityId"],
        "currentGeneration": source["generation"],
        "sourceEnvelopeDigest": canonical_digest(source),
        "derivationDependencies": {
            "historyDigest": derivation["historyDigest"],
            "currentSensorSetDigest": derivation["currentSensorSetDigest"],
        },
        "currentDependencies": {
            "historyDigest": current_history_digest,
            "currentSensorSetDigest": current_sensor_digest,
        },
        "dependencyMatch": {
            "history": history_match,
            "currentSensors": sensor_match,
        },
    })
    if history_match and sensor_match:
        result.update({"applicability": "APPLICABLE", "reason": "exact-derivation-dependencies-current"})
    else:
        result.update({"applicability": "STALE_NOT_APPLICABLE", "reason": "one-or-more-derivation-dependencies-advanced"})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--projection", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source", type=Path)
    source.add_argument("--source-unavailable", action="store_true")
    args = parser.parse_args()
    try:
        projection = load_object(args.projection, label="projection")
        current_source = None if args.source_unavailable else load_object(args.source, label="source")
        result = classify(projection, current_source)
    except (OSError, ValueError, TypeError) as exc:
        print(f"ec1 applicability error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
