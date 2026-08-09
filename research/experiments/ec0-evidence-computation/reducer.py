#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REDUCER_REVISION = "ae3c-exact-evidence-reduction-v1"
SOURCE_IDS = ("sensor:ae2-a", "sensor:ae2-b")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_object(value: Any, *, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    if set(value) != fields:
        raise ValueError(f"{label} fields differ")
    return value


def load_input(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("input is not valid JSON") from exc
    root = require_object(value, label="EC0 input", fields={"schemaVersion", "kind", "history", "currentSensors"})
    if root["schemaVersion"] != 1 or root["kind"] != "ordivon.security.ec0-evidence-computation-input":
        raise ValueError("EC0 input identity is unsupported")
    history = require_object(root["history"], label="history", fields={"schemaVersion", "episodes"})
    sensors = require_object(root["currentSensors"], label="currentSensors", fields={"schemaVersion", "observations"})
    if history["schemaVersion"] != 1 or sensors["schemaVersion"] != 1:
        raise ValueError("input schemaVersion is unsupported")
    if not isinstance(history["episodes"], list) or not history["episodes"]:
        raise ValueError("history episodes must be a non-empty array")
    if not isinstance(sensors["observations"], list) or len(sensors["observations"]) != len(SOURCE_IDS):
        raise ValueError("current sensor set must contain the exact source cardinality")
    return history, sensors


def reduce(history: dict[str, Any], sensors: dict[str, Any]) -> dict[str, Any]:
    current_by_source: dict[str, bool] = {}
    for item in sensors["observations"]:
        observation = require_object(item, label="current sensor observation", fields={"observationId", "sourceId", "property", "value", "observationAuthority", "sourceClass"})
        source_id = observation["sourceId"]
        value = observation["value"]
        if source_id not in SOURCE_IDS or not isinstance(value, bool):
            raise ValueError("current sensor identity/value is invalid")
        if source_id in current_by_source:
            raise ValueError("duplicate current sensor source")
        current_by_source[source_id] = value
    if tuple(current_by_source) != SOURCE_IDS:
        raise ValueError("current sensors must preserve the accepted source order")

    match_counts = {source_id: 0 for source_id in SOURCE_IDS}
    matching_episode_ids: list[str] = []
    adjudicated_true = 0
    adjudicated_false = 0
    episode_ids: list[str] = []
    for raw_episode in history["episodes"]:
        episode = require_object(raw_episode, label="history episode", fields={"episodeId", "sensorObservations", "adjudicatedWorldTruth"})
        episode_id = episode["episodeId"]
        if not isinstance(episode_id, str) or not episode_id:
            raise ValueError("history episodeId is invalid")
        truth = require_object(episode["adjudicatedWorldTruth"], label="adjudicatedWorldTruth", fields={"serviceCompromised", "truthAuthority"})["serviceCompromised"]
        if not isinstance(truth, bool):
            raise ValueError("adjudicated truth must be boolean")
        observations = episode["sensorObservations"]
        if not isinstance(observations, list) or len(observations) != len(SOURCE_IDS):
            raise ValueError("historical sensor observation cardinality differs")
        observed: dict[str, bool] = {}
        for raw_observation in observations:
            observation = require_object(raw_observation, label="historical sensor observation", fields={"sourceId", "property", "value"})
            source_id = observation["sourceId"]
            value = observation["value"]
            if source_id not in SOURCE_IDS or not isinstance(value, bool):
                raise ValueError("historical sensor identity/value is invalid")
            if source_id in observed:
                raise ValueError("duplicate historical sensor source")
            observed[source_id] = value
            if value == truth:
                match_counts[source_id] += 1
        if tuple(observed) != SOURCE_IDS:
            raise ValueError("historical sensors must preserve the accepted source order")
        episode_ids.append(episode_id)
        if observed == current_by_source:
            matching_episode_ids.append(episode_id)
            if truth:
                adjudicated_true += 1
            else:
                adjudicated_false += 1

    body: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ae3c-derived-factual-projection",
        "projectionId": "evidence-projection:ae3c:" + canonical_digest(history).removeprefix("sha256:")[:16],
        "derivation": {
            "reducerRevision": REDUCER_REVISION,
            "historyDigest": canonical_digest(history),
            "currentSensorSetDigest": canonical_digest(sensors),
            "episodeIds": episode_ids,
        },
        "sourceMatchCounts": [
            {"sourceId": source_id, "matchedAdjudicatedTruthCount": match_counts[source_id], "episodeCount": len(history["episodes"])}
            for source_id in SOURCE_IDS
        ],
        "currentPatternPriorOccurrences": {
            "sensorValues": [{"sourceId": source_id, "value": current_by_source[source_id]} for source_id in SOURCE_IDS],
            "matchingEpisodeIds": matching_episode_ids,
            "occurrenceCount": len(matching_episode_ids),
            "adjudicatedTrueCount": adjudicated_true,
            "adjudicatedFalseCount": adjudicated_false,
        },
    }
    projection = dict(body)
    projection["projectionDigest"] = canonical_digest(body)
    return projection


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        history, sensors = load_input(args.input)
        projection = reduce(history, sensors)
    except (OSError, ValueError, TypeError) as exc:
        print(f"ec0 reducer error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(projection) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
