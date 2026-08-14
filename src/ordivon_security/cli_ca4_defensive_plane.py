from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .fixtures import CLEAN_TEST_BYTES, EICAR_TEST_BYTES

_EICAR = EICAR_TEST_BYTES
_CLEAN = CLEAN_TEST_BYTES


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _file_truth(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False, "sha256": None, "byteLength": 0}
    data = path.read_bytes()
    return {"present": True, "sha256": _sha256(data), "byteLength": len(data)}


def _provider_identity(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    version = subprocess.run(
        [str(path), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    ).stdout.splitlines()
    return {
        "path": str(path),
        "sha256": _sha256(raw),
        "version": version[0] if version else "unknown",
    }


def _raw_observe(path: Path) -> dict[str, Any]:
    stat = path.stat()
    data = path.read_bytes()
    return {
        "kind": "raw-artifact-observation",
        "path": path.name,
        "sha256": _sha256(data),
        "byteLength": len(data),
        "mode": stat.st_mode & 0o777,
        "worldTruthVerified": False,
    }


def _detect(clamscan: Path | None, path: Path) -> dict[str, Any]:
    if clamscan is None:
        return {
            "kind": "derived-detection",
            "providerAvailable": False,
            "status": "UNKNOWN_PROVIDER_UNAVAILABLE",
            "matched": None,
            "signature": None,
            "scannedSha256": _sha256(path.read_bytes()),
            "worldTruthVerified": False,
        }
    completed = subprocess.run(
        [str(clamscan), "--no-summary", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    line = completed.stdout.strip().splitlines()
    report = line[-1] if line else ""
    matched = completed.returncode == 1 and report.endswith(" FOUND")
    signature = None
    if matched and ": " in report:
        signature = report.rsplit(": ", 1)[1].removesuffix(" FOUND")
    return {
        "kind": "derived-detection",
        "providerAvailable": True,
        "exitCode": completed.returncode,
        "stdout": completed.stdout,
        "stderrSha256": _sha256(completed.stderr.encode()),
        "status": "MATCH"
        if matched
        else "NO_MATCH"
        if completed.returncode == 0
        else "PROVIDER_ERROR",
        "matched": matched,
        "signature": signature,
        "scannedSha256": _sha256(path.read_bytes()),
        "worldTruthVerified": False,
    }


def _adjudicate(
    *,
    observation: dict[str, Any],
    detection: dict[str, Any],
    current_truth: dict[str, Any],
    fixture_class: str,
) -> dict[str, Any]:
    if detection.get("providerAvailable") is False:
        return {
            "decision": "UNKNOWN_NO_RESPONSE",
            "reason": "detector unavailable",
            "fixtureClass": fixture_class,
            "worldTruthVerified": False,
        }
    if detection.get("scannedSha256") != current_truth.get("sha256"):
        return {
            "decision": "STALE_NOT_APPLICABLE",
            "reason": "detected bytes are not the current artifact bytes",
            "fixtureClass": fixture_class,
            "worldTruthVerified": False,
        }
    if observation.get("sha256") != detection.get("scannedSha256"):
        return {
            "decision": "CONFLICT_UNKNOWN",
            "reason": "raw observation and detector input identity disagree",
            "fixtureClass": fixture_class,
            "worldTruthVerified": False,
        }
    if detection.get("matched") is True:
        return {
            "decision": "QUARANTINE_TEST_PATTERN",
            "reason": "current bytes match a provider signature under the experiment response policy",
            "fixtureClass": fixture_class,
            "providerSignature": detection.get("signature"),
            "malwareTruthClaim": False,
            "worldTruthVerified": False,
        }
    return {
        "decision": "NO_RESPONSE",
        "reason": "no current provider match",
        "fixtureClass": fixture_class,
        "worldTruthVerified": False,
    }


def _respond(path: Path, quarantine: Path, adjudication: dict[str, Any]) -> dict[str, Any]:
    if adjudication.get("decision") != "QUARANTINE_TEST_PATTERN":
        return {
            "action": "none",
            "attempted": False,
            "worldTruthVerified": False,
        }
    quarantine.mkdir(parents=True, exist_ok=True)
    destination = quarantine / path.name
    os.replace(path, destination)
    return {
        "action": "quarantine-move",
        "attempted": True,
        "destination": destination.name,
        "receiptSha256": _sha256(destination.read_bytes()),
        "worldTruthVerified": False,
    }


def _run_case(root: Path, clamscan: Path, case: str) -> dict[str, Any]:
    case_root = root / case
    case_root.mkdir()
    artifact = case_root / "artifact.bin"
    quarantine = case_root / "quarantine"

    if case == "clean":
        artifact.write_bytes(_CLEAN)
        fixture_class = "known-clean"
        detector = clamscan
    elif case in {"eicar-current", "eicar-stale", "sensor-unavailable"}:
        artifact.write_bytes(_EICAR)
        fixture_class = "eicar-harmless-standard-test"
        detector = None if case == "sensor-unavailable" else clamscan
    else:
        raise ValueError(case)

    observation = _raw_observe(artifact)
    detection = _detect(detector, artifact)
    pre_adjudication_truth = _file_truth(artifact)

    if case == "eicar-stale":
        artifact.write_bytes(_CLEAN)

    current_truth = _file_truth(artifact)
    adjudication = _adjudicate(
        observation=observation,
        detection=detection,
        current_truth=current_truth,
        fixture_class=fixture_class,
    )
    response = _respond(artifact, quarantine, adjudication)
    post_truth = {
        "activeArtifact": _file_truth(artifact),
        "quarantinedArtifact": _file_truth(quarantine / artifact.name),
    }
    return {
        "case": case,
        "fixtureClass": fixture_class,
        "observation": observation,
        "detection": detection,
        "preAdjudicationTruth": pre_adjudication_truth,
        "currentTruth": current_truth,
        "adjudication": adjudication,
        "responseReceipt": response,
        "postResponseTruth": post_truth,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the bounded CA4 defensive evidence/response plane."
    )
    parser.add_argument("--output", type=Path)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    clamscan_raw = shutil.which("clamscan")
    if clamscan_raw is None:
        raise RuntimeError("CA4 requires the existing clamscan provider")
    clamscan = Path(clamscan_raw).resolve()
    provider_identity = {"clamscan": _provider_identity(clamscan)}

    with tempfile.TemporaryDirectory(prefix="ordivon-ca4-") as raw_root:
        root = Path(raw_root)
        cases = {
            name: _run_case(root, clamscan, name)
            for name in ("clean", "eicar-current", "eicar-stale", "sensor-unavailable")
        }
        clean = cases["clean"]
        current = cases["eicar-current"]
        stale = cases["eicar-stale"]
        unavailable = cases["sensor-unavailable"]
        gates = {
            "cleanRawObservationPresent": clean["observation"]["sha256"] == _sha256(_CLEAN),
            "cleanNoDetectionAndNoResponse": (
                clean["detection"]["matched"] is False
                and clean["adjudication"]["decision"] == "NO_RESPONSE"
                and clean["postResponseTruth"]["activeArtifact"]["present"] is True
            ),
            "eicarProviderDetectionObserved": (
                current["detection"]["matched"] is True
                and current["detection"]["signature"] is not None
            ),
            "detectionDoesNotClaimMalwareTruth": current["adjudication"].get("malwareTruthClaim")
            is False,
            "currentDetectionLeadsToQuarantineResponse": (
                current["adjudication"]["decision"] == "QUARANTINE_TEST_PATTERN"
                and current["responseReceipt"]["attempted"] is True
            ),
            "responseReceiptIsNotTruth": current["responseReceipt"]["worldTruthVerified"] is False,
            "postResponseTruthVerifiesQuarantine": (
                current["postResponseTruth"]["activeArtifact"]["present"] is False
                and current["postResponseTruth"]["quarantinedArtifact"]["present"] is True
                and current["postResponseTruth"]["quarantinedArtifact"]["sha256"] == _sha256(_EICAR)
            ),
            "staleDetectionRejectedAfterBytesChange": (
                stale["detection"]["matched"] is True
                and stale["currentTruth"]["sha256"] == _sha256(_CLEAN)
                and stale["adjudication"]["decision"] == "STALE_NOT_APPLICABLE"
                and stale["responseReceipt"]["attempted"] is False
            ),
            "sensorUnavailablePreservesUnknown": (
                unavailable["detection"]["status"] == "UNKNOWN_PROVIDER_UNAVAILABLE"
                and unavailable["adjudication"]["decision"] == "UNKNOWN_NO_RESPONSE"
                and unavailable["postResponseTruth"]["activeArtifact"]["present"] is True
            ),
        }
        payload = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ca4-defensive-plane",
            "authority": {
                "ownedLocalWorld": True,
                "realMalwareUsed": False,
                "eicarHarmlessTestPatternOnly": True,
                "networkUsed": False,
                "responseScope": "case-local quarantine move only",
            },
            "providerIdentity": provider_identity,
            "cases": list(cases.values()),
            "gates": gates,
            "interpretation": {
                "evidenceChain": [
                    "raw observation",
                    "provider-derived detection",
                    "current applicability adjudication",
                    "response receipt",
                    "fresh post-response truth",
                ],
                "staleness": "a valid detection over old bytes is not applicable to changed current bytes",
                "classificationBoundary": "EICAR provider detection is a correct test-signature classification, not a Security claim that real malware exists",
                "failureBoundary": "detector unavailability preserves UNKNOWN and does not authorize response by default",
                "nonClaim": "no real malware, EDR, SIEM, IDS, external endpoint, network sensor, autonomous response authority or omniscient Blue is implemented",
            },
        }
        encoded = json.dumps(payload, sort_keys=True, indent=2) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        if not all(gates.values()):
            raise SystemExit(2)


if __name__ == "__main__":
    main()
