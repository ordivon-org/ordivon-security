from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ordivon_security.fixtures import CLEAN_TEST_BYTES, EICAR_TEST_BYTES
from ordivon_security.research_corpus import ResearchCorpus

ROOT = Path(__file__).resolve().parents[2]
EICAR_ID = "sample:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def detect(path: Path) -> dict:
    proc = subprocess.run(
        ["/usr/bin/clamscan", "--no-summary", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    out = proc.stdout.strip()
    signature = "Eicar-Test-Signature" if "Eicar-Test-Signature" in out else None
    return {
        "provider": "clamscan",
        "returnCode": proc.returncode,
        "signature": signature,
        "artifactDigest": digest(path.read_bytes()),
        "providerMatched": signature is not None,
    }


def run_treatment(root: Path, *, stale: bool) -> dict:
    active = root / "active" / "incident.bin"
    quarantine = root / "quarantine" / "incident.bin"
    active.parent.mkdir(parents=True)
    quarantine.parent.mkdir(parents=True)
    active.write_bytes(EICAR_TEST_BYTES)
    detection = detect(active)
    if stale:
        active.write_bytes(CLEAN_TEST_BYTES)
    current_digest = digest(active.read_bytes())
    applicable = detection["providerMatched"] and detection["artifactDigest"] == current_digest
    response = "none"
    if applicable:
        shutil.move(active, quarantine)
        response = "quarantine-move"
    post = {
        "activeExists": active.exists(),
        "quarantineExists": quarantine.exists(),
        "activeDigest": digest(active.read_bytes()) if active.exists() else None,
        "quarantineDigest": digest(quarantine.read_bytes()) if quarantine.exists() else None,
    }
    return {
        "treatment": "stale-detection" if stale else "current-detection",
        "detection": detection,
        "currentDigestAtAdjudication": current_digest,
        "adjudication": ("CURRENT_MATCH_RESPONSE" if applicable else "STALE_NOT_APPLICABLE"),
        "responseReceipt": {
            "action": response,
            "worldTruthVerified": False,
        },
        "postResponseTruth": post,
    }


def main() -> None:
    seed = json.loads((ROOT / "research/corpus/seed-eicar-sample.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="ordivon-security-blue-") as td:
        root = Path(td)
        corpus = ResearchCorpus(root / "corpus")
        corpus.register(seed)
        memory = corpus.inspect(EICAR_ID)
        fixture_claims = memory["claimsByTruthRole"]["maintained-fixture-fact"]
        real_malware = [
            claim.get("value")
            for claim in fixture_claims
            if claim.get("predicate") == "real-malware"
        ]
        current = run_treatment(root / "current", stale=False)
        stale = run_treatment(root / "stale", stale=True)
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ordinary-blue-incident-consumer",
            "memory": {
                "recordId": memory["recordId"],
                "realMalware": real_malware[0] if real_malware else None,
                "executionAdmission": memory["sample"]["executionAdmission"],
                "providerClaimCount": len(memory["claimsByTruthRole"]["provider-claim"]),
            },
            "treatments": [current, stale],
            "gates": {
                "fixtureIsNotPromotedToMalwareTruth": real_malware == [False],
                "currentDetectionProducesBoundedResponse": (
                    current["adjudication"] == "CURRENT_MATCH_RESPONSE"
                    and current["postResponseTruth"]["activeExists"] is False
                    and current["postResponseTruth"]["quarantineExists"] is True
                    and current["postResponseTruth"]["quarantineDigest"] == digest(EICAR_TEST_BYTES)
                ),
                "staleDetectionProducesNoResponse": (
                    stale["adjudication"] == "STALE_NOT_APPLICABLE"
                    and stale["postResponseTruth"]["activeExists"] is True
                    and stale["postResponseTruth"]["quarantineExists"] is False
                    and stale["postResponseTruth"]["activeDigest"] == digest(CLEAN_TEST_BYTES)
                ),
                "responseReceiptNotTruth": all(
                    item["responseReceipt"]["worldTruthVerified"] is False
                    for item in (current, stale)
                ),
                "newTelemetryProviderRequired": False,
            },
            "interpretation": {
                "ordinaryCompositionSucceeded": True,
                "newIncidentWorkflowAbstractionEarned": False,
                "sysmonOrEdrEarned": False,
                "higherFidelityNetworkTransferEarned": False,
            },
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
