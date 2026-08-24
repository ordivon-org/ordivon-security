from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ordivon_security.research_corpus import ResearchCorpus
from ordivon_security.research_corpus_sources import normalize_provider_record

ROOT = Path(__file__).resolve().parents[2]


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def count_role(inspection: dict, role: str) -> int:
    return len(inspection["claimsByTruthRole"][role])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ordivon-security-memory-") as td:
        corpus = ResearchCorpus(Path(td) / "corpus")
        seed_paths = (
            "research/corpus/seed-ca2-vulnerability.json",
            "research/corpus/seed-eicar-sample.json",
            "research/corpus/seed-caseb-sample-postedge.json",
        )
        seeds = {name: load(name) for name in seed_paths}
        for record in seeds.values():
            corpus.register(record)

        ca2 = corpus.inspect(str(seeds[seed_paths[0]]["recordId"]))
        eicar = corpus.inspect(str(seeds[seed_paths[1]]["recordId"]))
        目标产品B = corpus.inspect(str(seeds[seed_paths[2]]["recordId"]))

        old = normalize_provider_record("osv", load("research/corpus/k1/controlled-osv-old.json"))
        current = normalize_provider_record(
            "osv", load("research/corpus/k1/controlled-osv-current.json")
        )
        corpus.register(old)
        comparison = corpus.compare_candidate(current)

        eicar_fixture_claims = eicar["claimsByTruthRole"]["maintained-fixture-fact"]
        eicar_real_malware = [
            claim.get("value")
            for claim in eicar_fixture_claims
            if claim.get("predicate") == "real-malware"
        ]
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ordinary-research-memory-dogfood",
            "questions": {
                "ca2EvidenceRoles": {
                    "providerClaims": count_role(ca2, "provider-claim"),
                    "independentObservations": count_role(ca2, "independent-observation"),
                    "answeredBy": "ResearchCorpus.inspect",
                },
                "eicarClassification": {
                    "realMalware": eicar_real_malware[0] if eicar_real_malware else None,
                    "providerClaims": count_role(eicar, "provider-claim"),
                    "executionAdmission": eicar["sample"]["executionAdmission"],
                    "answeredBy": "ResearchCorpus.inspect",
                },
                "目标产品BCurrentCaseState": {
                    "caseConclusions": count_role(目标产品B, "case-conclusion"),
                    "independentObservations": count_role(目标产品B, "independent-observation"),
                    "materialization": 目标产品B["sample"]["materialization"],
                    "executionAdmission": 目标产品B["sample"]["executionAdmission"],
                    "answeredBy": "ResearchCorpus.inspect",
                },
                "providerCurrentness": {
                    "status": comparison["status"],
                    "mutationPerformed": comparison["mutationPerformed"],
                    "sourceChanges": len(comparison["sourceChanges"]),
                    "answeredBy": "ResearchCorpus.compare_candidate",
                },
                "genericRecoveryLaw": {
                    "corpusMatches": len(corpus.query("compensation")),
                    "answeredBy": "canonical-docs-not-corpus",
                },
            },
            "verification": corpus.verify(),
            "interpretation": {
                "ordinaryPreAnalysisReadEarned": True,
                "bulkHistoricalImportEarned": False,
                "newRecordKindEarned": False,
                "genericResearchLawMemoryRemainsDocsOwned": True,
            },
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
