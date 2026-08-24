from __future__ import annotations

import unittest

from ordivon_security.ordinary_memory import (
    security_ordinary_provider_currentness,
    security_ordinary_research_inspect,
    security_ordinary_research_query,
)


class OrdinarySecurityMemoryTests(unittest.TestCase):
    def test_eicar_query_hides_storage_and_preserves_execution_boundary(self) -> None:
        value = security_ordinary_research_query("EICAR")
        self.assertEqual(value["candidateCount"], 1)
        candidate = value["candidates"][0]
        self.assertTrue(candidate["recordId"].startswith("sample:"))
        self.assertEqual(candidate["sampleStanding"]["executionAdmission"], "denied-by-default")
        self.assertNotIn("root", value)
        self.assertNotIn("corpusRoot", value)

    def test_semantic_phrase_ranks_eicar_without_requiring_exact_substring(self) -> None:
        value = security_ordinary_research_query(
            "EICAR test fixture malware classification provider claim"
        )
        self.assertGreaterEqual(value["candidateCount"], 1)
        candidate = value["candidates"][0]
        self.assertTrue(candidate["recordId"].startswith("sample:275a021b"))
        self.assertIn("eicar", candidate["matchedTerms"])
        self.assertGreater(candidate["score"], 1)

    def test_eicar_inspection_preserves_truth_roles_without_execution_authority(self) -> None:
        query = security_ordinary_research_query("EICAR")
        record_id = query["candidates"][0]["recordId"]
        value = security_ordinary_research_inspect(record_id)
        inspection = value["inspection"]
        fixture = inspection["claimsByTruthRole"]["maintained-fixture-fact"]
        provider = inspection["claimsByTruthRole"]["provider-claim"]
        self.assertEqual(
            [claim["value"] for claim in fixture if claim["predicate"] == "real-malware"],
            [False],
        )
        self.assertEqual(
            [
                claim["value"]
                for claim in provider
                if claim["predicate"] == "provider-signature-match"
            ],
            ["Eicar-Test-Signature"],
        )
        self.assertEqual(inspection["sample"]["executionAdmission"], "denied-by-default")
        self.assertFalse(value["claims"]["executionAuthorityGranted"])
        self.assertFalse(value["claims"]["corpusStorageCoordinateExposed"])

    def test_unknown_query_does_not_claim_external_absence(self) -> None:
        value = security_ordinary_research_query("definitely-not-a-retained-security-record")
        self.assertEqual(value["candidateCount"], 0)
        self.assertIn("external world", " ".join(value["boundaries"]))

    def test_provider_currentness_remains_read_only(self) -> None:
        value = security_ordinary_provider_currentness()
        self.assertFalse(value["claims"]["mutationPerformed"])
        self.assertFalse(value["claims"]["targetApplicabilityInferred"])
        self.assertFalse(value["claims"]["executionAuthorityGranted"])


if __name__ == "__main__":
    unittest.main()
