from __future__ import annotations

import unittest

from ordivon_security.research_corpus import validate_corpus_record
from ordivon_security.research_corpus_sources import (
    normalize_cisa_kev_vulnerability,
    normalize_malwarebazaar_sample,
    normalize_nvd_vulnerability,
    normalize_osv_vulnerability,
    normalize_virustotal_sample,
)


class ResearchCorpusSourceTests(unittest.TestCase):
    def test_osv_normalizer_preserves_external_advisory_boundary(self) -> None:
        record = normalize_osv_vulnerability(
            {
                "id": "OSV-TEST-1",
                "modified": "2026-08-14T00:00:00Z",
                "aliases": ["CVE-2099-0001"],
                "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}, "ranges": []}],
            }
        )
        validate_corpus_record(record)
        self.assertEqual(record["subject"]["revisions"], [])
        self.assertEqual(record["subject"]["targetScope"], "external-advisory-only")
        self.assertEqual(record["sourceRefs"][0]["provider"], "osv")

    def test_nvd_normalizer_does_not_claim_target_exploitability(self) -> None:
        record = normalize_nvd_vulnerability(
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "lastModified": "2099-01-01T00:00:00.000",
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-120"}]}],
                }
            }
        )
        validate_corpus_record(record)
        self.assertEqual(record["claims"][0]["truthRole"], "provider-claim")
        self.assertEqual(record["subject"]["revisions"], [])

    def test_cisa_kev_is_provider_claim_not_local_truth(self) -> None:
        record = normalize_cisa_kev_vulnerability(
            {
                "cveID": "CVE-2099-0001",
                "dateAdded": "2099-01-02",
                "vendorProject": "Example",
                "product": "Demo",
            }
        )
        validate_corpus_record(record)
        self.assertEqual(record["claims"][0]["predicate"], "known-exploited-in-the-wild")
        self.assertEqual(record["claims"][0]["truthRole"], "provider-claim")

    def test_nvd_official_envelope_is_consumed_without_manual_preprocessing(self) -> None:
        record = normalize_nvd_vulnerability(
            {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2099-0002",
                            "lastModified": "2099-01-03T00:00:00.000",
                            "weaknesses": [],
                        }
                    }
                ],
            }
        )
        validate_corpus_record(record)
        self.assertEqual(record["recordId"], "vuln:nvd:CVE-2099-0002")
        self.assertEqual(record["sourceRefs"][0]["provider"], "nvd")

    def test_cisa_catalog_requires_exact_record_selection(self) -> None:
        snapshot = {
            "catalogVersion": "2099.1",
            "dateReleased": "2099-01-04T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-0003",
                    "dateAdded": "2099-01-04",
                    "vendorProject": "Example A",
                    "product": "Demo A",
                },
                {
                    "cveID": "CVE-2099-0004",
                    "dateAdded": "2099-01-04",
                    "vendorProject": "Example B",
                    "product": "Demo B",
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "requires record_id"):
            normalize_cisa_kev_vulnerability(snapshot)
        record = normalize_cisa_kev_vulnerability(snapshot, record_id="CVE-2099-0004")
        validate_corpus_record(record)
        self.assertEqual(record["recordId"], "vuln:cisa-kev:CVE-2099-0004")
        self.assertEqual(record["metadata"]["product"], "Demo B")

    def test_malwarebazaar_metadata_never_materializes_bytes_or_exec_authority(self) -> None:
        record = normalize_malwarebazaar_sample(
            {
                "sha256_hash": "b" * 64,
                "file_size": 123,
                "file_name": "sample.exe",
                "file_type_mime": "application/x-dosexec",
                "signature": "ExampleFamily",
                "tags": ["exe"],
            }
        )
        validate_corpus_record(record)
        self.assertEqual(record["sample"]["materialization"], "metadata-only")
        self.assertEqual(record["sample"]["executionAdmission"], "denied-by-default")
        self.assertTrue(all(c["truthRole"] == "provider-claim" for c in record["claims"]))

    def test_virustotal_metadata_never_promotes_analysis_stats_to_truth(self) -> None:
        record = normalize_virustotal_sample(
            {
                "data": {
                    "id": "c" * 64,
                    "attributes": {
                        "size": 456,
                        "names": ["artifact.bin"],
                        "type_description": "Win32 EXE",
                        "last_analysis_stats": {"malicious": 42, "undetected": 10},
                    },
                }
            }
        )
        validate_corpus_record(record)
        stats = next(c for c in record["claims"] if c["claimId"] == "virustotal-analysis-stats")
        self.assertEqual(stats["truthRole"], "provider-claim")
        self.assertEqual(record["sample"]["executionAdmission"], "denied-by-default")


if __name__ == "__main__":
    unittest.main()
