from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ordivon_security.evaluation import SampleVault
from ordivon_security.research_corpus import ResearchCorpus, validate_corpus_record


class ResearchCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.corpus = ResearchCorpus(self.root / "corpus")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _sample_record(self) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "recordKind": "sample",
            "recordId": "sample:" + "a" * 64,
            "sample": {
                "sha256": "sha256:" + "a" * 64,
                "byteLength": 3,
                "mediaType": "application/octet-stream",
                "originalName": "x.bin",
                "artifactRole": "third-party-artifact",
                "materialization": "metadata-only",
                "executionAdmission": "denied-by-default",
            },
            "sourceRefs": [{"provider": "test", "recordId": "r1"}],
            "claims": [],
            "evidenceRefs": [],
        }

    def test_sample_execution_is_denied_by_schema(self) -> None:
        record = self._sample_record()
        record["sample"]["executionAdmission"] = "allowed"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "denied-by-default"):
            validate_corpus_record(record)  # type: ignore[arg-type]

    def test_sample_manifest_rejects_embedded_bytes(self) -> None:
        record = self._sample_record()
        record["metadata"] = {"payloadBytes": "AAAA"}
        with self.assertRaisesRegex(ValueError, "must not embed Sample bytes"):
            validate_corpus_record(record)  # type: ignore[arg-type]

    def test_registration_is_revisioned_and_verifiable(self) -> None:
        first = self._sample_record()
        receipt1 = self.corpus.register(first)  # type: ignore[arg-type]
        self.assertIsNone(receipt1.previous_digest)
        second = json.loads(json.dumps(first))
        second["claims"] = [
            {
                "claimId": "provider-classification",
                "predicate": "family",
                "value": "example",
                "truthRole": "provider-claim",
                "assertedBy": "test-provider",
                "evidenceRefs": [],
            }
        ]
        receipt2 = self.corpus.register(second)
        self.assertEqual(receipt2.previous_digest, receipt1.record_digest)
        self.assertNotEqual(receipt2.record_digest, receipt1.record_digest)
        current = self.corpus.load(str(first["recordId"]), record_kind="sample")
        self.assertEqual(current["claims"], second["claims"])
        verification = self.corpus.verify()
        self.assertTrue(verification["verified"])
        self.assertEqual(verification["sampleCount"], 1)

    def test_local_sample_import_binds_vault_but_does_not_grant_execution(self) -> None:
        source = self.root / "specimen.bin"
        source.write_bytes(b"owned synthetic specimen")
        vault = SampleVault(self.root / "vault")
        sample, registration = self.corpus.import_local_sample(
            vault=vault,
            path=source,
            artifact_role="owned-synthetic",
        )
        self.assertTrue(vault.resolve(sample).is_file())
        record = self.corpus.load(registration.record_id, record_kind="sample")
        self.assertEqual(record["sample"]["materialization"], "sample-vault")
        self.assertEqual(record["sample"]["executionAdmission"], "denied-by-default")

    def test_sample_record_id_must_match_content_identity(self) -> None:
        record = self._sample_record()
        record["recordId"] = "sample:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "must equal its SHA-256"):
            validate_corpus_record(record)  # type: ignore[arg-type]

    def test_verify_checks_historical_revisions_not_only_current_head(self) -> None:
        first = self._sample_record()
        receipt1 = self.corpus.register(first)  # type: ignore[arg-type]
        second = json.loads(json.dumps(first))
        second["metadata"] = {"revision": 2}
        self.corpus.register(second)
        old_revision = self.corpus.root / receipt1.revision_path
        old_revision.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.corpus.verify()

    def test_head_cannot_redirect_to_an_unbound_revision_path(self) -> None:
        record = self._sample_record()
        self.corpus.register(record)  # type: ignore[arg-type]
        head_path = self.corpus._head_path("sample", str(record["recordId"]))
        head = json.loads(head_path.read_text(encoding="utf-8"))
        head["revisionPath"] = "../../outside.json"
        head_path.write_text(json.dumps(head), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "revision path"):
            self.corpus.load(str(record["recordId"]), record_kind="sample")

    def test_inspection_keeps_claim_role_and_execution_admission_explicit(self) -> None:
        record = self._sample_record()
        record["claims"] = [
            {
                "claimId": "provider-label",
                "predicate": "provider-family-label",
                "value": "ExampleFamily",
                "truthRole": "provider-claim",
                "assertedBy": "example-provider",
                "evidenceRefs": [],
            }
        ]
        self.corpus.register(record)  # type: ignore[arg-type]
        projection = self.corpus.inspect(str(record["recordId"]), record_kind="sample")
        self.assertEqual(projection["sample"]["executionAdmission"], "denied-by-default")
        self.assertEqual(len(projection["claimsByTruthRole"]["provider-claim"]), 1)
        self.assertEqual(projection["claimsByTruthRole"]["independent-observation"], [])

    def test_compare_candidate_is_read_only_and_reports_source_change(self) -> None:
        current = {
            "schemaVersion": 1,
            "recordKind": "vulnerability",
            "recordId": "vuln:osv:CVE-K1-0001",
            "subject": {"targetScope": "external-advisory-only", "revisions": []},
            "sourceRefs": [
                {
                    "provider": "osv",
                    "recordId": "CVE-K1-0001",
                    "snapshotDigest": "sha256:" + "1" * 64,
                    "providerModified": "2026-01-01T00:00:00Z",
                }
            ],
            "claims": [],
            "evidenceRefs": [],
        }
        self.corpus.register(current)  # type: ignore[arg-type]
        candidate = json.loads(json.dumps(current))
        candidate["sourceRefs"][0]["snapshotDigest"] = "sha256:" + "2" * 64
        candidate["sourceRefs"][0]["providerModified"] = "2026-08-14T00:00:00Z"
        before = self.corpus.load("vuln:osv:CVE-K1-0001", record_kind="vulnerability")
        comparison = self.corpus.compare_candidate(candidate)  # type: ignore[arg-type]
        after = self.corpus.load("vuln:osv:CVE-K1-0001", record_kind="vulnerability")
        self.assertEqual(comparison["status"], "changed")
        self.assertTrue(comparison["recordChanged"])
        self.assertFalse(comparison["mutationPerformed"])
        self.assertEqual(len(comparison["sourceChanges"]), 1)
        self.assertEqual(
            comparison["sourceChanges"][0]["candidateProviderModified"],
            "2026-08-14T00:00:00Z",
        )
        self.assertEqual(before, after)

    def test_compare_candidate_reports_unchanged_and_not_registered(self) -> None:
        record = {
            "schemaVersion": 1,
            "recordKind": "vulnerability",
            "recordId": "vuln:osv:CVE-K1-0002",
            "subject": {"targetScope": "external-advisory-only", "revisions": []},
            "sourceRefs": [
                {
                    "provider": "osv",
                    "recordId": "CVE-K1-0002",
                    "snapshotDigest": "sha256:" + "3" * 64,
                    "providerModified": "2026-08-14T00:00:00Z",
                }
            ],
            "claims": [],
            "evidenceRefs": [],
        }
        missing = self.corpus.compare_candidate(record)  # type: ignore[arg-type]
        self.assertEqual(missing["status"], "not-registered")
        self.corpus.register(record)  # type: ignore[arg-type]
        unchanged = self.corpus.compare_candidate(record)  # type: ignore[arg-type]
        self.assertEqual(unchanged["status"], "unchanged")
        self.assertFalse(unchanged["recordChanged"])
        self.assertEqual(unchanged["sourceChanges"], [])

    def test_seed_records_are_valid_and_do_not_embed_sample_bytes(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        seeds = sorted((repo / "research" / "corpus").glob("seed-*.json"))
        self.assertGreaterEqual(len(seeds), 3)
        for path in seeds:
            value = json.loads(path.read_text(encoding="utf-8"))
            validate_corpus_record(value)
            self.corpus.register(value)
        verification = self.corpus.verify()
        self.assertEqual(verification["sampleCount"], 2)
        self.assertEqual(verification["vulnerabilityCount"], 1)


if __name__ == "__main__":
    unittest.main()
