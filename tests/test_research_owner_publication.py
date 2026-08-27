from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "research" / "security" / "authority"
CURRENT = AUTH / "CURRENT.json"


class SecurityResearchOwnerPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = json.loads(CURRENT.read_text())
        cls.publication_path = ROOT / "research" / "security" / cls.current["publication"]
        cls.publication = json.loads(cls.publication_path.read_text())
        cls.manifest_path = ROOT / cls.publication["source"]["aggregateManifest"]
        cls.manifest = json.loads(cls.manifest_path.read_text())

    def test_current_pointer_binds_immutable_publication(self):
        observed = "sha256:" + hashlib.sha256(self.publication_path.read_bytes()).hexdigest()
        self.assertEqual(observed, self.current["currentAuthorityVersionRef"])
        self.assertEqual(self.current["ownerResearchRef"], "research-owner:security")
        self.assertEqual(self.current["authorityRef"], "authority:ordivon:research-owner:security")

    def test_manifest_digest_and_77_anchors_revalidate(self):
        observed = "sha256:" + hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self.assertEqual(observed, self.publication["source"]["aggregateManifestDigest"])
        self.assertEqual(self.manifest["inventory"]["canonicalDocs"], 73)
        self.assertEqual(len(self.manifest["anchors"]), 77)
        for anchor in self.manifest["anchors"]:
            payload = subprocess.run(["git", "show", f"{anchor['revision']}:{anchor['path']}"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
            self.assertEqual(len(payload), anchor["bytes"], anchor["path"])
            self.assertEqual("sha256:" + hashlib.sha256(payload).hexdigest(), anchor["sha256"], anchor["path"])

    def test_current_recovery_is_owner_native_authority_map(self):
        self.assertEqual(self.publication["currentRecovery"], {"targetRole": "OWNER_RESEARCH_AUTHORITY_MAP", "locator": "docs/authority.md"})
        self.assertTrue((ROOT / "docs" / "authority.md").is_file())

    def test_projection_is_bounded_not_second_authority_map(self):
        result_refs = {s["subjectRef"] for s in self.publication["statements"] if s.get("scope") == "RESULT"}
        closeout_refs = {r for c in self.publication["closeouts"] for r in c.get("resultRefs", [])}
        self.assertEqual(result_refs, closeout_refs)
        self.assertEqual(len(result_refs), 20)
        self.assertLess(len(result_refs), self.manifest["inventory"]["canonicalDocs"])

    def test_negative_and_historical_standing_are_not_promoted(self):
        standing = {(s.get("subjectRef"), s.get("predicate")) for s in self.publication["statements"] if s.get("value") is True}
        self.assertIn(("result:security:ae3b-raw-history-falsified", "STANDING:FALSIFIED"), standing)
        self.assertIn(("result:security:ca7-campaign-organization-not-admitted", "STANDING:NOT_ADMITTED"), standing)
        self.assertIn(("result:security:ace0-direct-representation-poison-sufficient-falsified", "STANDING:FALSIFIED"), standing)
        self.assertIn(("result:security:ordinary-mechanical-preflight-current", "STANDING:CURRENT"), standing)
        self.assertIn(("result:security:whole-domain-exhaustive-not-claimed", "STANDING:NOT_CLAIMED"), standing)
        self.assertIn(("result:security:w5b-historical-current-relevant", "STANDING:HISTORICAL_VALID"), standing)
        self.assertNotIn(("result:security:w5b-historical-current-relevant", "STANDING:ACCEPTED"), standing)

    def test_authority_map_routes_all_canonical_docs(self):
        import re
        canonical=[]
        for p in sorted((ROOT / "docs").glob("*.md")):
            t=p.read_text(errors="replace")
            if t.startswith("---\n") and re.search(r"(?m)^source_role:\s*canonical\s*$", t.split("---",2)[1]):
                canonical.append(p)
        links=set(re.findall(r"\]\(([^)#?]+)", (ROOT / "docs" / "authority.md").read_text()))
        uncovered=[p.name for p in canonical if p.name != "authority.md" and p.name not in links]
        self.assertEqual(len(canonical), 73)
        self.assertEqual(uncovered, [])


if __name__ == "__main__":
    unittest.main()
