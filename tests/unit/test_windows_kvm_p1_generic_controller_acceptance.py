from __future__ import annotations

import json
import unittest
from pathlib import Path


class WindowsKvmP1GenericControllerAcceptanceTests(unittest.TestCase):
    def test_public_acceptance_keeps_case_a_closed(self) -> None:
        path = (
            Path(__file__).parents[2]
            / "evidence"
            / "acceptance"
            / "windows-kvm-p1-generic-controller-e352e86.json"
        )
        index = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["status"], "accepted-generic-controller-self-test")
        self.assertEqual(
            index["implementationRevision"],
            "git:e352e86228b99669035a5d05593adc4a10a8d5f5",
        )
        self.assertIs(index["scope"]["maintainedSelfTest"], True)
        self.assertIs(index["scope"]["thirdPartySample"], False)
        self.assertIs(index["scope"]["actualCaseAExecuted"], False)
        self.assertIs(index["scope"]["arbitraryExecutableTarget"], False)
        self.assertEqual(index["scope"]["productionTarget"], "sealed-p1-orchestrator-only")
        self.assertIs(index["scope"]["controllerSealedInP1Base"], False)
        self.assertIs(index["scope"]["caseAExecutionAuthorized"], False)
        self.assertEqual(
            index["controller"]["executableDigest"],
            "sha256:eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a",
        )
        self.assertIs(index["controller"]["vaultObjectVerified"], True)
        self.assertIs(index["controller"]["rebuildByteIdentityAssumed"], False)
        for gate in (
            "manifestDigestVerified",
            "normalChildCompleted",
            "normalMarkerObserved",
            "timeoutObserved",
            "timeoutChildTerminated",
            "timeoutMarkerAbsent",
            "jobTotalProcessesObserved",
            "qmpNoNetworkDevice",
            "providerErrorAbsent",
            "residualClosure",
        ):
            self.assertIs(index["gates"][gate], True)
        self.assertIs(index["gates"]["networkRequested"], False)


if __name__ == "__main__":
    unittest.main()
