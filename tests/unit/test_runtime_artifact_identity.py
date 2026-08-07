from __future__ import annotations

import unittest
from typing import cast

from ordivon_security._canonical import JsonObject
from ordivon_security.actors.runtime_assigned import _read_artifact
from ordivon_security.actors.runtime_mcp import RuntimeMcpClient, RuntimeMcpError

_DIGEST = "sha256:" + "1" * 64


class _ArtifactClient:
    def __init__(self, responses: list[JsonObject]) -> None:
        self.responses = list(responses)
        self.requests: list[JsonObject] = []

    def call_tool(self, name: str, arguments: JsonObject) -> JsonObject:
        if name != "artifact.read":
            raise AssertionError(name)
        self.requests.append(arguments)
        if not self.responses:
            raise AssertionError("unexpected artifact.read call")
        return self.responses.pop(0)


def _descriptor(*, retained_bytes: int = 31) -> JsonObject:
    return {
        "artifactId": "attempt-a1.stdout",
        "digest": _DIGEST,
        "retainedBytes": retained_bytes,
        "truncated": False,
    }


class RuntimeArtifactIdentityTests(unittest.TestCase):
    def test_complete_artifact_requires_digest_and_exact_retained_byte_count(self) -> None:
        client = _ArtifactClient(
            [
                {
                    "jobId": "job-a1",
                    "artifactId": "attempt-a1.stdout",
                    "content": "complete",
                    "offset": 0,
                    "nextOffset": 31,
                    "eof": True,
                    "digest": _DIGEST,
                }
            ]
        )
        self.assertEqual(
            _read_artifact(
                cast(RuntimeMcpClient, client),
                job_id="job-a1",
                descriptor=_descriptor(),
            ),
            "complete",
        )

    def test_early_eof_with_matching_digest_fails_closed_on_byte_count(self) -> None:
        client = _ArtifactClient(
            [
                {
                    "jobId": "job-a1",
                    "artifactId": "attempt-a1.stdout",
                    "content": "short-data",
                    "offset": 0,
                    "nextOffset": 10,
                    "eof": True,
                    "digest": _DIGEST,
                }
            ]
        )
        with self.assertRaisesRegex(
            RuntimeMcpError,
            "byte count differs from its descriptor",
        ):
            _read_artifact(
                cast(RuntimeMcpClient, client),
                job_id="job-a1",
                descriptor=_descriptor(),
            )

    def test_eof_overshoot_with_matching_digest_fails_closed_on_byte_count(self) -> None:
        client = _ArtifactClient(
            [
                {
                    "jobId": "job-a1",
                    "artifactId": "attempt-a1.stdout",
                    "content": "overshoot",
                    "offset": 0,
                    "nextOffset": 32,
                    "eof": True,
                    "digest": _DIGEST,
                }
            ]
        )
        with self.assertRaisesRegex(
            RuntimeMcpError,
            "byte count differs from its descriptor",
        ):
            _read_artifact(
                cast(RuntimeMcpClient, client),
                job_id="job-a1",
                descriptor=_descriptor(),
            )

    def test_digest_mismatch_still_fails_before_byte_count(self) -> None:
        client = _ArtifactClient(
            [
                {
                    "jobId": "job-a1",
                    "artifactId": "attempt-a1.stdout",
                    "content": "complete",
                    "offset": 0,
                    "nextOffset": 31,
                    "eof": True,
                    "digest": "sha256:" + "2" * 64,
                }
            ]
        )
        with self.assertRaisesRegex(RuntimeMcpError, "descriptor and read digest differ"):
            _read_artifact(
                cast(RuntimeMcpClient, client),
                job_id="job-a1",
                descriptor=_descriptor(),
            )


if __name__ == "__main__":
    unittest.main()
