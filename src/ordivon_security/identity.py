from __future__ import annotations

import hashlib
import os
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

EVIDENCE_SCHEMA_REVISION = "2"


def _package_version() -> str:
    try:
        return version("ordivon-security")
    except PackageNotFoundError:
        return "0.3.0-dev"


def _repository_root() -> Path | None:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / ".git").exists():
            return parent
    return None


def security_source_identity() -> JsonObject:
    explicit = os.environ.get("ORDIVON_SECURITY_REVISION")
    if explicit:
        return {
            "componentId": "ordivon-security",
            "revision": explicit,
            "revisionKind": "operator-declared",
            "packageVersion": _package_version(),
        }
    repository = _repository_root()
    if repository is None:
        return {
            "componentId": "ordivon-security",
            "revision": f"package:{_package_version()}",
            "revisionKind": "package-version",
            "packageVersion": _package_version(),
        }
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain=v1", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    if not status:
        revision = f"git:{head}"
        revision_kind = "git-commit"
    else:
        digest = hashlib.sha256()
        digest.update(status)
        digest.update(
            subprocess.run(
                ["git", "-C", str(repository), "diff", "--binary", "HEAD", "--"],
                check=True,
                capture_output=True,
            ).stdout
        )
        for entry in status.split(b"\0"):
            if not entry.startswith(b"?? "):
                continue
            relative = entry[3:].decode("utf-8", errors="surrogateescape")
            path = repository / relative
            digest.update(relative.encode("utf-8", errors="surrogateescape"))
            if path.is_file():
                digest.update(path.read_bytes())
        revision = f"git:{head}+dirty:{digest.hexdigest()}"
        revision_kind = "git-working-tree"
    return {
        "componentId": "ordivon-security",
        "revision": revision,
        "revisionKind": revision_kind,
        "packageVersion": _package_version(),
    }


def build_trial_identity(
    *,
    range_identity: JsonObject,
    actor_identities: tuple[tuple[str, JsonObject], ...],
) -> JsonObject:
    validate_json(range_identity)
    for _, identity in actor_identities:
        validate_json(identity)
    return {
        "schemaVersion": 1,
        "kind": "ordivon.security.trial-identity",
        "contestCore": security_source_identity(),
        "evidenceSchemaRevision": EVIDENCE_SCHEMA_REVISION,
        "range": range_identity,
        "actors": [
            {"actorId": actor_id, "executionIdentity": identity}
            for actor_id, identity in actor_identities
        ],
    }


def trial_identity_digest(identity: JsonObject) -> str:
    return canonical_digest(identity)
