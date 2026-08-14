from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ordivon_security._canonical import (
    JsonObject,
    canonical_bytes,
    canonical_digest,
    validate_json,
)
from ordivon_security.evaluation.models import SampleIdentity
from ordivon_security.evaluation.vault import SampleVault

_CORPUS_KINDS = frozenset({"sample", "vulnerability"})
_SAMPLE_MATERIALIZATIONS = frozenset({"metadata-only", "sample-vault", "maintained-source-fixture"})
_SAMPLE_ROLES = frozenset({"third-party-artifact", "owned-synthetic", "maintained-test-fixture"})
_CLAIM_TRUTH_ROLES = frozenset(
    {
        "provider-claim",
        "independent-observation",
        "maintained-fixture-fact",
        "case-conclusion",
    }
)
_EXECUTION_ADMISSION = "denied-by-default"
_FORBIDDEN_EMBEDDED_KEYS = frozenset(
    {
        "samplebytes",
        "sample_bytes",
        "payloadbytes",
        "payload_bytes",
        "blobbytes",
        "blob_bytes",
        "base64bytes",
        "base64_bytes",
    }
)


@dataclass(frozen=True, slots=True)
class CorpusHead:
    record_id: str
    record_kind: str
    record_digest: str
    revision_path: str

    def to_dict(self) -> JsonObject:
        return {
            "recordId": self.record_id,
            "recordKind": self.record_kind,
            "recordDigest": self.record_digest,
            "revisionPath": self.revision_path,
        }


@dataclass(frozen=True, slots=True)
class CorpusRegistration:
    record_id: str
    record_kind: str
    record_digest: str
    previous_digest: str | None
    revision_path: str
    receipt_path: str

    def to_dict(self) -> JsonObject:
        return {
            "recordId": self.record_id,
            "recordKind": self.record_kind,
            "recordDigest": self.record_digest,
            "previousDigest": self.previous_digest,
            "revisionPath": self.revision_path,
            "receiptPath": self.receipt_path,
        }


def _require_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Corpus field {field} must be a non-empty string")
    return value


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Corpus field {field} must be a non-negative integer")
    return value


def _require_list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"Corpus field {field} must be a list")
    return value


def _require_dict(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Corpus field {field} must be an object")
    return value


def _validate_sha256(value: object, field: str) -> str:
    text = _require_string(value, field)
    if not text.startswith("sha256:") or len(text) != 71:
        raise ValueError(f"Corpus field {field} must use sha256:<64 hex>")
    try:
        int(text.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise ValueError(f"Corpus field {field} contains invalid SHA-256 hex") from exc
    return text.lower()


def _reject_embedded_bytes(value: object, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in _FORBIDDEN_EMBEDDED_KEYS:
                raise ValueError(f"Corpus records must not embed Sample bytes: {path}.{key}")
            _reject_embedded_bytes(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_embedded_bytes(child, path=f"{path}[{index}]")


def _validate_source_refs(value: object) -> None:
    for index, source in enumerate(_require_list(value, "sourceRefs")):
        item = _require_dict(source, f"sourceRefs[{index}]")
        _require_string(item.get("provider"), f"sourceRefs[{index}].provider")
        _require_string(item.get("recordId"), f"sourceRefs[{index}].recordId")
        if item.get("snapshotDigest") is not None:
            _validate_sha256(item.get("snapshotDigest"), f"sourceRefs[{index}].snapshotDigest")
        if item.get("locator") is not None:
            _require_string(item.get("locator"), f"sourceRefs[{index}].locator")
        if item.get("retrievedAt") is not None:
            _require_string(item.get("retrievedAt"), f"sourceRefs[{index}].retrievedAt")
        if item.get("providerModified") is not None:
            _require_string(item.get("providerModified"), f"sourceRefs[{index}].providerModified")


def _validate_claims(value: object) -> None:
    claim_ids: set[str] = set()
    for index, claim in enumerate(_require_list(value, "claims")):
        item = _require_dict(claim, f"claims[{index}]")
        claim_id = _require_string(item.get("claimId"), f"claims[{index}].claimId")
        if claim_id in claim_ids:
            raise ValueError(f"Duplicate corpus claimId: {claim_id}")
        claim_ids.add(claim_id)
        _require_string(item.get("predicate"), f"claims[{index}].predicate")
        truth_role = _require_string(item.get("truthRole"), f"claims[{index}].truthRole")
        if truth_role not in _CLAIM_TRUTH_ROLES:
            raise ValueError(f"Unsupported corpus claim truthRole: {truth_role}")
        _require_string(item.get("assertedBy"), f"claims[{index}].assertedBy")
        if "value" not in item:
            raise ValueError(f"Corpus claim {claim_id} must contain value")
        validate_json(item["value"])
        for evidence in _require_list(
            item.get("evidenceRefs", []), f"claims[{index}].evidenceRefs"
        ):
            _require_string(evidence, f"claims[{index}].evidenceRefs[]")


def validate_corpus_record(record: JsonObject) -> None:
    validate_json(record)
    _reject_embedded_bytes(record)
    if record.get("schemaVersion") != 1:
        raise ValueError("Corpus record schemaVersion must be 1")
    record_id = _require_string(record.get("recordId"), "recordId")
    kind = _require_string(record.get("recordKind"), "recordKind")
    if kind not in _CORPUS_KINDS:
        raise ValueError(f"Unsupported corpus recordKind: {kind}")
    expected_prefix = "sample:" if kind == "sample" else "vuln:"
    if not record_id.startswith(expected_prefix):
        raise ValueError(f"Corpus {kind} recordId must start with {expected_prefix}")
    _validate_source_refs(record.get("sourceRefs", []))
    _validate_claims(record.get("claims", []))
    for evidence in _require_list(record.get("evidenceRefs", []), "evidenceRefs"):
        _require_string(evidence, "evidenceRefs[]")

    if kind == "sample":
        sample = _require_dict(record.get("sample"), "sample")
        sha256 = _validate_sha256(sample.get("sha256"), "sample.sha256")
        expected_record_id = "sample:" + sha256.removeprefix("sha256:")
        if record_id != expected_record_id:
            raise ValueError("Corpus Sample recordId must equal its SHA-256 content identity")
        _require_int(sample.get("byteLength"), "sample.byteLength")
        _require_string(sample.get("mediaType"), "sample.mediaType")
        role = _require_string(sample.get("artifactRole"), "sample.artifactRole")
        if role not in _SAMPLE_ROLES:
            raise ValueError(f"Unsupported sample artifactRole: {role}")
        materialization = _require_string(sample.get("materialization"), "sample.materialization")
        if materialization not in _SAMPLE_MATERIALIZATIONS:
            raise ValueError(f"Unsupported sample materialization: {materialization}")
        if sample.get("executionAdmission") != _EXECUTION_ADMISSION:
            raise ValueError("Corpus Sample executionAdmission must remain denied-by-default")
        if materialization == "sample-vault":
            vault_sample_id = _require_string(sample.get("vaultSampleId"), "sample.vaultSampleId")
            if vault_sample_id != expected_record_id:
                raise ValueError("Corpus Sample vaultSampleId does not match SampleIdentity")
        elif sample.get("vaultSampleId") is not None:
            raise ValueError("Only sample-vault materialization may contain vaultSampleId")
    else:
        subject = _require_dict(record.get("subject"), "subject")
        _require_string(subject.get("targetScope"), "subject.targetScope")
        revisions = _require_list(subject.get("revisions", []), "subject.revisions")
        if not revisions and not record.get("sourceRefs"):
            raise ValueError(
                "Vulnerability corpus record needs an exact target revision or external sourceRef"
            )
        for index, revision in enumerate(revisions):
            item = _require_dict(revision, f"subject.revisions[{index}]")
            _require_string(item.get("name"), f"subject.revisions[{index}].name")
            _validate_sha256(item.get("digest"), f"subject.revisions[{index}].digest")


def _record_key(record_id: str) -> str:
    return hashlib.sha256(record_id.encode("utf-8")).hexdigest()


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ResearchCorpus:
    """Revisioned local catalog over private SampleVault bytes and external provider records.

    The corpus stores only canonical manifests and evidence/source references. Sample bytes remain
    in SampleVault or provider-owned systems. A corpus Sample record always keeps execution denied
    by default; a later Range/Evaluation authority must independently admit any execution.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.records_root = root / "records"
        self.heads_root = root / "heads"
        self.receipts_root = root / "receipts"
        for path in (self.root, self.records_root, self.heads_root, self.receipts_root):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        for kind in sorted(_CORPUS_KINDS):
            (self.records_root / kind).mkdir(parents=True, exist_ok=True)
            (self.records_root / kind).chmod(0o700)
            (self.heads_root / kind).mkdir(parents=True, exist_ok=True)
            (self.heads_root / kind).chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "kind": "ordivon.security.research-corpus",
            "revision": "1",
            "storage": "revisioned-canonical-manifests",
            "sampleBytes": "external-private-sample-vault-only",
            "sampleExecutionAdmission": _EXECUTION_ADMISSION,
            "recordDigest": "canonical-sha256",
        }

    def _head_path(self, record_kind: str, record_id: str) -> Path:
        return self.heads_root / record_kind / f"{_record_key(record_id)}.json"

    def _revision_path(self, record_kind: str, record_id: str, digest: str) -> Path:
        record_key = _record_key(record_id)
        digest_hex = digest.removeprefix("sha256:")
        return self.records_root / record_kind / record_key / f"{digest_hex}.json"

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        descriptor, raw_name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
        temporary = Path(raw_name)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _load_head(self, record_kind: str, record_id: str) -> CorpusHead | None:
        path = self._head_path(record_kind, record_id)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise ValueError("Corpus head path is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Corpus head must be an object")
        head = CorpusHead(
            record_id=_require_string(value.get("recordId"), "head.recordId"),
            record_kind=_require_string(value.get("recordKind"), "head.recordKind"),
            record_digest=_validate_sha256(value.get("recordDigest"), "head.recordDigest"),
            revision_path=_require_string(value.get("revisionPath"), "head.revisionPath"),
        )
        if head.record_id != record_id or head.record_kind != record_kind:
            raise ValueError("Corpus head identity mismatch")
        expected_revision = self._revision_path(
            record_kind, record_id, head.record_digest
        ).relative_to(self.root).as_posix()
        if head.revision_path != expected_revision:
            raise ValueError("Corpus head revision path does not match digest-bound identity")
        return head

    def register(self, record: JsonObject) -> CorpusRegistration:
        validate_corpus_record(record)
        record_id = str(record["recordId"])
        record_kind = str(record["recordKind"])
        digest = canonical_digest(record)
        revision = self._revision_path(record_kind, record_id, digest)
        relative_revision = revision.relative_to(self.root).as_posix()
        if revision.exists():
            if revision.is_symlink() or revision.read_bytes() != canonical_bytes(record) + b"\n":
                raise ValueError("Existing corpus revision differs from its digest-bound record")
        else:
            self._atomic_write(revision, canonical_bytes(record) + b"\n")

        previous = self._load_head(record_kind, record_id)
        head = CorpusHead(record_id, record_kind, digest, relative_revision)
        self._atomic_write(
            self._head_path(record_kind, record_id), canonical_bytes(head.to_dict()) + b"\n"
        )

        registered_at_ms = time.time_ns() // 1_000_000
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.research-corpus-registration-receipt",
            "recordId": record_id,
            "recordKind": record_kind,
            "recordDigest": digest,
            "previousDigest": previous.record_digest if previous is not None else None,
            "revisionPath": relative_revision,
            "registeredAtMs": registered_at_ms,
        }
        receipt_name = f"register-{_record_key(record_id)}-{time.time_ns()}.json"
        receipt_path = self.receipts_root / receipt_name
        self._atomic_write(receipt_path, canonical_bytes(receipt) + b"\n")
        return CorpusRegistration(
            record_id=record_id,
            record_kind=record_kind,
            record_digest=digest,
            previous_digest=previous.record_digest if previous is not None else None,
            revision_path=relative_revision,
            receipt_path=receipt_path.relative_to(self.root).as_posix(),
        )

    def load(self, record_id: str, *, record_kind: str | None = None) -> JsonObject:
        kinds: Iterable[str] = (record_kind,) if record_kind is not None else sorted(_CORPUS_KINDS)
        matches: list[CorpusHead] = []
        for kind in kinds:
            if kind not in _CORPUS_KINDS:
                raise ValueError(f"Unsupported corpus recordKind: {kind}")
            head = self._load_head(kind, record_id)
            if head is not None:
                matches.append(head)
        if not matches:
            raise KeyError(record_id)
        if len(matches) != 1:
            raise ValueError(f"Ambiguous corpus recordId across kinds: {record_id}")
        head = matches[0]
        revision = self.root / head.revision_path
        if revision.is_symlink() or not revision.is_file():
            raise ValueError("Corpus revision path is unsafe or missing")
        raw = revision.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Corpus revision must be an object")
        record = dict(value)
        validate_corpus_record(record)
        if canonical_digest(record) != head.record_digest:
            raise ValueError("Corpus revision digest differs from head")
        return record

    def list_heads(self, *, record_kind: str | None = None) -> list[CorpusHead]:
        kinds: Iterable[str] = (record_kind,) if record_kind is not None else sorted(_CORPUS_KINDS)
        heads: list[CorpusHead] = []
        for kind in kinds:
            if kind not in _CORPUS_KINDS:
                raise ValueError(f"Unsupported corpus recordKind: {kind}")
            for path in sorted((self.heads_root / kind).glob("*.json")):
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Corpus head path is unsafe")
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("Corpus head must be an object")
                head = CorpusHead(
                    record_id=_require_string(value.get("recordId"), "head.recordId"),
                    record_kind=_require_string(value.get("recordKind"), "head.recordKind"),
                    record_digest=_validate_sha256(
                        value.get("recordDigest"), "head.recordDigest"
                    ),
                    revision_path=_require_string(
                        value.get("revisionPath"), "head.revisionPath"
                    ),
                )
                if head.record_kind != kind:
                    raise ValueError("Corpus head kind differs from its storage namespace")
                if path.name != f"{_record_key(head.record_id)}.json":
                    raise ValueError("Corpus head filename differs from record identity")
                expected_revision = self._revision_path(
                    kind, head.record_id, head.record_digest
                ).relative_to(self.root).as_posix()
                if head.revision_path != expected_revision:
                    raise ValueError(
                        "Corpus head revision path does not match digest-bound identity"
                    )
                heads.append(head)
        return sorted(heads, key=lambda item: (item.record_kind, item.record_id))

    def verify(self) -> JsonObject:
        heads = self.list_heads()
        for head in heads:
            loaded = self.load(head.record_id, record_kind=head.record_kind)
            if canonical_digest(loaded) != head.record_digest:
                raise ValueError("Corpus verification found a head digest mismatch")

        revision_count = 0
        for kind in sorted(_CORPUS_KINDS):
            for path in sorted((self.records_root / kind).glob("*/*.json")):
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Corpus revision path is unsafe")
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("Corpus revision must be an object")
                record = dict(value)
                validate_corpus_record(record)
                if record.get("recordKind") != kind:
                    raise ValueError("Corpus revision kind differs from its storage namespace")
                digest = canonical_digest(record)
                expected = self._revision_path(kind, str(record["recordId"]), digest)
                if path != expected:
                    raise ValueError("Corpus revision path differs from digest-bound identity")
                revision_count += 1

        return {
            "schemaVersion": 1,
            "kind": "ordivon.security.research-corpus-verification",
            "headCount": len(heads),
            "revisionCount": revision_count,
            "sampleCount": sum(item.record_kind == "sample" for item in heads),
            "vulnerabilityCount": sum(item.record_kind == "vulnerability" for item in heads),
            "sampleExecutionAdmission": _EXECUTION_ADMISSION,
            "verified": True,
        }

    def query(self, needle: str) -> list[JsonObject]:
        if not needle:
            raise ValueError("Corpus query needle must not be empty")
        lowered = needle.lower()
        matches: list[JsonObject] = []
        for head in self.list_heads():
            record = self.load(head.record_id, record_kind=head.record_kind)
            searchable = json.dumps(record, ensure_ascii=False, sort_keys=True).lower()
            if lowered in searchable:
                matches.append(record)
        return matches

    def inspect(
        self, record_id: str, *, record_kind: str | None = None
    ) -> JsonObject:
        record = self.load(record_id, record_kind=record_kind)
        claims_by_role: JsonObject = {
            role: [] for role in sorted(_CLAIM_TRUTH_ROLES)
        }
        claims = record.get("claims", [])
        if isinstance(claims, list):
            for claim in claims:
                if not isinstance(claim, dict):
                    continue
                truth_role = claim.get("truthRole")
                if isinstance(truth_role, str) and truth_role in claims_by_role:
                    bucket = claims_by_role[truth_role]
                    if isinstance(bucket, list):
                        bucket.append(dict(claim))

        projection: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.research-corpus-inspection",
            "recordId": str(record["recordId"]),
            "recordKind": str(record["recordKind"]),
            "claimsByTruthRole": claims_by_role,
            "sourceRefs": list(record.get("sourceRefs", [])),
            "evidenceRefs": list(record.get("evidenceRefs", [])),
            "interpretationRules": [
                "provider-claim is not Security independent world truth",
                "catalog possession is not execution authority",
                "absence of an independent-observation claim is not a negative observation",
            ],
        }
        if record.get("recordKind") == "sample":
            sample = _require_dict(record.get("sample"), "sample")
            projection["sample"] = {
                "sha256": sample["sha256"],
                "byteLength": sample["byteLength"],
                "mediaType": sample["mediaType"],
                "artifactRole": sample["artifactRole"],
                "materialization": sample["materialization"],
                "executionAdmission": sample["executionAdmission"],
            }
        else:
            projection["subject"] = dict(_require_dict(record.get("subject"), "subject"))
        validate_json(projection)
        return projection

    def compare_candidate(self, candidate: JsonObject) -> JsonObject:
        validate_corpus_record(candidate)
        record_id = _require_string(candidate.get("recordId"), "recordId")
        record_kind = _require_string(candidate.get("recordKind"), "recordKind")
        candidate_digest = canonical_digest(candidate)
        try:
            current = self.load(record_id, record_kind=record_kind)
        except (FileNotFoundError, KeyError):
            return {
                "schemaVersion": 1,
                "kind": "ordivon.security.research-corpus-candidate-comparison",
                "recordId": record_id,
                "recordKind": record_kind,
                "status": "not-registered",
                "candidateRecordDigest": candidate_digest,
                "recordChanged": None,
                "sourceChanges": [],
                "mutationPerformed": False,
                "executionAdmissionChanged": False,
            }

        current_digest = canonical_digest(current)
        current_sources = {
            (str(item.get("provider")), str(item.get("recordId"))): item
            for item in current.get("sourceRefs", [])
            if isinstance(item, dict)
        }
        candidate_sources = {
            (str(item.get("provider")), str(item.get("recordId"))): item
            for item in candidate.get("sourceRefs", [])
            if isinstance(item, dict)
        }
        source_changes: list[JsonObject] = []
        for key in sorted(set(current_sources) | set(candidate_sources)):
            before = current_sources.get(key)
            after = candidate_sources.get(key)
            if before == after:
                continue
            source_changes.append(
                {
                    "provider": key[0],
                    "providerRecordId": key[1],
                    "currentSnapshotDigest": before.get("snapshotDigest") if before else None,
                    "candidateSnapshotDigest": after.get("snapshotDigest") if after else None,
                    "currentProviderModified": before.get("providerModified") if before else None,
                    "candidateProviderModified": after.get("providerModified") if after else None,
                    "sourceAdded": before is None,
                    "sourceRemoved": after is None,
                }
            )

        execution_admission_changed = False
        if record_kind == "sample":
            current_sample = _require_dict(current.get("sample"), "sample")
            candidate_sample = _require_dict(candidate.get("sample"), "sample")
            execution_admission_changed = (
                current_sample.get("executionAdmission")
                != candidate_sample.get("executionAdmission")
            )

        result: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.research-corpus-candidate-comparison",
            "recordId": record_id,
            "recordKind": record_kind,
            "status": "changed" if current_digest != candidate_digest else "unchanged",
            "currentRecordDigest": current_digest,
            "candidateRecordDigest": candidate_digest,
            "recordChanged": current_digest != candidate_digest,
            "sourceChanges": source_changes,
            "mutationPerformed": False,
            "executionAdmissionChanged": execution_admission_changed,
            "interpretationRules": [
                "a changed provider snapshot means the stored provider claim may require review; it does not establish changed target applicability",
                "an unchanged provider snapshot does not establish target exploitability or Sample execution authority",
                "comparison is read-only and never advances the corpus head",
            ],
        }
        validate_json(result)
        return result

    def import_local_sample(
        self,
        *,
        vault: SampleVault,
        path: Path,
        media_type: str = "application/octet-stream",
        artifact_role: str = "third-party-artifact",
        source_provider: str = "operator-local",
        source_record_id: str | None = None,
        evidence_refs: list[str] | None = None,
    ) -> tuple[SampleIdentity, CorpusRegistration]:
        if artifact_role not in _SAMPLE_ROLES:
            raise ValueError(f"Unsupported sample artifactRole: {artifact_role}")
        sample = vault.import_path(path, media_type=media_type)
        record: JsonObject = {
            "schemaVersion": 1,
            "recordKind": "sample",
            "recordId": "sample:" + sample.sha256.removeprefix("sha256:"),
            "sample": {
                "sha256": sample.sha256,
                "byteLength": sample.byte_length,
                "mediaType": sample.media_type,
                "originalName": sample.original_name,
                "artifactRole": artifact_role,
                "materialization": "sample-vault",
                "vaultSampleId": sample.sample_id,
                "executionAdmission": _EXECUTION_ADMISSION,
            },
            "sourceRefs": [
                {
                    "provider": source_provider,
                    "recordId": source_record_id or sample.original_name or sample.sample_id,
                }
            ],
            "claims": [],
            "evidenceRefs": evidence_refs or [],
        }
        return sample, self.register(record)


def provider_source_ref(
    *,
    provider: str,
    record_id: str,
    locator: str | None = None,
    snapshot_digest: str | None = None,
    retrieved_at: str | None = None,
) -> JsonObject:
    result: JsonObject = {"provider": provider, "recordId": record_id}
    if locator is not None:
        result["locator"] = locator
    if snapshot_digest is not None:
        result["snapshotDigest"] = _validate_sha256(snapshot_digest, "snapshotDigest")
    if retrieved_at is not None:
        result["retrievedAt"] = retrieved_at
    _validate_source_refs([result])
    return result


__all__ = [
    "CorpusHead",
    "CorpusRegistration",
    "ResearchCorpus",
    "provider_source_ref",
    "validate_corpus_record",
]
