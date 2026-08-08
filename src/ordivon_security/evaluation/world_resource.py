from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_bytes, canonical_digest

from .models import SampleIdentity
from .vault import SampleVault

_REQUEST_KIND = "ordivon.world.resource-transfer-destination-request"
_RESPONSE_KIND = "ordivon.world.resource-transfer-destination-response"
_PLAN_KIND = "ordivon.world.prepared-resource-transfer"
_RECEIPT_KIND = "ordivon.world.resource-transfer-receipt"
_ADMISSION_KIND = "ordivon.security.world-resource-admission-record"
_MEDIA_TYPE = "application/vnd.ordivon.world.resource+json"


class WorldResourceRequestError(ValueError):
    code = "invalid-request"


class WorldResourceIdentityConflict(WorldResourceRequestError):
    code = "identity-conflict"


class WorldResourcePolicyRejected(WorldResourceRequestError):
    code = "policy-rejected"


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise WorldResourceRequestError(f"{label} must be a JSON object")
    return cast(JsonObject, value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorldResourceRequestError(f"{label} must be a non-empty string")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label)
    if not text.startswith("sha256:") or len(text) != 71:
        raise WorldResourceRequestError(f"{label} must be a sha256: digest")
    return text


def _sample_from_dict(value: object) -> SampleIdentity:
    sample = _object(value, "Admission Sample")
    return SampleIdentity(
        sample_id=_text(sample.get("sampleId"), "Sample identity"),
        sha256=_digest(sample.get("sha256"), "Sample digest"),
        byte_length=int(sample.get("byteLength", -1)),
        media_type=_text(sample.get("mediaType"), "Sample media type"),
        original_name=(
            None
            if sample.get("originalName") is None
            else _text(sample.get("originalName"), "Sample original name")
        ),
    )


class WorldResourceInbox:
    """Security-owned destination admission for World Resource Transfer.

    The inbox deliberately does not import ordivon-world. It implements the
    versioned JSON destination contract while Security remains authoritative for
    its SampleVault bytes and transfer-specific admission record.

    SampleVault content existence alone is never treated as proof that a
    transfer identity was admitted. Reconciliation requires the durable
    transfer-specific admission record.
    """

    def __init__(
        self,
        root: Path,
        *,
        destination_world_id: str,
        allowed_source_world_ids: tuple[str, ...] = (),
        allowed_resource_kinds: tuple[str, ...] = (),
    ) -> None:
        if not destination_world_id:
            raise ValueError("Destination World identity must be non-empty")
        self.root = root
        self.destination_world_id = destination_world_id
        self.allowed_source_world_ids = frozenset(allowed_source_world_ids)
        self.allowed_resource_kinds = frozenset(allowed_resource_kinds)
        self.vault = SampleVault(root / "vault")
        self.transfers_root = root / "world-resource-transfers"
        self.locks_root = root / "world-resource-locks"
        for path in (self.transfers_root, self.locks_root):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "kind": "ordivon.security.world-resource-inbox",
            "revision": "3",
            "destinationWorldId": self.destination_world_id,
            "admission": "per-transfer-exclusive-lock+transfer-specific-atomic-record",
            "sourceAuthorityAuthentication": "caller-trust-boundary",
            "payloadStorage": cast(JsonValue, self.vault.execution_identity),
            "allowedSourceWorldIds": sorted(self.allowed_source_world_ids),
            "allowedResourceKinds": sorted(self.allowed_resource_kinds),
        }

    def handle(self, request: JsonObject) -> JsonObject:
        operation, plan, plan_digest = self._validate_request(request)
        if operation == "materialize":
            return self._materialize(request, plan, plan_digest)
        return self._reconcile(plan, plan_digest)

    def _validate_request(self, request: JsonObject) -> tuple[str, JsonObject, str]:
        if request.get("schemaVersion") != 1 or request.get("kind") != _REQUEST_KIND:
            raise WorldResourceRequestError("Resource destination request schema is unsupported")
        operation = _text(request.get("operation"), "Resource destination operation")
        if operation not in {"materialize", "reconcile"}:
            raise WorldResourceRequestError("Resource destination operation is unsupported")
        plan = _object(request.get("plan"), "Resource transfer plan")
        if plan.get("schemaVersion") != 1 or plan.get("kind") != _PLAN_KIND:
            raise WorldResourceRequestError("Prepared Resource Transfer schema is unsupported")
        plan_digest = _digest(request.get("planDigest"), "Resource transfer plan digest")
        if canonical_digest(plan) != plan_digest:
            raise WorldResourceRequestError(
                "Resource transfer plan digest does not match plan content"
            )

        _text(plan.get("transferId"), "Resource transfer identity")
        source_world_id = _text(plan.get("sourceWorldId"), "Source World identity")
        destination_world_id = _text(plan.get("destinationWorldId"), "Destination World identity")
        resource_kind = _text(plan.get("resourceKind"), "Resource kind")
        _digest(plan.get("sourceEgressDigest"), "Source Egress digest")
        _digest(plan.get("payloadDigest"), "Resource payload digest")
        if destination_world_id != self.destination_world_id:
            raise WorldResourcePolicyRejected("Resource transfer targets another destination World")
        if self.allowed_source_world_ids and source_world_id not in self.allowed_source_world_ids:
            raise WorldResourcePolicyRejected("Source World is not admitted by this destination")
        if self.allowed_resource_kinds and resource_kind not in self.allowed_resource_kinds:
            raise WorldResourcePolicyRejected("Resource kind is not admitted by this destination")
        return operation, plan, plan_digest

    def _source_egress(self, value: object, plan: JsonObject) -> JsonObject:
        egress = _object(value, "Resource Egress receipt")
        if (
            egress.get("schemaVersion") != 1
            or egress.get("kind") != "ordivon.world.resource-egress-receipt"
        ):
            raise WorldResourceRequestError("Resource Egress receipt schema is unsupported")
        source_egress_digest = _digest(plan.get("sourceEgressDigest"), "Source Egress digest")
        if canonical_digest(egress) != source_egress_digest:
            raise WorldResourceRequestError(
                "Resource Egress receipt digest does not match Resource Transfer plan"
            )
        expected = {
            "transferId": plan.get("transferId"),
            "sourceWorldId": plan.get("sourceWorldId"),
            "destinationWorldId": plan.get("destinationWorldId"),
            "resourceKind": plan.get("resourceKind"),
            "payloadDigest": plan.get("payloadDigest"),
        }
        for field, expected_value in expected.items():
            if egress.get(field) != expected_value:
                raise WorldResourceRequestError(
                    f"Resource Egress receipt {field} differs from Resource Transfer plan"
                )
        _text(egress.get("sourceOccurrenceId"), "Source Resource occurrence identity")
        _digest(
            egress.get("sourceOccurrenceDigest"),
            "Source Resource occurrence digest",
        )
        authority = _object(egress.get("authority"), "Resource Egress authority")
        _text(authority.get("authorityId"), "Resource Egress authority identity")
        _text(authority.get("mechanism"), "Resource Egress authority mechanism")
        _object(authority.get("evidence"), "Resource Egress authority evidence")
        return egress

    def _materialize(
        self,
        request: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject:
        source_egress = self._source_egress(request.get("sourceEgress"), plan)
        payload = cast(JsonValue, request.get("payload"))
        source_egress_digest = _digest(plan.get("sourceEgressDigest"), "Source Egress digest")
        payload_digest = _digest(plan.get("payloadDigest"), "Resource payload digest")
        if canonical_digest(payload) != payload_digest:
            raise WorldResourceRequestError(
                "Resource payload digest does not match request content"
            )

        transfer_id = _text(plan.get("transferId"), "Resource transfer identity")
        with self._transfer_lock(transfer_id):
            retained = self._load_admission(transfer_id)
            if retained is not None:
                receipt = self._receipt_for_exact_plan(retained, plan, plan_digest)
                return self._materialized_response(receipt)

            payload_bytes = canonical_bytes(payload)
            sample = self.vault.import_bytes(
                payload_bytes,
                media_type=_MEDIA_TYPE,
                original_name="world-resource.json",
            )
            if sample.sha256 != payload_digest:
                raise RuntimeError(
                    "Security SampleVault content identity differs from World payload digest"
                )

            receipt = self._build_receipt(plan, plan_digest, sample)
            body: JsonObject = {
                "transferId": transfer_id,
                "planDigest": plan_digest,
                "sourceWorldId": _text(plan.get("sourceWorldId"), "Source World identity"),
                "destinationWorldId": _text(
                    plan.get("destinationWorldId"), "Destination World identity"
                ),
                "resourceKind": _text(plan.get("resourceKind"), "Resource kind"),
                "sourceEgressDigest": source_egress_digest,
                "sourceEgress": cast(JsonValue, source_egress),
                "payloadDigest": payload_digest,
                "sample": cast(JsonValue, sample.to_dict()),
                "receipt": cast(JsonValue, receipt),
            }
            record: JsonObject = {
                "schemaVersion": 1,
                "kind": _ADMISSION_KIND,
                "body": cast(JsonValue, body),
                "bodyDigest": canonical_digest(body),
            }
            retained_record = self._commit_admission(transfer_id, record)
            retained_receipt = self._receipt_for_exact_plan(retained_record, plan, plan_digest)
            return self._materialized_response(retained_receipt)

    def _reconcile(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        transfer_id = _text(plan.get("transferId"), "Resource transfer identity")
        with self._transfer_lock(transfer_id):
            retained = self._load_admission(transfer_id)
            if retained is None:
                return {
                    "schemaVersion": 1,
                    "kind": _RESPONSE_KIND,
                    "status": "not_committed",
                    "transferId": transfer_id,
                    "planDigest": plan_digest,
                    "destinationWorldId": self.destination_world_id,
                    "payloadDigest": _digest(plan.get("payloadDigest"), "Resource payload digest"),
                    "evidence": {
                        "authority": "ordivon-security:sample-vault-resource-inbox",
                        "semanticCommitPoint": "transfer-specific-atomic-admission-record",
                        "admissionRecordPresent": False,
                        "exclusiveTransferLockHeldAtObservation": True,
                        "exactOriginalRetrySafe": True,
                        "payloadStagingMayExist": True,
                    },
                }
            receipt = self._receipt_for_exact_plan(retained, plan, plan_digest)
            return self._materialized_response(receipt)

    def _build_receipt(
        self,
        plan: JsonObject,
        plan_digest: str,
        sample: SampleIdentity,
    ) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RECEIPT_KIND,
            "transferId": _text(plan.get("transferId"), "Resource transfer identity"),
            "planDigest": plan_digest,
            "destinationWorldId": self.destination_world_id,
            "payloadDigest": sample.sha256,
            "materializationId": sample.sample_id,
            "materializationDigest": canonical_digest(sample.to_dict()),
            "destinationEvidence": {
                "authority": "ordivon-security:sample-vault-resource-inbox",
                "sample": sample.to_dict(),
                "transferSpecificAdmission": True,
                "sourceEgressStructurallyBound": True,
                "sourceAuthorityAuthentication": "caller-trust-boundary",
                "currentPresenceImplied": False,
                "inboxExecutionIdentityDigest": canonical_digest(self.execution_identity),
            },
        }

    @staticmethod
    def _materialized_response(receipt: JsonObject) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RESPONSE_KIND,
            "status": "materialized",
            "receipt": cast(JsonValue, receipt),
        }

    def _lock_path(self, transfer_id: str) -> Path:
        token = hashlib.sha256(transfer_id.encode("utf-8")).hexdigest()
        return self.locks_root / f"{token}.lock"

    @contextlib.contextmanager
    def _transfer_lock(self, transfer_id: str):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._lock_path(transfer_id), flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("World Resource transfer lock is not a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _record_path(self, transfer_id: str) -> Path:
        token = hashlib.sha256(transfer_id.encode("utf-8")).hexdigest()
        return self.transfers_root / f"{token}.json"

    def _load_admission(self, transfer_id: str) -> JsonObject | None:
        path = self._record_path(transfer_id)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("World Resource admission path is not a regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
        record = _object(value, "World Resource admission record")
        if record.get("schemaVersion") != 1 or record.get("kind") != _ADMISSION_KIND:
            raise RuntimeError("World Resource admission record schema is unsupported")
        body = _object(record.get("body"), "World Resource admission body")
        if canonical_digest(body) != record.get("bodyDigest"):
            raise RuntimeError("World Resource admission record digest mismatch")
        if body.get("transferId") != transfer_id:
            raise RuntimeError("World Resource admission record identity mismatch")
        return record

    def _commit_admission(self, transfer_id: str, record: JsonObject) -> JsonObject:
        final_path = self._record_path(transfer_id)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".admission-", dir=self.transfers_root)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(canonical_bytes(record) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary_path, final_path)
            except FileExistsError as error:
                retained = self._load_admission(transfer_id)
                if retained is None:
                    raise RuntimeError(
                        "Concurrent admission appeared without a readable record"
                    ) from error
                return retained
            directory_fd = os.open(self.transfers_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            retained = self._load_admission(transfer_id)
            if retained is None:
                raise RuntimeError("Committed World Resource admission record cannot be reloaded")
            return retained
        finally:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            temporary_path.unlink(missing_ok=True)

    def _receipt_for_exact_plan(
        self,
        record: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject:
        body = _object(record.get("body"), "World Resource admission body")
        expected = {
            "transferId": plan.get("transferId"),
            "planDigest": plan_digest,
            "sourceWorldId": plan.get("sourceWorldId"),
            "destinationWorldId": plan.get("destinationWorldId"),
            "resourceKind": plan.get("resourceKind"),
            "sourceEgressDigest": plan.get("sourceEgressDigest"),
            "payloadDigest": plan.get("payloadDigest"),
        }
        for field, value in expected.items():
            if body.get(field) != value:
                raise WorldResourceIdentityConflict(
                    f"Resource transfer identity already belongs to different {field}"
                )
        receipt = _object(body.get("receipt"), "World Resource admission receipt")
        if receipt.get("kind") != _RECEIPT_KIND:
            raise RuntimeError("World Resource admission record contains an invalid receipt")
        sample = _sample_from_dict(body.get("sample"))
        if receipt.get("materializationId") != sample.sample_id:
            raise RuntimeError("World Resource receipt materialization identity mismatch")
        if receipt.get("payloadDigest") != sample.sha256:
            raise RuntimeError("World Resource receipt payload identity mismatch")
        return receipt


def rejected_world_resource_response(error: WorldResourceRequestError) -> JsonObject:
    return {
        "schemaVersion": 1,
        "kind": _RESPONSE_KIND,
        "status": "rejected",
        "code": error.code,
        "reason": str(error),
    }
