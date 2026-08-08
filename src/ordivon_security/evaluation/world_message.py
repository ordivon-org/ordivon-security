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

_REQUEST_KIND = "ordivon.world.message-delivery-destination-request"
_RESPONSE_KIND = "ordivon.world.message-delivery-destination-response"
_PLAN_KIND = "ordivon.world.prepared-message-delivery"
_ISSUANCE_KIND = "ordivon.world.message-issuance-receipt"
_RECEIPT_KIND = "ordivon.world.message-delivery-receipt"
_ADMISSION_KIND = "ordivon.security.world-message-admission-record"


class WorldMessageRequestError(ValueError):
    code = "invalid-request"


class WorldMessageIdentityConflict(WorldMessageRequestError):
    code = "identity-conflict"


class WorldMessagePolicyRejected(WorldMessageRequestError):
    code = "policy-rejected"


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise WorldMessageRequestError(f"{label} must be a JSON object")
    return cast(JsonObject, value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorldMessageRequestError(f"{label} must be a non-empty string")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label)
    if not text.startswith("sha256:") or len(text) != 71:
        raise WorldMessageRequestError(f"{label} must be a sha256: digest")
    return text


class WorldMessageInbox:
    """Security-owned durable ingress for one exact informational Message.

    The inbox intentionally does not import ordivon-world. It validates the
    versioned JSON boundary, binds a source-issued statement structurally, and
    commits one message-specific admission record. Admission classifies the
    foreign claim as management information; it never promotes destination
    knowledge or world-truth.
    """

    def __init__(
        self,
        root: Path,
        *,
        destination_world_id: str,
        allowed_source_world_ids: tuple[str, ...] = (),
        allowed_message_kinds: tuple[str, ...] = (),
    ) -> None:
        if not destination_world_id:
            raise ValueError("Destination World identity must be non-empty")
        self.root = root
        self.destination_world_id = destination_world_id
        self.allowed_source_world_ids = frozenset(allowed_source_world_ids)
        self.allowed_message_kinds = frozenset(allowed_message_kinds)
        self.messages_root = root / "world-message-deliveries"
        self.locks_root = root / "world-message-locks"
        for path in (self.messages_root, self.locks_root):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "kind": "ordivon.security.world-message-inbox",
            "revision": "1",
            "destinationWorldId": self.destination_world_id,
            "admission": "per-message-exclusive-lock+message-specific-atomic-record",
            "sourceAuthorityAuthentication": "caller-trust-boundary",
            "classification": "management",
            "knowledgePromotion": "never-by-ingress",
            "worldTruthPromotion": "never-by-ingress",
            "allowedSourceWorldIds": sorted(self.allowed_source_world_ids),
            "allowedMessageKinds": sorted(self.allowed_message_kinds),
        }

    def handle(self, request: JsonObject) -> JsonObject:
        operation, plan, plan_digest = self._validate_request(request)
        if operation == "deliver":
            return self._deliver(request, plan, plan_digest)
        return self._reconcile(plan, plan_digest)

    def _validate_request(self, request: JsonObject) -> tuple[str, JsonObject, str]:
        if request.get("schemaVersion") != 1 or request.get("kind") != _REQUEST_KIND:
            raise WorldMessageRequestError("Message destination request schema is unsupported")
        operation = _text(request.get("operation"), "Message destination operation")
        if operation not in {"deliver", "reconcile"}:
            raise WorldMessageRequestError("Message destination operation is unsupported")
        plan = _object(request.get("plan"), "Message delivery plan")
        if plan.get("schemaVersion") != 1 or plan.get("kind") != _PLAN_KIND:
            raise WorldMessageRequestError("Prepared Message Delivery schema is unsupported")
        plan_digest = _digest(request.get("planDigest"), "Message delivery plan digest")
        if canonical_digest(plan) != plan_digest:
            raise WorldMessageRequestError(
                "Message delivery plan digest does not match plan content"
            )

        _text(plan.get("messageId"), "Message identity")
        source_world_id = _text(plan.get("sourceWorldId"), "Source World identity")
        destination_world_id = _text(plan.get("destinationWorldId"), "Destination World identity")
        message_kind = _text(plan.get("messageKind"), "Message kind")
        _digest(plan.get("provenanceDigest"), "Message provenance digest")
        _digest(plan.get("payloadDigest"), "Message payload digest")
        self._source_issuance(plan.get("sourceIssuance"), plan)
        if destination_world_id != self.destination_world_id:
            raise WorldMessagePolicyRejected("Message targets another destination World")
        if self.allowed_source_world_ids and source_world_id not in self.allowed_source_world_ids:
            raise WorldMessagePolicyRejected("Source World is not admitted by this destination")
        if self.allowed_message_kinds and message_kind not in self.allowed_message_kinds:
            raise WorldMessagePolicyRejected("Message kind is not admitted by this destination")
        return operation, plan, plan_digest

    def _source_issuance(self, value: object, plan: JsonObject) -> JsonObject:
        issuance = _object(value, "Message Issuance receipt")
        if issuance.get("schemaVersion") != 1 or issuance.get("kind") != _ISSUANCE_KIND:
            raise WorldMessageRequestError("Message Issuance receipt schema is unsupported")
        expected = {
            "messageId": plan.get("messageId"),
            "sourceWorldId": plan.get("sourceWorldId"),
            "destinationWorldId": plan.get("destinationWorldId"),
            "messageKind": plan.get("messageKind"),
            "provenanceDigest": plan.get("provenanceDigest"),
            "payloadDigest": plan.get("payloadDigest"),
        }
        for field, expected_value in expected.items():
            if issuance.get(field) != expected_value:
                raise WorldMessageRequestError(
                    f"Message Issuance receipt {field} differs from Message Delivery plan"
                )
        _text(issuance.get("sourceOccurrenceId"), "Source Message occurrence identity")
        _digest(issuance.get("sourceOccurrenceDigest"), "Source Message occurrence digest")
        authority = _object(issuance.get("authority"), "Message Issuance authority")
        _text(authority.get("authorityId"), "Message Issuance authority identity")
        _text(authority.get("mechanism"), "Message Issuance authority mechanism")
        _object(authority.get("evidence"), "Message Issuance authority evidence")
        return issuance

    def _deliver(self, request: JsonObject, plan: JsonObject, plan_digest: str) -> JsonObject:
        provenance = cast(JsonValue, request.get("provenance"))
        payload = cast(JsonValue, request.get("payload"))
        if canonical_digest(provenance) != _digest(
            plan.get("provenanceDigest"), "Message provenance digest"
        ):
            raise WorldMessageRequestError(
                "Message provenance digest does not match request content"
            )
        if canonical_digest(payload) != _digest(
            plan.get("payloadDigest"), "Message payload digest"
        ):
            raise WorldMessageRequestError("Message payload digest does not match request content")

        message_id = _text(plan.get("messageId"), "Message identity")
        with self._message_lock(message_id):
            retained = self._load_admission(message_id)
            if retained is not None:
                receipt = self._receipt_for_exact_plan(retained, plan, plan_digest)
                return self._delivered_response(receipt)

            issuance = self._source_issuance(plan.get("sourceIssuance"), plan)
            receipt = self._build_receipt(plan, plan_digest)
            body: JsonObject = {
                "messageId": message_id,
                "planDigest": plan_digest,
                "sourceWorldId": _text(plan.get("sourceWorldId"), "Source World identity"),
                "destinationWorldId": _text(
                    plan.get("destinationWorldId"), "Destination World identity"
                ),
                "messageKind": _text(plan.get("messageKind"), "Message kind"),
                "sourceIssuanceDigest": canonical_digest(issuance),
                "sourceIssuance": cast(JsonValue, issuance),
                "provenanceDigest": _digest(
                    plan.get("provenanceDigest"), "Message provenance digest"
                ),
                "provenance": provenance,
                "payloadDigest": _digest(plan.get("payloadDigest"), "Message payload digest"),
                "payload": payload,
                "classification": "management",
                "knowledgePromoted": False,
                "worldTruthPromoted": False,
                "receipt": cast(JsonValue, receipt),
            }
            record: JsonObject = {
                "schemaVersion": 1,
                "kind": _ADMISSION_KIND,
                "body": cast(JsonValue, body),
                "bodyDigest": canonical_digest(body),
            }
            retained_record = self._commit_admission(message_id, record)
            retained_receipt = self._receipt_for_exact_plan(retained_record, plan, plan_digest)
            return self._delivered_response(retained_receipt)

    def _reconcile(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        message_id = _text(plan.get("messageId"), "Message identity")
        with self._message_lock(message_id):
            retained = self._load_admission(message_id)
            if retained is None:
                return {
                    "schemaVersion": 1,
                    "kind": _RESPONSE_KIND,
                    "status": "not_committed",
                    "messageId": message_id,
                    "planDigest": plan_digest,
                    "destinationWorldId": self.destination_world_id,
                    "payloadDigest": _digest(plan.get("payloadDigest"), "Message payload digest"),
                    "evidence": {
                        "authority": "ordivon-security:world-message-inbox",
                        "semanticCommitPoint": "message-specific-atomic-admission-record",
                        "admissionRecordPresent": False,
                        "exclusiveMessageLockHeldAtObservation": True,
                        "exactOriginalRetrySafe": True,
                    },
                }
            receipt = self._receipt_for_exact_plan(retained, plan, plan_digest)
            return self._delivered_response(receipt)

    def _build_receipt(self, plan: JsonObject, plan_digest: str) -> JsonObject:
        message_id = _text(plan.get("messageId"), "Message identity")
        admission_identity = {
            "messageId": message_id,
            "planDigest": plan_digest,
            "destinationWorldId": self.destination_world_id,
        }
        return {
            "schemaVersion": 1,
            "kind": _RECEIPT_KIND,
            "messageId": message_id,
            "planDigest": plan_digest,
            "destinationWorldId": self.destination_world_id,
            "payloadDigest": _digest(plan.get("payloadDigest"), "Message payload digest"),
            "deliveryId": (
                "message-admission:" + canonical_digest(admission_identity).removeprefix("sha256:")
            ),
            "deliveryDigest": canonical_digest(admission_identity),
            "destinationEvidence": {
                "authority": "ordivon-security:world-message-inbox",
                "messageSpecificAdmission": True,
                "sourceIssuanceStructurallyBound": True,
                "sourceAuthorityAuthentication": "caller-trust-boundary",
                "classification": "management",
                "knowledgePromoted": False,
                "worldTruthPromoted": False,
                "inboxExecutionIdentityDigest": canonical_digest(self.execution_identity),
            },
        }

    @staticmethod
    def _delivered_response(receipt: JsonObject) -> JsonObject:
        return {
            "schemaVersion": 1,
            "kind": _RESPONSE_KIND,
            "status": "delivered",
            "receipt": cast(JsonValue, receipt),
        }

    def _lock_path(self, message_id: str) -> Path:
        token = hashlib.sha256(message_id.encode("utf-8")).hexdigest()
        return self.locks_root / f"{token}.lock"

    @contextlib.contextmanager
    def _message_lock(self, message_id: str):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._lock_path(message_id), flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("World Message lock is not a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _record_path(self, message_id: str) -> Path:
        token = hashlib.sha256(message_id.encode("utf-8")).hexdigest()
        return self.messages_root / f"{token}.json"

    def _load_admission(self, message_id: str) -> JsonObject | None:
        path = self._record_path(message_id)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("World Message admission path is not a regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
        record = _object(value, "World Message admission record")
        if record.get("schemaVersion") != 1 or record.get("kind") != _ADMISSION_KIND:
            raise RuntimeError("World Message admission record schema is unsupported")
        body = _object(record.get("body"), "World Message admission body")
        if canonical_digest(body) != record.get("bodyDigest"):
            raise RuntimeError("World Message admission record digest mismatch")
        if body.get("messageId") != message_id:
            raise RuntimeError("World Message admission record identity mismatch")
        return record

    def _commit_admission(self, message_id: str, record: JsonObject) -> JsonObject:
        final_path = self._record_path(message_id)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".admission-", dir=self.messages_root)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(canonical_bytes(record) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary_path, final_path)
            except FileExistsError as error:
                retained = self._load_admission(message_id)
                if retained is None:
                    raise RuntimeError(
                        "Concurrent Message admission appeared without a readable record"
                    ) from error
                return retained
            directory_fd = os.open(self.messages_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            retained = self._load_admission(message_id)
            if retained is None:
                raise RuntimeError("Committed World Message admission record cannot be reloaded")
            return retained
        finally:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            temporary_path.unlink(missing_ok=True)

    def _receipt_for_exact_plan(
        self,
        record: JsonObject,
        plan: JsonObject,
        plan_digest: str,
    ) -> JsonObject:
        body = _object(record.get("body"), "World Message admission body")
        issuance = self._source_issuance(plan.get("sourceIssuance"), plan)
        expected = {
            "messageId": plan.get("messageId"),
            "planDigest": plan_digest,
            "sourceWorldId": plan.get("sourceWorldId"),
            "destinationWorldId": plan.get("destinationWorldId"),
            "messageKind": plan.get("messageKind"),
            "sourceIssuanceDigest": canonical_digest(issuance),
            "provenanceDigest": plan.get("provenanceDigest"),
            "payloadDigest": plan.get("payloadDigest"),
        }
        for field, value in expected.items():
            if body.get(field) != value:
                raise WorldMessageIdentityConflict(
                    f"Message identity already belongs to different {field}"
                )
        if body.get("classification") != "management":
            raise RuntimeError("World Message admission classification changed")
        if (
            body.get("knowledgePromoted") is not False
            or body.get("worldTruthPromoted") is not False
        ):
            raise RuntimeError("World Message admission illegally promoted foreign claim")
        receipt = _object(body.get("receipt"), "World Message admission receipt")
        if receipt.get("kind") != _RECEIPT_KIND:
            raise RuntimeError("World Message admission record contains an invalid receipt")
        return receipt


def rejected_world_message_response(error: WorldMessageRequestError) -> JsonObject:
    return {
        "schemaVersion": 1,
        "kind": _RESPONSE_KIND,
        "status": "rejected",
        "code": error.code,
        "reason": str(error),
    }
