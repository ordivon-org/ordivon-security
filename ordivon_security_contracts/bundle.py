"""Bounded one-way Campaign evidence export and independent verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .bindings import ResidualReport
from .campaign import ContractError, canonical_bytes, digest, load_json
from .ledger import CampaignEvent, CampaignLedger, LedgerCorrupt, replay_campaign

MAX_BUNDLE_FILES = 512
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class BundleError(ContractError):
    """Evidence export, seal, or replay verification failed."""


def _validate_relative_path(value: str, *, allow_reserved: bool) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or value.startswith("/")
    ):
        raise BundleError(["relative path: must stay inside the bundle"])
    if not allow_reserved and (value.startswith("campaign/") or value.startswith("bundle-")):
        raise BundleError(["relative path: collides with reserved bundle paths"])
    return path


@dataclass(frozen=True, slots=True)
class EvidenceAttachment:
    relative_path: str
    content: bytes

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path, allow_reserved=False)
        if len(self.content) > MAX_SINGLE_FILE_BYTES:
            raise BundleError(["attachment.content: exceeds per-file byte limit"])


@dataclass(frozen=True, slots=True)
class BundleReceipt:
    bundle_id: str
    bundle_digest: str
    file_count: int
    total_bytes: int
    path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "bundle_id": self.bundle_id,
            "bundle_digest": self.bundle_digest,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "path": self.path,
        }


def _bytes_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _json_bytes(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def _listed_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BundleError([f"bundle: symbolic link is forbidden: {path.relative_to(root)}"])
        if path.is_file():
            result.append(path)
        elif not path.is_dir():
            raise BundleError([f"bundle: unsupported filesystem entry: {path.relative_to(root)}"])
    return result


def export_evidence_bundle(
    ledger: CampaignLedger,
    destination: str | Path,
    *,
    bundle_id: str,
    residual_report: ResidualReport | None = None,
    attachments: Iterable[EvidenceAttachment] = (),
) -> BundleReceipt:
    """Export one immutable bundle through staging and atomic directory rename.

    The export path is write-only from the Campaign's perspective: bundle bytes
    are never interpreted as commands and no executable content is invoked.
    """

    if not isinstance(bundle_id, str) or not bundle_id.startswith(
        "urn:ordivon:security:evidence-bundle:"
    ):
        raise BundleError(["bundle_id: must be a Security evidence-bundle URN"])
    target = Path(destination)
    if target.exists():
        receipt = verify_evidence_bundle(target)
        if receipt.bundle_id != bundle_id:
            raise BundleError(["destination: already contains another bundle identity"])
        return receipt
    if target.parent.exists() and target.parent.is_symlink():
        raise BundleError(["destination parent: symbolic link is forbidden"])
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=target.parent)
    )
    try:
        manifest = ledger.manifest()
        events = [event.to_dict() for event in ledger.events()]
        projection = replay_campaign(manifest, events).to_dict()
        if residual_report is not None and (
            residual_report.campaign_id != projection["campaign_id"]
            or residual_report.world_id != projection["world_id"]
        ):
            raise BundleError(["residual report: Campaign or World identity differs"])

        reserved: dict[str, bytes] = {
            "campaign/manifest.json": _json_bytes(manifest),
            "campaign/events.json": _json_bytes(events),
            "campaign/projection.json": _json_bytes(projection),
            "campaign/bindings.json": _json_bytes(
                sorted(projection["bindings"].values(), key=lambda item: item["binding_id"])
            ),
        }
        if residual_report is not None:
            reserved["campaign/residual-report.json"] = _json_bytes(
                residual_report.to_dict()
            )
        attachment_map: dict[str, bytes] = {}
        for attachment in attachments:
            if attachment.relative_path in reserved or attachment.relative_path in attachment_map:
                raise BundleError([f"attachment: duplicate path {attachment.relative_path!r}"])
            attachment_map[attachment.relative_path] = attachment.content
        all_content = {**reserved, **attachment_map}
        if len(all_content) + 2 > MAX_BUNDLE_FILES:
            raise BundleError([f"bundle: exceeds file limit {MAX_BUNDLE_FILES}"])
        total_payload = sum(len(content) for content in all_content.values())
        if total_payload > MAX_BUNDLE_BYTES:
            raise BundleError([f"bundle: exceeds byte limit {MAX_BUNDLE_BYTES}"])
        for relative_path, content in all_content.items():
            _write_atomic(staging / relative_path, content)

        entries = [
            {
                "path": relative_path,
                "bytes": len(content),
                "digest": _bytes_digest(content),
            }
            for relative_path, content in sorted(all_content.items())
        ]
        bundle_manifest = {
            "schema_version": 1,
            "bundle_id": bundle_id,
            "campaign_id": projection["campaign_id"],
            "world_id": projection["world_id"],
            "campaign_manifest_digest": projection["manifest_digest"],
            "campaign_event_head": projection["head_hash"],
            "campaign_revision": projection["revision"],
            "files": entries,
        }
        manifest_bytes = _json_bytes(bundle_manifest)
        _write_atomic(staging / "bundle-manifest.json", manifest_bytes)
        bundle_digest = digest(bundle_manifest)
        seal = {
            "schema_version": 1,
            "bundle_id": bundle_id,
            "bundle_digest": bundle_digest,
            "manifest_file_digest": _bytes_digest(manifest_bytes),
        }
        _write_atomic(staging / "bundle-seal.json", _json_bytes(seal))
        directory_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.replace(staging, target)
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return verify_evidence_bundle(target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def verify_evidence_bundle(path: str | Path) -> BundleReceipt:
    root = Path(path)
    if not root.is_dir() or root.is_symlink():
        raise BundleError(["bundle: must be a regular directory"])
    manifest_path = root / "bundle-manifest.json"
    seal_path = root / "bundle-seal.json"
    if not manifest_path.is_file() or not seal_path.is_file():
        raise BundleError(["bundle: manifest or seal is missing"])
    bundle_manifest = load_json(manifest_path)
    seal = load_json(seal_path)
    expected_manifest_keys = {
        "schema_version",
        "bundle_id",
        "campaign_id",
        "world_id",
        "campaign_manifest_digest",
        "campaign_event_head",
        "campaign_revision",
        "files",
    }
    if set(bundle_manifest) != expected_manifest_keys or bundle_manifest["schema_version"] != 1:
        raise BundleError(["bundle-manifest: invalid v1 shape"])
    if set(seal) != {
        "schema_version",
        "bundle_id",
        "bundle_digest",
        "manifest_file_digest",
    } or seal["schema_version"] != 1:
        raise BundleError(["bundle-seal: invalid v1 shape"])
    if seal["bundle_id"] != bundle_manifest["bundle_id"]:
        raise BundleError(["bundle-seal: bundle identity differs"])
    if seal["bundle_digest"] != digest(bundle_manifest):
        raise BundleError(["bundle-seal: bundle digest differs"])
    if seal["manifest_file_digest"] != _bytes_digest(manifest_path.read_bytes()):
        raise BundleError(["bundle-seal: manifest file digest differs"])
    if SHA256_RE.fullmatch(seal["bundle_digest"]) is None:
        raise BundleError(["bundle-seal: invalid digest"])

    listed: set[str] = set()
    total_bytes = 0
    for index, entry in enumerate(bundle_manifest["files"]):
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "digest"}:
            raise BundleError([f"bundle-manifest.files[{index}]: invalid entry"])
        _validate_relative_path(entry["path"], allow_reserved=True)
        if entry["path"] in listed:
            raise BundleError([f"bundle-manifest.files[{index}]: duplicate path"])
        listed.add(entry["path"])
        file_path = root / PurePosixPath(entry["path"])
        if not file_path.is_file() or file_path.is_symlink():
            raise BundleError([f"bundle file missing or unsafe: {entry['path']}"])
        content = file_path.read_bytes()
        if len(content) != entry["bytes"] or _bytes_digest(content) != entry["digest"]:
            raise BundleError([f"bundle file digest differs: {entry['path']}"])
        total_bytes += len(content)
    actual = {
        path.relative_to(root).as_posix()
        for path in _listed_files(root)
        if path.name not in {"bundle-manifest.json", "bundle-seal.json"}
    }
    if actual != listed:
        raise BundleError(["bundle: listed and physical file sets differ"])
    if len(listed) + 2 > MAX_BUNDLE_FILES or total_bytes > MAX_BUNDLE_BYTES:
        raise BundleError(["bundle: limits exceeded"])

    manifest = load_json(root / "campaign/manifest.json")
    try:
        raw_events = json.loads((root / "campaign/events.json").read_text(encoding="utf-8"))
        stored_projection = json.loads(
            (root / "campaign/projection.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError([f"campaign replay material: invalid JSON: {exc}"]) from exc
    if not isinstance(raw_events, list) or not isinstance(stored_projection, dict):
        raise BundleError(["campaign replay material: invalid shape"])
    try:
        projection = replay_campaign(
            manifest, [CampaignEvent.from_dict(item) for item in raw_events]
        ).to_dict()
    except LedgerCorrupt as exc:
        raise BundleError([f"campaign replay failed: {error}" for error in exc.errors]) from exc
    if projection != stored_projection:
        raise BundleError(["campaign projection: does not match deterministic replay"])
    if bundle_manifest["campaign_id"] != projection["campaign_id"]:
        raise BundleError(["bundle-manifest: Campaign identity differs"])
    if bundle_manifest["world_id"] != projection["world_id"]:
        raise BundleError(["bundle-manifest: World identity differs"])
    if bundle_manifest["campaign_manifest_digest"] != projection["manifest_digest"]:
        raise BundleError(["bundle-manifest: Campaign manifest digest differs"])
    if bundle_manifest["campaign_event_head"] != projection["head_hash"]:
        raise BundleError(["bundle-manifest: Campaign event head differs"])
    if bundle_manifest["campaign_revision"] != projection["revision"]:
        raise BundleError(["bundle-manifest: Campaign revision differs"])
    return BundleReceipt(
        bundle_id=bundle_manifest["bundle_id"],
        bundle_digest=seal["bundle_digest"],
        file_count=len(listed) + 2,
        total_bytes=total_bytes + manifest_path.stat().st_size + seal_path.stat().st_size,
        path=str(root),
    )
