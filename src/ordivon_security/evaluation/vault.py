from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_bytes

from .models import SampleIdentity


class SampleVault:
    """Content-addressed local storage for non-executable Sample bytes.

    The Vault verifies bytes on every resolve. It does not execute, inspect, upload,
    or expose Sample content through evidence records.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.objects_root = root / "objects" / "sha256"
        self.receipts_root = root / "receipts"
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self.receipts_root.mkdir(parents=True, exist_ok=True)
        for path in (self.root, self.objects_root, self.receipts_root):
            path.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "kind": "ordivon.security.sample-vault",
            "revision": "1",
            "verification": "sha256-on-import-and-resolve",
            "storage": "content-addressed-local-filesystem",
        }

    @staticmethod
    def _digest_bytes(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def _digest_path(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        byte_length = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                byte_length += len(chunk)
        return "sha256:" + digest.hexdigest(), byte_length

    def _object_dir(self, sample: SampleIdentity) -> Path:
        digest = sample.sha256.removeprefix("sha256:")
        return self.objects_root / digest[:2] / digest

    def import_bytes(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        original_name: str | None = None,
    ) -> SampleIdentity:
        sha256 = self._digest_bytes(data)
        sample = SampleIdentity.create(
            sha256=sha256,
            byte_length=len(data),
            media_type=media_type,
            original_name=original_name,
        )
        object_dir = self._object_dir(sample)
        sample_path = object_dir / "sample.bin"
        manifest_path = object_dir / "manifest.json"
        if sample_path.exists():
            actual_digest, actual_length = self._digest_path(sample_path)
            if actual_digest != sample.sha256 or actual_length != sample.byte_length:
                raise ValueError("Existing Sample Vault object differs from its content address")
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Existing Sample Vault manifest must be an object")
            stored = SampleIdentity(
                sample_id=str(value.get("sampleId", "")),
                sha256=str(value.get("sha256", "")),
                byte_length=int(value.get("byteLength", -1)),
                media_type=str(value.get("mediaType", "")),
                original_name=(
                    None if value.get("originalName") is None else str(value.get("originalName"))
                ),
            )
            if stored.sha256 != sample.sha256 or stored.byte_length != sample.byte_length:
                raise ValueError("Existing Sample Vault manifest differs from stored bytes")
            return stored
        object_dir.mkdir(parents=True, exist_ok=False)
        object_dir.chmod(0o700)
        temporary = object_dir / ".sample.bin.tmp"
        try:
            temporary.write_bytes(data)
            temporary.chmod(0o600)
            os.replace(temporary, sample_path)
            manifest_path.write_bytes(canonical_bytes(sample.to_dict()) + b"\n")
            manifest_path.chmod(0o600)
        except BaseException:
            shutil.rmtree(object_dir, ignore_errors=True)
            raise
        return sample

    def import_path(
        self,
        path: Path,
        *,
        media_type: str = "application/octet-stream",
    ) -> SampleIdentity:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Sample import path must be a regular non-symlink file")
        return self.import_bytes(
            path.read_bytes(),
            media_type=media_type,
            original_name=path.name,
        )

    def resolve(self, sample: SampleIdentity) -> Path:
        sample_path = self._object_dir(sample) / "sample.bin"
        if not sample_path.is_file() or sample_path.is_symlink():
            raise FileNotFoundError(f"Sample is not present in the Vault: {sample.sample_id}")
        actual_digest, actual_length = self._digest_path(sample_path)
        if actual_digest != sample.sha256 or actual_length != sample.byte_length:
            raise ValueError("Sample Vault bytes differ from the admitted Sample identity")
        return sample_path

    def purge(self, sample: SampleIdentity) -> Path:
        object_dir = self._object_dir(sample)
        existed = object_dir.exists()
        if existed:
            shutil.rmtree(object_dir)
        purged_at_ms = time.time_ns() // 1_000_000
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.sample-purge-receipt",
            "sampleId": sample.sample_id,
            "sampleDigest": sample.sha256,
            "objectExisted": existed,
            "purgedAtMs": purged_at_ms,
        }
        receipt_path = self.receipts_root / (
            f"purge-{sample.sha256.removeprefix('sha256:')}-{purged_at_ms}.json"
        )
        receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
        receipt_path.chmod(0o600)
        return receipt_path
