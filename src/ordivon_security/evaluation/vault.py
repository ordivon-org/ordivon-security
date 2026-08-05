from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_bytes, canonical_digest

from .models import SampleIdentity

_DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024


class SampleVault:
    """Private content-addressed local storage for non-executable Sample bytes.

    Path imports are streamed into a private staging directory, hashed while copied,
    fsynced, and atomically renamed into the content-addressed object tree. Complete
    bytes are verified again on every resolve. The Vault never executes or inspects
    Sample content and never places Sample bytes in evidence records.
    """

    def __init__(
        self,
        root: Path,
        *,
        max_sample_bytes: int | None = None,
        max_vault_bytes: int | None = None,
        chunk_bytes: int = _DEFAULT_CHUNK_BYTES,
    ) -> None:
        if max_sample_bytes is not None and max_sample_bytes < 1:
            raise ValueError("Sample Vault per-Sample limit must be positive")
        if max_vault_bytes is not None and max_vault_bytes < 1:
            raise ValueError("Sample Vault total limit must be positive")
        if chunk_bytes < 1:
            raise ValueError("Sample Vault chunk size must be positive")
        self.root = root
        self.objects_parent = root / "objects"
        self.objects_root = self.objects_parent / "sha256"
        self.receipts_root = root / "receipts"
        self.imports_root = root / "imports"
        self.max_sample_bytes = max_sample_bytes
        self.max_vault_bytes = max_vault_bytes
        self.chunk_bytes = chunk_bytes
        for path in (
            self.root,
            self.objects_parent,
            self.objects_root,
            self.receipts_root,
            self.imports_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        configuration: JsonObject = {
            "maxSampleBytes": self.max_sample_bytes,
            "maxVaultBytes": self.max_vault_bytes,
            "chunkBytes": self.chunk_bytes,
        }
        return {
            "kind": "ordivon.security.sample-vault",
            "revision": "2",
            "verification": "streaming-sha256-on-import-and-resolve",
            "commit": "private-staging-fsync-atomic-rename",
            "storage": "content-addressed-local-filesystem",
            "configurationDigest": canonical_digest(configuration),
        }

    @staticmethod
    def _digest_bytes(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def _digest_path(path: Path, *, chunk_bytes: int = _DEFAULT_CHUNK_BYTES) -> tuple[str, int]:
        digest = hashlib.sha256()
        byte_length = 0
        with path.open("rb") as handle:
            while chunk := handle.read(chunk_bytes):
                digest.update(chunk)
                byte_length += len(chunk)
        return "sha256:" + digest.hexdigest(), byte_length

    @staticmethod
    def _open_regular_nofollow(path: Path) -> BinaryIO:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Sample import path must be a regular file")
            return os.fdopen(descriptor, "rb", closefd=True)
        except BaseException:
            os.close(descriptor)
            raise

    def _object_dir(self, sample: SampleIdentity) -> Path:
        digest = sample.sha256.removeprefix("sha256:")
        return self.objects_root / digest[:2] / digest

    def _stored_bytes(self) -> int:
        total = 0
        for path in self.objects_root.glob("*/*/sample.bin"):
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        return total

    def _load_existing(self, sample: SampleIdentity) -> SampleIdentity | None:
        object_dir = self._object_dir(sample)
        sample_path = object_dir / "sample.bin"
        manifest_path = object_dir / "manifest.json"
        if not sample_path.exists() and not manifest_path.exists():
            return None
        if (
            not sample_path.is_file()
            or sample_path.is_symlink()
            or not manifest_path.is_file()
            or manifest_path.is_symlink()
        ):
            raise ValueError("Existing Sample Vault object is incomplete or unsafe")
        actual_digest, actual_length = self._digest_path(
            sample_path,
            chunk_bytes=self.chunk_bytes,
        )
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

    def _import_stream(
        self,
        source: BinaryIO,
        *,
        expected_length: int | None,
        media_type: str,
        original_name: str | None,
    ) -> SampleIdentity:
        if expected_length is not None and expected_length < 0:
            raise ValueError("Sample expected length must be non-negative")
        if (
            expected_length is not None
            and self.max_sample_bytes is not None
            and expected_length > self.max_sample_bytes
        ):
            raise ValueError("Sample exceeds the configured per-Sample Vault limit")

        staging_dir = Path(tempfile.mkdtemp(prefix="import-", dir=self.imports_root))
        staging_dir.chmod(0o700)
        temporary_path = staging_dir / "sample.bin"
        digest = hashlib.sha256()
        byte_length = 0
        try:
            with temporary_path.open("xb") as destination:
                temporary_path.chmod(0o600)
                while chunk := source.read(self.chunk_bytes):
                    if not isinstance(chunk, bytes):
                        raise TypeError("Sample source must return bytes")
                    byte_length += len(chunk)
                    if self.max_sample_bytes is not None and byte_length > self.max_sample_bytes:
                        raise ValueError("Sample exceeds the configured per-Sample Vault limit")
                    destination.write(chunk)
                    digest.update(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if expected_length is not None and byte_length != expected_length:
                raise ValueError("Sample source length changed during import")

            sha256 = "sha256:" + digest.hexdigest()
            sample = SampleIdentity.create(
                sha256=sha256,
                byte_length=byte_length,
                media_type=media_type,
                original_name=original_name,
            )
            existing = self._load_existing(sample)
            if existing is not None:
                return existing
            if self.max_vault_bytes is not None:
                projected = self._stored_bytes() + sample.byte_length
                if projected > self.max_vault_bytes:
                    raise ValueError("Sample import exceeds the configured total Vault limit")

            manifest_path = staging_dir / "manifest.json"
            manifest_path.write_bytes(canonical_bytes(sample.to_dict()) + b"\n")
            manifest_path.chmod(0o600)
            with manifest_path.open("rb") as manifest_handle:
                os.fsync(manifest_handle.fileno())

            object_dir = self._object_dir(sample)
            object_dir.parent.mkdir(parents=True, exist_ok=True)
            object_dir.parent.chmod(0o700)
            try:
                os.rename(staging_dir, object_dir)
            except FileExistsError:
                existing = self._load_existing(sample)
                if existing is None:
                    raise
                return existing
            return sample
        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)

    def import_bytes(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        original_name: str | None = None,
    ) -> SampleIdentity:
        return self._import_stream(
            io.BytesIO(data),
            expected_length=len(data),
            media_type=media_type,
            original_name=original_name,
        )

    def import_path(
        self,
        path: Path,
        *,
        media_type: str = "application/octet-stream",
    ) -> SampleIdentity:
        if path.is_symlink():
            raise ValueError("Sample import path must not be a symlink")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Sample import path must be a regular file")
        with self._open_regular_nofollow(path) as source:
            return self._import_stream(
                source,
                expected_length=metadata.st_size,
                media_type=media_type,
                original_name=path.name,
            )

    def resolve(self, sample: SampleIdentity) -> Path:
        sample_path = self._object_dir(sample) / "sample.bin"
        if not sample_path.is_file() or sample_path.is_symlink():
            raise FileNotFoundError(f"Sample is not present in the Vault: {sample.sample_id}")
        actual_digest, actual_length = self._digest_path(
            sample_path,
            chunk_bytes=self.chunk_bytes,
        )
        if actual_digest != sample.sha256 or actual_length != sample.byte_length:
            raise ValueError("Sample Vault bytes differ from the admitted Sample identity")
        return sample_path

    def recover_incomplete_imports(self) -> Path:
        removed: list[str] = []
        for path in sorted(self.imports_root.iterdir()):
            if path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(path.name)
        recovered_at_ms = time.time_ns() // 1_000_000
        receipt: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.sample-import-recovery-receipt",
            "removedEntries": cast(list[JsonValue], removed),
            "recoveredAtMs": recovered_at_ms,
        }
        receipt_path = self.receipts_root / f"import-recovery-{time.time_ns()}.json"
        receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
        receipt_path.chmod(0o600)
        return receipt_path

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
            f"purge-{sample.sha256.removeprefix('sha256:')}-{time.time_ns()}.json"
        )
        receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")
        receipt_path.chmod(0o600)
        return receipt_path
