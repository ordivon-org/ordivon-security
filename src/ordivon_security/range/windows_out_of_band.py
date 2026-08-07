from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ordivon_security._canonical import JsonObject, validate_json


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _text_contains(value: bytes, needle: str) -> bool:
    lowered_needle = needle.casefold()
    for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            decoded = value.decode(encoding)
        except UnicodeDecodeError:
            continue
        if lowered_needle in decoded.casefold():
            return True
    return False


@dataclass(frozen=True, slots=True)
class WindowsOfflineNtfsConfig:
    qemu_nbd_path: Path = Path("/usr/bin/qemu-nbd")
    partx_path: Path = Path("/usr/bin/partx")
    ntfsls_path: Path = Path("/usr/bin/ntfsls")
    ntfscat_path: Path = Path("/usr/bin/ntfscat")
    sys_block_root: Path = Path("/sys/block")
    device_root: Path = Path("/dev")
    max_nbd_devices: int = 16
    max_file_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        for path in (self.qemu_nbd_path, self.partx_path, self.ntfsls_path, self.ntfscat_path):
            if not path.is_file() or not path.resolve().is_file():
                raise ValueError(f"offline NTFS tool is missing or unsafe: {path}")
        if self.max_nbd_devices < 1 or self.max_file_bytes < 1:
            raise ValueError("offline NTFS limits must be positive")


class WindowsOfflineNtfsInspector:
    """Read a stopped qcow2 Windows filesystem through a read-only host NBD view."""

    def __init__(self, config: WindowsOfflineNtfsConfig | None = None) -> None:
        self.config = WindowsOfflineNtfsConfig() if config is None else config

    @property
    def execution_identity(self) -> JsonObject:
        identity: JsonObject = {
            "kind": "ordivon.security.windows-offline-ntfs-inspector",
            "implementationRevision": "1",
            "transport": "qemu-nbd-read-only",
            "filesystem": "ntfs-3g-userspace-read",
            "tools": {
                "qemuNbd": {
                    "digest": _digest_path(self.config.qemu_nbd_path),
                },
                "partx": {
                    "digest": _digest_path(self.config.partx_path),
                },
                "ntfsls": {
                    "digest": _digest_path(self.config.ntfsls_path),
                },
                "ntfscat": {
                    "digest": _digest_path(self.config.ntfscat_path),
                },
            },
        }
        validate_json(identity)
        return identity

    def inspect(
        self,
        image_path: Path,
        *,
        file_paths: tuple[str, ...],
        text_checks: dict[str, tuple[str, str]] | None = None,
    ) -> JsonObject:
        if image_path.is_symlink() or not image_path.is_file():
            raise ValueError("offline NTFS image is missing or unsafe")
        if not file_paths or len(file_paths) != len(set(file_paths)):
            raise ValueError("offline NTFS file paths must be non-empty and unique")
        for value in file_paths:
            self._validate_guest_path(value)
        checks = {} if text_checks is None else text_checks
        for label, (path, needle) in checks.items():
            if not label or label != label.strip() or path not in file_paths or not needle:
                raise ValueError("offline NTFS text check is invalid")

        device = self._connect_read_only(image_path)
        try:
            partition, partition_number = self._windows_partition(device)
            file_results: list[JsonObject] = []
            contents: dict[str, bytes | None] = {}
            for path in file_paths:
                content = self._read_file(partition, path)
                contents[path] = content
                if content is None:
                    file_results.append({"path": path, "present": False})
                    continue
                if len(content) > self.config.max_file_bytes:
                    raise ValueError(f"offline NTFS file exceeds bounded read: {path}")
                file_results.append(
                    {
                        "path": path,
                        "present": True,
                        "byteLength": len(content),
                        "digest": _digest_bytes(content),
                    }
                )
            text_results: JsonObject = {}
            for label, (path, needle) in checks.items():
                content = contents[path]
                text_results[label] = content is not None and _text_contains(content, needle)
            result: JsonObject = {
                "kind": "ordivon.security.windows-offline-ntfs-observation",
                "authority": "host-offline-read-only-ntfs",
                "readOnlyTransport": True,
                "windowsPartitionNumber": partition_number,
                "files": file_results,
                "textChecks": text_results,
                "inspectorIdentity": self.execution_identity,
            }
            validate_json(result)
            return result
        finally:
            self._disconnect(device)

    @staticmethod
    def _validate_guest_path(value: str) -> None:
        if not value.startswith("/") or "\\" in value or "\x00" in value:
            raise ValueError("offline NTFS path must be an absolute slash path")
        if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
            raise ValueError("offline NTFS path contains an unsafe component")

    def _connect_read_only(self, image_path: Path) -> Path:
        failures: list[str] = []
        for index in range(self.config.max_nbd_devices):
            name = f"nbd{index}"
            sys_root = self.config.sys_block_root / name
            device = self.config.device_root / name
            if not sys_root.is_dir() or not device.exists():
                continue
            try:
                if int((sys_root / "size").read_text(encoding="utf-8").strip()) != 0:
                    continue
            except (OSError, ValueError):
                continue
            completed = subprocess.run(
                [
                    str(self.config.qemu_nbd_path),
                    "--read-only",
                    "--format=qcow2",
                    f"--connect={device}",
                    str(image_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            if completed.returncode != 0:
                failures.append(completed.stdout.decode("utf-8", errors="replace")[-500:])
                continue
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    size = int((sys_root / "size").read_text(encoding="utf-8").strip())
                    read_only = (sys_root / "ro").read_text(encoding="utf-8").strip() == "1"
                except (OSError, ValueError):
                    size = 0
                    read_only = False
                if size > 0 and read_only:
                    subprocess.run(
                        [str(self.config.partx_path), "-u", str(device)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=10,
                    )
                    return device
                time.sleep(0.1)
            self._disconnect(device)
            raise RuntimeError("offline NBD connection did not become read-only and ready")
        detail = failures[-1] if failures else "no free NBD device"
        raise RuntimeError(f"unable to attach offline Windows image read-only: {detail}")

    def _windows_partition(self, device: Path) -> tuple[Path, int]:
        deadline = time.monotonic() + 5
        candidates: list[tuple[Path, int]] = []
        while time.monotonic() < deadline:
            candidates = [
                (Path(f"{device}p{index}"), index)
                for index in range(1, 17)
                if Path(f"{device}p{index}").exists()
            ]
            if candidates:
                break
            time.sleep(0.1)
        for partition, index in candidates:
            completed = subprocess.run(
                [str(self.config.ntfsls_path), "-p", "/Windows", str(partition)],
                capture_output=True,
                timeout=15,
            )
            if completed.returncode == 0:
                return partition, index
        raise RuntimeError("offline NTFS inspector could not identify the Windows partition")

    def _read_file(self, partition: Path, guest_path: str) -> bytes | None:
        completed = subprocess.run(
            [str(self.config.ntfscat_path), str(partition), guest_path],
            capture_output=True,
            timeout=30,
        )
        if completed.returncode == 0:
            return completed.stdout
        message = completed.stderr.decode("utf-8", errors="replace")
        if "No such file or directory" in message:
            return None
        raise RuntimeError(f"offline NTFS read failed for {guest_path}: {message[-500:]}")

    def _disconnect(self, device: Path) -> None:
        subprocess.run(
            [str(self.config.partx_path), "-d", str(device)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
        completed = subprocess.run(
            [str(self.config.qemu_nbd_path), "--disconnect", str(device)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        if completed.returncode != 0:
            raise RuntimeError("offline NBD disconnect failed")
        sys_root = self.config.sys_block_root / device.name
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if int((sys_root / "size").read_text(encoding="utf-8").strip()) == 0:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        raise RuntimeError("offline NBD device remained connected after disconnect")
