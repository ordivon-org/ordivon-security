from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest, validate_json

from .backend import (
    EvaluationArtifact,
    EvaluationExecution,
    EvaluationInstance,
    GuardianRecord,
    ObserverRecord,
    ResidualClosureReceipt,
)
from .models import EvaluationSpec, SampleIdentity

_REPORT_LIMIT_BYTES = 32 * 1024 * 1024
_FOUND_PATTERN = re.compile(r"^(.*?):\s+(.+?)\s+FOUND$")
_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")


def _digest_path(path: Path, *, chunk_bytes: int = 4 * 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_length = 0
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_bytes):
            digest.update(chunk)
            byte_length += len(chunk)
    return "sha256:" + digest.hexdigest(), byte_length


def _artifact(path: Path, *, kind: str, media_type: str, logical_name: str) -> EvaluationArtifact:
    digest, byte_length = _digest_path(path)
    return EvaluationArtifact(
        artifact_id=f"artifact:{digest.removeprefix('sha256:')}",
        kind=kind,
        digest=digest,
        byte_length=byte_length,
        media_type=media_type,
        logical_name=logical_name,
        source_path=path,
    )


def _write_report(path: Path, content: bytes) -> None:
    if len(content) > _REPORT_LIMIT_BYTES:
        raise ValueError("Static analyzer report exceeds the P0 report bound")
    path.write_bytes(content)
    path.chmod(0o600)


def _binary_identity(path: Path, version_args: tuple[str, ...]) -> JsonObject:
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"Static analyzer executable is unavailable: {path}")
    digest, byte_length = _digest_path(path)
    completed = subprocess.run(
        [str(path), *version_args],
        check=False,
        capture_output=True,
        timeout=10,
    )
    version_output = (completed.stdout + completed.stderr)[:4096].decode("utf-8", errors="replace")
    return {
        "pathName": path.name,
        "digest": digest,
        "byteLength": byte_length,
        "versionOutput": version_output.strip(),
        "versionExitCode": completed.returncode,
    }


def _safe_archive_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    if not normalized or normalized.startswith("/") or _DRIVE_PATTERN.match(value):
        return False
    return ".." not in PurePosixPath(normalized).parts


@dataclass(frozen=True, slots=True)
class StaticAnalyzerResult:
    observer_records: tuple[ObserverRecord, ...]
    artifacts: tuple[EvaluationArtifact, ...]
    raw_metrics: JsonObject

    def __post_init__(self) -> None:
        validate_json(self.raw_metrics)


class StaticAnalyzer(Protocol):
    analyzer_id: str

    @property
    def execution_identity(self) -> JsonObject: ...

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult: ...


class FileIdentityAnalyzer:
    analyzer_id = "static-analyzer:file-identity"

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "analyzerId": self.analyzer_id,
            "implementationRevision": "1",
            "sampleExecution": False,
        }

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        digest, byte_length = _digest_path(sample_path)
        if digest != sample.sha256 or byte_length != sample.byte_length:
            raise ValueError("Static file analyzer received bytes outside Sample identity")
        return StaticAnalyzerResult(
            observer_records=(
                ObserverRecord(
                    channel=self.analyzer_id,
                    event_type="static.file-identity",
                    payload={
                        "sampleId": sample.sample_id,
                        "sampleDigest": sample.sha256,
                        "byteLength": sample.byte_length,
                        "mediaType": sample.media_type,
                        "originalName": sample.original_name,
                    },
                ),
            ),
            artifacts=(),
            raw_metrics={"static.file_identity_verified": True},
        )


class ArchiveInventoryAnalyzer:
    analyzer_id = "static-analyzer:archive-inventory"

    def __init__(
        self,
        executable: Path = Path("/usr/bin/7z"),
        *,
        timeout_seconds: int = 120,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("Archive analyzer timeout must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self._tool_identity = _binary_identity(executable, ())

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "analyzerId": self.analyzer_id,
            "implementationRevision": "1",
            "tool": self._tool_identity,
            "arguments": ["l", "-slt", "--", "<sample>"],
            "timeoutSeconds": self.timeout_seconds,
            "sampleExecution": False,
        }

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        completed = subprocess.run(
            [str(self.executable), "l", "-slt", "--", str(sample_path)],
            check=False,
            capture_output=True,
            timeout=self.timeout_seconds,
        )
        normalized = (completed.stdout + completed.stderr).replace(
            str(sample_path).encode("utf-8"), b"<sample>"
        )
        report_path = work_dir / "archive-inventory.txt"
        _write_report(report_path, normalized)
        if completed.returncode != 0:
            raise RuntimeError(f"Archive inventory failed with exit code {completed.returncode}")
        text = normalized.decode("utf-8", errors="replace")
        archive_type: str | None = None
        paths: list[str] = []
        for line in text.splitlines():
            if archive_type is None and line.startswith("Type = "):
                archive_type = line.removeprefix("Type = ").strip()
            if line.startswith("Path = "):
                value = line.removeprefix("Path = ").strip()
                if value != "<sample>":
                    paths.append(value)
        unsafe = tuple(value for value in paths if not _safe_archive_path(value))
        records = [
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.archive-inventory",
                payload={
                    "archiveType": archive_type,
                    "entryCount": len(paths),
                    "unsafePathCount": len(unsafe),
                    "reportDigest": _digest_path(report_path)[0],
                },
            )
        ]
        records.extend(
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.archive-path-traversal",
                payload={"entryPath": value, "reportDigest": _digest_path(report_path)[0]},
            )
            for value in unsafe
        )
        return StaticAnalyzerResult(
            observer_records=tuple(records),
            artifacts=(
                _artifact(
                    report_path,
                    kind="archive-inventory-report",
                    media_type="text/plain",
                    logical_name="archive-inventory.txt",
                ),
            ),
            raw_metrics={
                "static.archive_entry_count": len(paths),
                "static.archive_unsafe_path_count": len(unsafe),
            },
        )


class ClamAvAnalyzer:
    analyzer_id = "static-analyzer:clamav"

    def __init__(
        self,
        executable: Path = Path("/usr/bin/clamscan"),
        *,
        timeout_seconds: int = 600,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("ClamAV analyzer timeout must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self._tool_identity = _binary_identity(executable, ("--version",))

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "analyzerId": self.analyzer_id,
            "implementationRevision": "1",
            "tool": self._tool_identity,
            "arguments": ["--no-summary", "--infected", "--stdout", "--", "<sample>"],
            "timeoutSeconds": self.timeout_seconds,
            "sampleExecution": False,
        }

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        completed = subprocess.run(
            [
                str(self.executable),
                "--no-summary",
                "--infected",
                "--stdout",
                "--",
                str(sample_path),
            ],
            check=False,
            capture_output=True,
            timeout=self.timeout_seconds,
        )
        normalized = (completed.stdout + completed.stderr).replace(
            str(sample_path).encode("utf-8"), b"<sample>"
        )
        report_path = work_dir / "clamav-report.txt"
        _write_report(report_path, normalized)
        if completed.returncode not in {0, 1}:
            raise RuntimeError(f"ClamAV failed with exit code {completed.returncode}")
        report_digest = _digest_path(report_path)[0]
        detections: list[tuple[str, str]] = []
        limitations: list[str] = []
        for line in normalized.decode("utf-8", errors="replace").splitlines():
            stripped = line.strip()
            match = _FOUND_PATTERN.match(stripped)
            if match:
                detections.append((match.group(1), match.group(2)))
            if "not supported" in stripped.lower() or stripped.startswith("LibClamAV Warning:"):
                limitations.append(stripped)
        records = [
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.antivirus-summary",
                payload={
                    "engine": "ClamAV",
                    "exitCode": completed.returncode,
                    "detectionCount": len(detections),
                    "reportDigest": report_digest,
                    "limitations": cast(list[JsonValue], limitations),
                },
            )
        ]
        records.extend(
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.antivirus-detection",
                payload={
                    "engine": "ClamAV",
                    "subjectPath": path,
                    "signature": signature,
                    "reportDigest": report_digest,
                    "limitations": [
                        "A signature match is an Observer result, not independent proof "
                        "of behavior."
                    ],
                },
            )
            for path, signature in detections
        )
        return StaticAnalyzerResult(
            observer_records=tuple(records),
            artifacts=(
                _artifact(
                    report_path,
                    kind="antivirus-report",
                    media_type="text/plain",
                    logical_name="clamav-report.txt",
                ),
            ),
            raw_metrics={
                "static.clamav_detection_count": len(detections),
                "static.clamav_limitation_count": len(limitations),
            },
        )


class ImportedReportAnalyzer:
    def __init__(
        self,
        *,
        report_id: str,
        tool_id: str,
        report_path: Path,
        report_kind: str,
        media_type: str = "text/plain",
        limitations: tuple[str, ...] = (),
    ) -> None:
        if not report_id or not tool_id or not report_kind:
            raise ValueError("Imported report identity, tool and kind must be non-empty")
        if not report_path.is_file() or report_path.is_symlink():
            raise FileNotFoundError(f"Imported static report is unavailable: {report_path}")
        self.analyzer_id = f"static-analyzer:import:{report_id}"
        self.report_id = report_id
        self.tool_id = tool_id
        self.report_path = report_path
        self.report_kind = report_kind
        self.media_type = media_type
        self.limitations = limitations
        self._digest, self._byte_length = _digest_path(report_path)

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "analyzerId": self.analyzer_id,
            "implementationRevision": "1",
            "toolId": self.tool_id,
            "sourceReportDigest": self._digest,
            "sourceReportByteLength": self._byte_length,
            "reportKind": self.report_kind,
            "mediaType": self.media_type,
            "limitations": list(self.limitations),
            "sampleExecution": False,
        }

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        digest, byte_length = _digest_path(self.report_path)
        if digest != self._digest or byte_length != self._byte_length:
            raise ValueError("Imported static report changed after backend identity was bound")
        return StaticAnalyzerResult(
            observer_records=(
                ObserverRecord(
                    channel=self.analyzer_id,
                    event_type="static.native-report-imported",
                    payload={
                        "reportId": self.report_id,
                        "toolId": self.tool_id,
                        "reportKind": self.report_kind,
                        "reportDigest": digest,
                        "byteLength": byte_length,
                        "limitations": list(self.limitations),
                    },
                ),
            ),
            artifacts=(
                _artifact(
                    self.report_path,
                    kind=self.report_kind,
                    media_type=self.media_type,
                    logical_name=self.report_path.name,
                ),
            ),
            raw_metrics={f"static.imported_report.{self.report_id}": True},
        )


class ClamAvReportAnalyzer(ImportedReportAnalyzer):
    def __init__(self, report_path: Path, *, report_id: str = "clamav-existing") -> None:
        super().__init__(
            report_id=report_id,
            tool_id="tool:clamav",
            report_path=report_path,
            report_kind="antivirus-report",
            limitations=(
                "Imported report is historical Observer evidence and was not rerun by this Trial.",
                "Association between this report and the admitted Sample is operator-supplied "
                "unless the report independently binds the Sample digest.",
                "A signature match is not independent proof of runtime behavior.",
            ),
        )

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        base = super().analyze(sample_path, sample, work_dir)
        text = self.report_path.read_text(encoding="utf-8", errors="replace")
        report_digest = self._digest
        records = list(base.observer_records)
        detections: list[tuple[str, str]] = []
        summary: JsonObject = {"engine": "ClamAV", "reportDigest": report_digest}
        for line in text.splitlines():
            match = _FOUND_PATTERN.match(line.strip())
            if match:
                detections.append((match.group(1), match.group(2)))
            if line.startswith("Engine version:"):
                summary["engineVersion"] = line.partition(":")[2].strip()
            elif line.startswith("Known viruses:"):
                summary["knownViruses"] = int(line.partition(":")[2].strip())
            elif line.startswith("Scanned files:"):
                summary["scannedFiles"] = int(line.partition(":")[2].strip())
            elif line.startswith("Infected files:"):
                summary["infectedFiles"] = int(line.partition(":")[2].strip())
        summary["detectionCount"] = len(detections)
        records.append(
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.antivirus-summary",
                payload=summary,
            )
        )
        records.extend(
            ObserverRecord(
                channel=self.analyzer_id,
                event_type="static.antivirus-detection",
                payload={
                    "engine": "ClamAV",
                    "subjectPath": path,
                    "signature": signature,
                    "reportDigest": report_digest,
                    "historicalImport": True,
                    "limitations": [
                        "The report was produced before this Trial and is bound by digest.",
                        "A signature match is an Observer result, not independent proof "
                        "of behavior.",
                    ],
                },
            )
            for path, signature in detections
        )
        return StaticAnalyzerResult(
            observer_records=tuple(records),
            artifacts=base.artifacts,
            raw_metrics={
                **base.raw_metrics,
                "static.clamav_detection_count": len(detections),
            },
        )


class AuthenticodeReportAnalyzer(ImportedReportAnalyzer):
    def __init__(self, report_path: Path, *, report_id: str = "authenticode-existing") -> None:
        super().__init__(
            report_id=report_id,
            tool_id="tool:operator-authenticode-digest-check",
            report_path=report_path,
            report_kind="authenticode-summary-report",
            limitations=(
                "Imported custom report validates embedded file digests but is not WinVerifyTrust.",
                "Association between this report and the admitted Sample is operator-supplied "
                "unless the report independently binds the Sample digest.",
                "Certificate chain, revocation, timestamp and Windows policy were not proven here.",
            ),
        )

    def analyze(
        self,
        sample_path: Path,
        sample: SampleIdentity,
        work_dir: Path,
    ) -> StaticAnalyzerResult:
        base = super().analyze(sample_path, sample, work_dir)
        text = self.report_path.read_text(encoding="utf-8", errors="replace")
        counts: dict[str, int] = {}
        unsigned: list[str] = []
        in_unsigned = False
        for line in text.splitlines():
            stripped = line.strip()
            count_match = re.match(
                r"(VERIFIED_VENDORB|VERIFIED_OTHER|UNSIGNED|DIGEST_MISMATCH):"
                r"\s+(\d+)$",
                stripped,
            )
            if count_match:
                counts[count_match.group(1)] = int(count_match.group(2))
            if stripped == "=== UNSIGNED (all) ===":
                in_unsigned = True
                continue
            if in_unsigned and stripped.startswith("==="):
                in_unsigned = False
            elif in_unsigned and stripped:
                unsigned.append(stripped)
        record = ObserverRecord(
            channel=self.analyzer_id,
            event_type="static.authenticode-summary",
            payload={
                "reportDigest": self._digest,
                "counts": cast(JsonObject, counts),
                "unsignedPaths": cast(list[JsonValue], unsigned),
                "authorityClass": "custom-digest-consistency-check",
                "limitations": list(self.limitations),
            },
        )
        return StaticAnalyzerResult(
            observer_records=(*base.observer_records, record),
            artifacts=base.artifacts,
            raw_metrics={
                **base.raw_metrics,
                "static.authenticode_unsigned_count": counts.get("UNSIGNED", len(unsigned)),
                "static.authenticode_digest_mismatch_count": counts.get("DIGEST_MISMATCH", 0),
            },
        )


class LocalStaticEvaluationBackend:
    """Local observe-only backend that invokes analyzers but never the Sample."""

    backend_id = "backend:local-static-analysis"
    provider_id = "provider:local-static-analysis"

    def __init__(self, analyzers: tuple[StaticAnalyzer, ...], *, work_root: Path) -> None:
        if not analyzers:
            raise ValueError("Static Evaluation requires at least one analyzer")
        analyzer_ids = tuple(analyzer.analyzer_id for analyzer in analyzers)
        if len(analyzer_ids) != len(set(analyzer_ids)):
            raise ValueError("Static analyzer identities must be unique")
        self.analyzers = analyzers
        self.work_root = work_root
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.work_root.chmod(0o700)

    @property
    def execution_identity(self) -> JsonObject:
        configuration: JsonObject = {
            "analyzers": [analyzer.execution_identity for analyzer in self.analyzers],
        }
        return {
            "kind": "ordivon.security.evaluation-backend",
            "backendId": self.backend_id,
            "providerId": self.provider_id,
            "implementationRevision": "1",
            "configurationDigest": canonical_digest(configuration),
            "analyzers": configuration["analyzers"],
            "analysisMode": "static-only",
            "sampleExecution": False,
        }

    def create(self, run_id: str, spec: EvaluationSpec) -> EvaluationInstance:
        token = run_id.removeprefix("evaluation-run:")
        work_dir = self.work_root / token
        if work_dir.exists():
            raise FileExistsError(f"Static analysis work directory already exists: {work_dir}")
        work_dir.mkdir(parents=True)
        work_dir.chmod(0o700)
        return EvaluationInstance(
            instance_id=f"evaluation-instance:{token}",
            generation=f"static-generation:{spec.environment.configuration_digest[-16:]}",
            state={"workDir": str(work_dir)},
        )

    def stage(
        self,
        instance: EvaluationInstance,
        sample_path: Path,
        sample: SampleIdentity,
    ) -> JsonObject:
        digest, byte_length = _digest_path(sample_path)
        if digest != sample.sha256 or byte_length != sample.byte_length:
            raise ValueError("Static backend received bytes outside the admitted Sample identity")
        instance.state["samplePath"] = str(sample_path)
        instance.state["sampleDigest"] = sample.sha256
        return {
            "instanceId": instance.instance_id,
            "sampleId": sample.sample_id,
            "sampleDigest": sample.sha256,
            "analysisMode": "static-only",
            "executed": False,
        }

    def execute(
        self,
        instance: EvaluationInstance,
        spec: EvaluationSpec,
    ) -> EvaluationExecution:
        if instance.state.get("sampleDigest") != spec.sample.sha256:
            raise ValueError("Static Evaluation Sample was not staged")
        sample_path = Path(str(instance.state["samplePath"]))
        work_dir = Path(str(instance.state["workDir"]))
        observer_records: list[ObserverRecord] = []
        artifacts: list[EvaluationArtifact] = []
        raw_metrics: JsonObject = {}
        completed: list[str] = []
        for index, analyzer in enumerate(self.analyzers):
            analyzer_dir = work_dir / f"{index:02d}-{analyzer.analyzer_id.replace(':', '-')}"
            analyzer_dir.mkdir()
            analyzer_dir.chmod(0o700)
            result = analyzer.analyze(sample_path, spec.sample, analyzer_dir)
            observer_records.extend(result.observer_records)
            artifacts.extend(result.artifacts)
            for key, value in result.raw_metrics.items():
                if key in raw_metrics:
                    raise ValueError(f"Static analyzer metric identity is duplicated: {key}")
                raw_metrics[key] = value
            completed.append(analyzer.analyzer_id)
        raw_metrics.update(
            {
                "static.sample_executed": False,
                "static.analyzer_count": len(self.analyzers),
                "static.observer_event_count": len(observer_records),
                "static.native_report_count": len(artifacts),
            }
        )
        return EvaluationExecution(
            terminal_reason="static-analysis-completed",
            observer_records=tuple(observer_records),
            guardian_records=(
                GuardianRecord(
                    decision="allow",
                    reason="static-analysis-only",
                    payload={"sampleExecuted": False},
                ),
            ),
            world_facts={
                "analysisMode": "static-only",
                "sampleExecuted": False,
                "analyzerIds": cast(
                    list[JsonValue],
                    [analyzer.analyzer_id for analyzer in self.analyzers],
                ),
                "completedAnalyzerIds": cast(list[JsonValue], completed),
            },
            raw_metrics=raw_metrics,
            artifacts=tuple(artifacts),
        )

    def destroy(self, instance: EvaluationInstance) -> ResidualClosureReceipt:
        value = instance.state.get("workDir")
        if not isinstance(value, str) or not value:
            return ResidualClosureReceipt(
                clean=False,
                details={
                    "instanceId": instance.instance_id,
                    "generation": instance.generation,
                    "sampleExecuted": False,
                    "analysisMode": "static-only",
                    "workDirectoryRemoved": False,
                    "residualObjects": ["unknown-static-work-directory"],
                },
            )
        work_dir = Path(value)
        if work_dir.exists():
            shutil.rmtree(work_dir)
        clean = not work_dir.exists()
        return ResidualClosureReceipt(
            clean=clean,
            details={
                "instanceId": instance.instance_id,
                "generation": instance.generation,
                "sampleExecuted": False,
                "analysisMode": "static-only",
                "workDirectoryRemoved": clean,
                "residualObjects": [] if clean else [str(work_dir)],
            },
        )
