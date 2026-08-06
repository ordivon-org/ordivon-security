from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.evaluation import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationRunner,
    EvaluationSpec,
    GuardianPolicy,
    ObservationPlan,
    SampleVault,
)
from ordivon_security.evaluation.windows_kvm import (
    _READONLY_MEDIA_FIXTURE_ID,
    WindowsKvmEvaluationBackend,
    WindowsKvmProviderConfig,
)


def _load_object(path: Path, label: str) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _digest_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
            length += len(chunk)
    return "sha256:" + digest.hexdigest(), length


def _c_string(value: str) -> str:
    if not value or any(ord(character) < 32 or ord(character) > 126 for character in value):
        raise ValueError("Windows KVM P1 verifier requires one printable ASCII archive name")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _compile_verifier(
    output_path: Path,
    *,
    archive_name: str,
    archive_digest: str,
    archive_byte_length: int,
) -> JsonObject:
    template_path = Path(__file__).parent / "resources/windows_kvm/readonly_media_fixture.c.in"
    compiler = Path("/usr/bin/x86_64-w64-mingw32-gcc")
    objdump = Path("/usr/bin/x86_64-w64-mingw32-objdump")
    for path in (template_path, compiler, objdump):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Windows KVM P1 verifier dependency is missing or unsafe: {path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    source_path = output_path.with_suffix(".c")
    if source_path.exists() or output_path.exists():
        raise FileExistsError("Windows KVM P1 verifier output already exists")
    source_path.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
    source_path.chmod(0o600)
    command = [
        str(compiler),
        "-municode",
        "-Os",
        "-s",
        "-static",
        "-Wl,--dynamicbase",
        "-Wl,--nxcompat",
        f"-DEXPECTED_ARCHIVE_NAME={_c_string(archive_name)}",
        f"-DEXPECTED_ARCHIVE_SHA256={_c_string(archive_digest.removeprefix('sha256:'))}",
        f"-DEXPECTED_ARCHIVE_LENGTH={archive_byte_length}ULL",
        "-o",
        str(output_path),
        str(source_path),
        "-lbcrypt",
    ]
    try:
        subprocess.run(command, check=True, timeout=180)
        output_path.chmod(0o600)
        imports = subprocess.run(
            [str(objdump), "-p", str(output_path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        ).stdout.lower()
        prohibited = ("ws2_32", "wininet", "winhttp", "urlmon", "dnsapi", "iphlpapi")
        matches = [value for value in prohibited if value in imports]
        if matches:
            raise ValueError(f"Windows KVM P1 verifier imports network APIs: {matches}")
        return {
            "fixtureId": _READONLY_MEDIA_FIXTURE_ID,
            "templateDigest": _digest_path(template_path)[0],
            "generatedSourceDigest": _digest_path(source_path)[0],
            "fixtureDigest": _digest_path(output_path)[0],
            "fixtureByteLength": output_path.stat().st_size,
            "compilerDigest": _digest_path(compiler)[0],
            "compilerVersion": subprocess.run(
                [str(compiler), "--version"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                timeout=30,
            ).stdout.splitlines()[0],
            "archiveName": archive_name,
            "archiveDigest": archive_digest,
            "archiveByteLength": archive_byte_length,
            "networkImportMatches": [],
        }
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise
    finally:
        source_path.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify one attached P1 NTFS Sample disk from the sealed Windows Guest."
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--media-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--run-index", type=int, default=0)
    parser.add_argument("--memory-mib", type=int, default=5120)
    parser.add_argument("--vcpus", type=int, default=4)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    media_manifest = _load_object(args.media_manifest, "Windows KVM P1 media manifest")
    if (
        media_manifest.get("schemaVersion") != 1
        or media_manifest.get("kind") != "ordivon.security.windows-kvm-p1-sample-media"
    ):
        raise ValueError("Windows KVM P1 media manifest schema is unsupported")
    source = media_manifest.get("source")
    media = media_manifest.get("media")
    if not isinstance(source, dict) or not isinstance(media, dict):
        raise ValueError("Windows KVM P1 media manifest sections are missing")
    if (
        media.get("readOnly") is not True
        or media.get("removable") is not True
        or media.get("serial") != "ORDIVON_P1"
    ):
        raise ValueError("Windows KVM P1 media is not admitted as read-only removable input")
    image_path = Path(str(media.get("path", "")))
    if image_path.is_symlink() or not image_path.is_file():
        raise ValueError("Windows KVM P1 media image is missing or unsafe")
    media_root = (args.state_root / "sample-media").resolve(strict=True)
    resolved_image_path = image_path.resolve(strict=True)
    media_directory = resolved_image_path.parent
    if (
        media_directory.is_symlink()
        or not media_directory.is_dir()
        or media_directory.parent != media_root
    ):
        raise ValueError("Windows KVM P1 media path is outside the admitted media root")
    image_path = resolved_image_path
    actual_media_digest, actual_media_length = _digest_path(image_path)
    if actual_media_digest != media.get("digest") or actual_media_length != media.get("byteLength"):
        raise ValueError("Windows KVM P1 media image differs from the sealed manifest")
    archive_digest_value = source.get("digest")
    archive_name_value = source.get("logicalName")
    archive_byte_length_value = source.get("byteLength")
    if (
        not isinstance(archive_digest_value, str)
        or not archive_digest_value.startswith("sha256:")
        or not isinstance(archive_name_value, str)
        or not archive_name_value
        or isinstance(archive_byte_length_value, bool)
        or not isinstance(archive_byte_length_value, int)
        or archive_byte_length_value < 0
    ):
        raise ValueError("Windows KVM P1 archive identity is invalid")
    archive_digest = archive_digest_value
    archive_name = archive_name_value
    archive_byte_length = archive_byte_length_value

    fixture_root = args.state_root / "fixtures"
    fixture_path = fixture_root / f"{_READONLY_MEDIA_FIXTURE_ID}-run-{args.run_index}.exe"
    compilation = _compile_verifier(
        fixture_path,
        archive_name=archive_name,
        archive_digest=archive_digest,
        archive_byte_length=archive_byte_length,
    )
    original_stat = image_path.stat()
    original_mode = stat.S_IMODE(original_stat.st_mode)
    original_directory_stat = media_directory.stat()
    original_directory_mode = stat.S_IMODE(original_directory_stat.st_mode)
    try:
        vault = SampleVault(args.vault, max_sample_bytes=16 * 1024 * 1024)
        sample = vault.import_path(
            fixture_path,
            media_type="application/vnd.microsoft.portable-executable",
        )
        fixture_path.unlink(missing_ok=True)
        if fixture_root.exists() and not any(fixture_root.iterdir()):
            fixture_root.rmdir()
        compilation_digest = canonical_digest(compilation)

        shutil.chown(media_directory, user="root", group="qemu")
        media_directory.chmod(0o710)
        shutil.chown(image_path, user="root", group="qemu")
        image_path.chmod(0o440)
        config = WindowsKvmProviderConfig(
            state_root=args.state_root,
            base_manifest_path=args.base_manifest,
            admitted_sample_digest=sample.sha256,
            fixture_attestation_digest=compilation_digest,
            admitted_fixture_id=_READONLY_MEDIA_FIXTURE_ID,
            read_only_sample_media_path=image_path,
            read_only_sample_media_digest=actual_media_digest,
            read_only_sample_media_serial="ORDIVON_P1",
            fixture_runtime_ms=15 * 60 * 1000,
            memory_mib=args.memory_mib,
            vcpu_count=args.vcpus,
        )
        backend = WindowsKvmEvaluationBackend(config)
        guardian = GuardianPolicy(
            policy_id="guardian-policy:windows-kvm-p1-readonly-media",
            revision="1",
            network_mode="deny-all",
            max_runtime_ms=20 * 60 * 1000,
            max_memory_mib=args.memory_mib,
            max_processes=64,
            max_artifact_bytes=32 * 1024 * 1024,
            terminate_on=("network-device", "runtime-limit", "operator-stop"),
        )
        observation = ObservationPlan(
            plan_id="observation-plan:windows-kvm-p1-readonly-media",
            revision="1",
            channels=("sample", "management", "observer", "guardian", "world-truth"),
            capture_memory="never",
            max_event_bytes=512 * 1024,
        )
        identity = backend.execution_identity
        environment = EnvironmentIdentity(
            environment_id="environment:windows-kvm-p1-readonly-media",
            provider_id=backend.provider_id,
            provider_revision="1",
            image_digest=backend.base.environment_image_digest,
            configuration_digest=canonical_digest(identity),
            guardian_policy_digest=guardian.digest,
            observation_plan_digest=observation.digest,
        )
        media_binding: JsonObject = {
            "manifestDigest": canonical_digest(media_manifest),
            "digest": actual_media_digest,
            "byteLength": actual_media_length,
            "serial": "ORDIVON_P1",
            "readOnly": True,
            "removable": True,
            "archiveDigest": archive_digest,
            "archiveByteLength": archive_byte_length,
            "archiveName": archive_name,
            "sampleExecutionAuthorized": False,
        }
        authority = AuthorityManifest(
            authority_id="authority:windows-kvm-p1-readonly-media-verifier",
            revision="1",
            sample_digest=sample.sha256,
            operator_id="operator:local",
            authorization_basis=(
                "Execute only an Ordivon-maintained verifier in one disposable Windows Guest. "
                "The attached third-party archive is read-only input and may not be executed."
            ),
            permitted_environment_ids=(environment.environment_id,),
            permitted_actions=("execute-benign-fixture",),
            prohibited_actions=(
                "network-access",
                "execute-third-party-sample",
                "install-third-party-sample",
                "modify-read-only-sample-media",
            ),
            max_runtime_ms=guardian.max_runtime_ms,
            allow_network=False,
            metadata={
                "fixtureCompilation": compilation,
                "readOnlySampleMedia": media_binding,
            },
        )
        spec = EvaluationSpec(
            evaluation_id="evaluation:windows-kvm-p1-readonly-media",
            revision="1",
            sample=sample,
            authority=authority,
            environment=environment,
            guardian_policy=guardian,
            observation_plan=observation,
            requested_actions=("execute-benign-fixture",),
            metadata={
                "fixtureId": _READONLY_MEDIA_FIXTURE_ID,
                "fixtureCompilation": compilation,
                "fixtureCompilationDigest": compilation_digest,
                "readOnlySampleMedia": media_binding,
                "thirdPartySampleExecution": False,
            },
        )
        result = EvaluationRunner(backend, vault, evidence_root=args.evidence).run(
            spec,
            run_index=args.run_index,
        )
        payload = result.to_dict()
        payload["fixtureCompilation"] = compilation
        payload["readOnlySampleMedia"] = media_binding
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        if (
            result.terminal_reason != "readonly-sample-media-verification-completed"
            or result.disposition.value != "no-issue-observed"
            or not result.residual_closed
        ):
            raise SystemExit(2)
    finally:
        fixture_path.unlink(missing_ok=True)
        if fixture_root.exists() and not any(fixture_root.iterdir()):
            fixture_root.rmdir()
        try:
            os.chown(image_path, original_stat.st_uid, original_stat.st_gid)
            image_path.chmod(original_mode)
            os.chown(
                media_directory,
                original_directory_stat.st_uid,
                original_directory_stat.st_gid,
            )
            media_directory.chmod(original_directory_mode)
        except OSError:
            pass


if __name__ == "__main__":
    main()
