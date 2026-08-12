from __future__ import annotations

import argparse
import hashlib
import json
import signal
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from types import FrameType

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
    WindowsKvmEvaluationBackend,
    WindowsKvmProviderConfig,
)

_FIXTURE_ID = "ordivon-p1-generic-controller-selftest-v1"


class _RuntimeCancellation(RuntimeError):
    """Translate Runtime termination into controlled Evaluation cleanup."""


@contextmanager
def _translate_runtime_cancellation() -> Iterator[None]:
    previous_handlers = {
        signal_number: signal.getsignal(signal_number)
        for signal_number in (signal.SIGTERM, signal.SIGINT)
    }

    def request_cancellation(signal_number: int, _frame: FrameType | None) -> None:
        raise _RuntimeCancellation(f"Runtime cancellation requested by signal {signal_number}")

    for signal_number in previous_handlers:
        signal.signal(signal_number, request_cancellation)
    try:
        yield
    finally:
        for signal_number, previous_handler in previous_handlers.items():
            signal.signal(signal_number, previous_handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compile and execute the generic P1 Controller self-test in one disposable "
            "deny-all Windows KVM Evaluation Run. No third-party Sample is used."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--run-index", type=int, default=0)
    parser.add_argument("--memory-mib", type=int, default=5120)
    parser.add_argument("--vcpus", type=int, default=4)
    return parser


def _remove_compiled_fixture(fixture_path: Path, fixture_root: Path) -> None:
    fixture_path.unlink(missing_ok=True)
    if fixture_root.exists() and not any(fixture_root.iterdir()):
        fixture_root.rmdir()


def _compile_generic_controller(output_path: Path) -> JsonObject:
    source_resource = files("ordivon_security").joinpath(
        "resources", "windows_kvm", "p1_controller.c"
    )
    source_path = Path(str(source_resource))
    compiler = Path("/usr/bin/x86_64-w64-mingw32-gcc").resolve()
    objdump = Path("/usr/bin/x86_64-w64-mingw32-objdump").resolve()
    for path in (source_path, compiler, objdump):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"P1 generic Controller dependency is missing or unsafe: {path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    if output_path.exists():
        raise FileExistsError(f"P1 generic Controller output already exists: {output_path}")
    command = [
        str(compiler),
        "-municode",
        "-Os",
        "-s",
        "-static",
        "-Wl,--dynamicbase",
        "-Wl,--nxcompat",
        "-o",
        str(output_path),
        str(source_path),
        "-lbcrypt",
    ]
    subprocess.run(command, check=True, timeout=120)
    output_path.chmod(0o600)
    imports = subprocess.run(
        [str(objdump), "-p", str(output_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    ).stdout
    prohibited = (
        "ws2_32",
        "wininet",
        "winhttp",
        "urlmon",
        "dnsapi",
        "iphlpapi",
        "internetopen",
    )
    lowered = imports.lower()
    matches = [value for value in prohibited if value in lowered]
    if matches:
        output_path.unlink(missing_ok=True)
        raise ValueError(f"P1 generic Controller imports prohibited network APIs: {matches}")
    source_digest = "sha256:" + hashlib.sha256(source_path.read_bytes()).hexdigest()
    fixture_digest = "sha256:" + hashlib.sha256(output_path.read_bytes()).hexdigest()
    compiler_digest = "sha256:" + hashlib.sha256(compiler.read_bytes()).hexdigest()
    compiler_version = subprocess.run(
        [str(compiler), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    ).stdout.splitlines()[0]
    return {
        "fixtureId": _FIXTURE_ID,
        "sourceDigest": source_digest,
        "fixtureDigest": fixture_digest,
        "fixtureByteLength": output_path.stat().st_size,
        "compilerPath": str(compiler),
        "compilerDigest": compiler_digest,
        "compilerVersion": compiler_version,
        "networkImportMatches": [],
        "productionInterface": {
            "target": "sealed-p1-orchestrator-only",
            "binds": ["runId", "manifestPath", "manifestDigest", "timeoutMs", "resultPath"],
            "arbitraryExecutableTarget": False,
        },
        "selfTestClaims": [
            "manifest-sha256-verification",
            "job-object-child-ownership",
            "bounded-timeout-termination",
        ],
    }


def main() -> None:
    args = build_parser().parse_args()
    fixture_root = args.state_root / "fixtures"
    fixture_path = fixture_root / f"{_FIXTURE_ID}-run-{args.run_index}.exe"
    compilation = _compile_generic_controller(fixture_path)
    try:
        vault = SampleVault(args.vault, max_sample_bytes=16 * 1024 * 1024)
        sample = vault.import_path(
            fixture_path,
            media_type="application/vnd.microsoft.portable-executable",
        )
        _remove_compiled_fixture(fixture_path, fixture_root)
        compilation_digest = canonical_digest(compilation)
        config = WindowsKvmProviderConfig(
            state_root=args.state_root,
            base_manifest_path=args.base_manifest,
            admitted_sample_digest=sample.sha256,
            fixture_attestation_digest=compilation_digest,
            admitted_fixture_id=_FIXTURE_ID,
            fixture_runtime_ms=90 * 1000,
            memory_mib=args.memory_mib,
            vcpu_count=args.vcpus,
        )
        backend = WindowsKvmEvaluationBackend(config)
        guardian = GuardianPolicy(
            policy_id="guardian-policy:windows-kvm-p1-generic-controller-selftest",
            revision="1",
            network_mode="deny-all",
            max_runtime_ms=6 * 60 * 1000,
            max_memory_mib=args.memory_mib,
            max_processes=16,
            max_artifact_bytes=32 * 1024 * 1024,
            terminate_on=("network-device", "runtime-limit", "operator-stop"),
        )
        observation = ObservationPlan(
            plan_id="observation-plan:windows-kvm-p1-generic-controller-selftest",
            revision="1",
            channels=("sample", "management", "observer", "guardian", "world-truth"),
            capture_memory="never",
            max_event_bytes=512 * 1024,
        )
        identity = backend.execution_identity
        environment = EnvironmentIdentity(
            environment_id="environment:windows-kvm-p1-generic-controller-selftest",
            provider_id=backend.provider_id,
            provider_revision="1",
            image_digest=backend.base.environment_image_digest,
            configuration_digest=canonical_digest(identity),
            guardian_policy_digest=guardian.digest,
            observation_plan_digest=observation.digest,
        )
        authority = AuthorityManifest(
            authority_id="authority:ordivon-p1-generic-controller-selftest",
            revision="1",
            sample_digest=sample.sha256,
            operator_id="operator:local",
            authorization_basis=(
                "Ordivon-maintained generic Controller self-test compiled locally to verify "
                "exact manifest hashing, Job Object child ownership, and bounded timeout "
                "termination inside a disposable no-network Windows KVM Guest."
            ),
            permitted_environment_ids=(environment.environment_id,),
            permitted_actions=("execute-benign-fixture",),
            prohibited_actions=("network-access", "execute-third-party-sample"),
            max_runtime_ms=guardian.max_runtime_ms,
            allow_network=False,
            metadata={"fixtureCompilation": compilation},
        )
        spec = EvaluationSpec(
            evaluation_id="evaluation:windows-kvm-p1-generic-controller-selftest",
            revision="1",
            sample=sample,
            authority=authority,
            environment=environment,
            guardian_policy=guardian,
            observation_plan=observation,
            requested_actions=("execute-benign-fixture",),
            metadata={
                "fixtureId": _FIXTURE_ID,
                "fixtureCompilation": compilation,
                "fixtureCompilationDigest": compilation_digest,
                "unknownSampleExecution": False,
                "thirdPartySampleExecution": False,
            },
        )
        with _translate_runtime_cancellation():
            result = EvaluationRunner(backend, vault, evidence_root=args.evidence).run(
                spec,
                run_index=args.run_index,
            )
        payload = result.to_dict()
        payload["fixtureCompilation"] = compilation
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        if (
            result.terminal_reason != "benign-fixture-completed"
            or result.disposition.value != "no-issue-observed"
            or not result.residual_closed
        ):
            raise SystemExit(2)
    finally:
        _remove_compiled_fixture(fixture_path, fixture_root)


if __name__ == "__main__":
    main()
