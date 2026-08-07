from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from importlib.resources import files
from pathlib import Path

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig
from ordivon_security.range import RangeSession, RangeSessionSpec
from ordivon_security.range.windows_sacrificial import (
    AdversarialWindowsRange,
    SacrificialWindowsRangeConfig,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Ordivon S3 sacrificial Windows canary in an isolated disposable KVM node. "
            "The canary changes only the disposable Guest and requests no network capability."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=5120)
    parser.add_argument("--vcpus", type=int, default=4)
    parser.add_argument("--max-runtime-seconds", type=int, default=8 * 60)
    return parser


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _compile_canary(output_path: Path) -> JsonObject:
    source_resource = files("ordivon_security").joinpath(
        "resources", "windows_kvm", "sacrificial_canary.c"
    )
    source_path = Path(str(source_resource))
    compiler = Path("/usr/bin/x86_64-w64-mingw32-gcc")
    objdump = Path("/usr/bin/x86_64-w64-mingw32-objdump")
    for path in (source_path, compiler, objdump):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"S3 canary dependency is missing or unsafe: {path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    if output_path.exists():
        raise FileExistsError(f"S3 canary output already exists: {output_path}")
    command = [
        str(compiler),
        "-municode",
        "-Os",
        "-s",
        "-static",
        "-Wl,--dynamicbase",
        "-Wl,--nxcompat",
        "-Wl,--no-insert-timestamp",
        "-o",
        str(output_path),
        str(source_path),
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
    prohibited_network_imports = (
        "ws2_32",
        "wininet",
        "winhttp",
        "urlmon",
        "dnsapi",
        "iphlpapi",
        "internetopen",
    )
    lowered = imports.lower()
    matches = [value for value in prohibited_network_imports if value in lowered]
    if matches:
        output_path.unlink(missing_ok=True)
        raise ValueError(f"S3 canary imports prohibited network APIs: {matches}")
    compiler_version = subprocess.run(
        [str(compiler), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    ).stdout.splitlines()[0]
    result: JsonObject = {
        "canaryId": "ordivon-s3-sacrificial-canary-v1",
        "sourceDigest": _digest(source_path),
        "canaryDigest": _digest(output_path),
        "canaryByteLength": output_path.stat().st_size,
        "compilerPath": str(compiler),
        "compilerDigest": _digest(compiler),
        "compilerVersion": compiler_version,
        "networkImportMatches": [],
        "declaredGuestEffects": [
            "spawn-and-terminate-dedicated-test-observer",
            "install-synthetic-onstart-persistence",
            "terminate-guest-bootstrap-parent",
            "delete-synthetic-guest-log",
            "request-guest-reboot",
            "continue-after-reboot",
        ],
    }
    result["compilationDigest"] = canonical_digest(result)
    return result


def _write_receipt(path: Path, value: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _guest_claim_passes(claim: object) -> bool:
    if not isinstance(claim, dict):
        return False
    required_true = (
        "completed",
        "stage1Observed",
        "observerKilled",
        "guestRunnerKilled",
        "persistenceFiredAfterReboot",
        "syntheticGuestLogDeleted",
        "rebootContinuationObserved",
    )
    return (
        all(claim.get(key) is True for key in required_true)
        and claim.get("networkRequested") is False
    )


def main() -> None:
    args = build_parser().parse_args()
    canary_root = args.state_root / "canaries"
    token = f"{time.time_ns():x}"
    canary_path = canary_root / f"ordivon-s3-sacrificial-canary-{token}.exe"
    compilation = _compile_canary(canary_path)
    session: RangeSession | None = None
    final_inspect: JsonObject | None = None
    destroy_receipt: JsonObject | None = None
    failure: BaseException | None = None
    try:
        machine = WindowsKvmMachineConfig(
            state_root=args.state_root,
            base_manifest_path=args.base_manifest,
            qemu_path=Path("/usr/bin/qemu-system-x86_64"),
            qemu_img_path=Path("/usr/bin/qemu-img"),
            swtpm_path=Path("/usr/bin/swtpm"),
            setpriv_path=Path("/usr/bin/setpriv"),
            firmware_code_path=Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
            run_user="qemu",
            run_group="qemu",
            memory_mib=args.memory_mib,
            vcpu_count=args.vcpus,
            qmp_ready_timeout_seconds=60,
            shutdown_grace_seconds=15,
        )
        backend = AdversarialWindowsRange(
            SacrificialWindowsRangeConfig(
                machine=machine,
                canary_path=canary_path,
                canary_digest=str(compilation["canaryDigest"]),
                max_runtime_seconds=args.max_runtime_seconds,
            )
        )
        session_id = f"range-session:s3-{token}"
        session = RangeSession(
            backend,
            RangeSessionSpec(
                session_id=session_id,
                revision="1",
                range_id=backend.range_id,
                actor_ids=(),
                metadata={
                    "purpose": "s3-sacrificial-node-acceptance",
                    "guestAuthority": "untrusted-disposable",
                    "externalNetwork": "denied-no-nic",
                },
            ),
        )
        session.start()
        deadline = time.monotonic() + args.max_runtime_seconds
        while True:
            session.poll_backend()
            inspected = session.inspect()
            backend_state = inspected.get("backendState")
            if isinstance(backend_state, dict) and backend_state.get("running") is False:
                final_inspect = backend_state
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("S3 sacrificial canary did not finish within the outer bound")
            time.sleep(1)
    except BaseException as error:
        failure = error
    finally:
        if session is not None and session.state in {"running", "terminated"}:
            try:
                destroy_receipt = session.destroy(logical_time=4)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
        canary_path.unlink(missing_ok=True)
        if canary_root.exists() and not any(canary_root.iterdir()):
            canary_root.rmdir()

    events = [] if session is None else [event.to_dict() for event in session.events]
    event_types = [event.get("eventType") for event in events]
    guest_claim = None if final_inspect is None else final_inspect.get("guestCanaryClaim")
    external_acceptance = {
        "containmentConfirmed": "machine.containment-confirmed" in event_types,
        "resetObservedByQmp": "machine.reset-observed" in event_types,
        "qemuExited": final_inspect is not None and final_inspect.get("running") is False,
        "networkDeviceAbsent": final_inspect is not None
        and final_inspect.get("networkDevicePresent") is False,
        "residualClosureClean": destroy_receipt is not None
        and destroy_receipt.get("clean") is True,
    }
    guest_claim_acceptance = {
        "present": isinstance(guest_claim, dict),
        "claimPasses": _guest_claim_passes(guest_claim),
        "authority": "guest-claim-not-world-truth",
    }
    passed = all(external_acceptance.values()) and guest_claim_acceptance["claimPasses"]
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.s3-sacrificial-range-acceptance",
        "status": "accepted" if passed and failure is None else "failed",
        "compilation": compilation,
        "externalAcceptance": external_acceptance,
        "guestClaimAcceptance": guest_claim_acceptance,
        "finalBackendState": final_inspect,
        "destroyReceipt": destroy_receipt,
        "events": events,
        "failure": (
            None
            if failure is None
            else {"errorType": type(failure).__name__, "errorMessage": str(failure)}
        ),
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if receipt["status"] != "accepted":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
