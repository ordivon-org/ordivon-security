from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from ordivon_security._canonical import JsonObject
from ordivon_security.cli_windows_kvm_s3_acceptance import (
    _compile_canary,
    _guest_claim_passes,
    _write_receipt,
)
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig
from ordivon_security.range import RangeSession, RangeSessionSpec
from ordivon_security.range.windows_out_of_band import WindowsOfflineNtfsInspector
from ordivon_security.range.windows_sacrificial import (
    AdversarialWindowsRange,
    SacrificialWindowsRangeConfig,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run S4 out-of-band truth acceptance over the maintained sacrificial Windows node. "
            "The Guest challenge remains isolated; the new acceptance reads the stopped system "
            "overlay through a host read-only NTFS path."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=5120)
    parser.add_argument("--vcpus", type=int, default=4)
    parser.add_argument("--max-runtime-seconds", type=int, default=8 * 60)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    canary_root = args.state_root / "canaries"
    token = f"{time.time_ns():x}"
    canary_path = canary_root / f"ordivon-s4-sacrificial-canary-{token}.exe"
    compilation = _compile_canary(canary_path)
    session: RangeSession | None = None
    final_inspect: JsonObject | None = None
    disk_truth: JsonObject | None = None
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
        inspector = WindowsOfflineNtfsInspector()
        session_id = f"range-session:s4-{token}"
        session = RangeSession(
            backend,
            RangeSessionSpec(
                session_id=session_id,
                revision="1",
                range_id=backend.range_id,
                actor_ids=(),
                metadata={
                    "purpose": "s4-out-of-band-truth-acceptance",
                    "guestAuthority": "untrusted-disposable",
                    "externalNetwork": "denied-no-nic",
                    "truthAuthority": "host-offline-read-only-ntfs",
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
                raise TimeoutError("S4 sacrificial canary did not finish within the outer bound")
            time.sleep(1)
        disk_truth = backend.capture_offline_disk_truth(session.instance, inspector)
        session.poll_backend()
        inspected = session.inspect()
        backend_state = inspected.get("backendState")
        if isinstance(backend_state, dict):
            final_inspect = backend_state
    except BaseException as error:
        failure = error
    finally:
        if session is not None and session.state in {"running", "terminated"}:
            try:
                destroy_receipt = session.destroy(logical_time=5)
            except BaseException as cleanup_error:
                if failure is None:
                    failure = cleanup_error
        canary_path.unlink(missing_ok=True)
        if canary_root.exists() and not any(canary_root.iterdir()):
            canary_root.rmdir()

    events = [] if session is None else [event.to_dict() for event in session.events]
    event_types = [event.get("eventType") for event in events]
    guest_claim = None if final_inspect is None else final_inspect.get("guestCanaryClaim")
    facts = None if disk_truth is None else disk_truth.get("facts")
    external_acceptance = {
        "containmentConfirmed": "machine.containment-confirmed" in event_types,
        "resetObservedByQmp": "machine.reset-observed" in event_types,
        "qemuExited": final_inspect is not None and final_inspect.get("running") is False,
        "networkDeviceAbsent": final_inspect is not None
        and final_inspect.get("networkDevicePresent") is False,
        "worldTruthEventRecorded": "world.disk-state-observed" in event_types,
        "residualClosureClean": destroy_receipt is not None
        and destroy_receipt.get("clean") is True,
    }
    disk_truth_acceptance = {
        "authority": None if disk_truth is None else disk_truth.get("authority"),
        "allFactsPass": isinstance(facts, dict) and all(value is True for value in facts.values()),
        "facts": facts,
    }
    guest_claim_acceptance = {
        "present": isinstance(guest_claim, dict),
        "claimPasses": _guest_claim_passes(guest_claim),
        "authority": "guest-claim-not-world-truth",
        "role": "challenge-completeness-only",
    }
    passed = (
        all(external_acceptance.values())
        and disk_truth_acceptance["allFactsPass"] is True
        and guest_claim_acceptance["claimPasses"] is True
    )
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.s4-out-of-band-truth-acceptance",
        "status": "accepted" if passed and failure is None else "failed",
        "compilation": compilation,
        "externalAcceptance": external_acceptance,
        "diskTruthAcceptance": disk_truth_acceptance,
        "guestClaimAcceptance": guest_claim_acceptance,
        "diskTruth": disk_truth,
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
