from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from ordivon_security._canonical import JsonObject
from ordivon_security.cli_windows_kvm_s3_acceptance import _write_receipt
from ordivon_security.cli_windows_kvm_s6_acceptance import (
    _compile_canary,
    _guest_claim_passes,
    _topology_phases,
)
from ordivon_security.providers.windows_kvm import WindowsKvmMachineConfig
from ordivon_security.range import (
    RangeAuthority,
    RangeEffectAdmission,
    RangeEffectRequest,
    RangeSession,
    RangeSessionSpec,
)
from ordivon_security.range.windows_fabric import WindowsFabricRangeConfig
from ordivon_security.range.windows_topology_churn import WindowsTopologyChurnRange

_ACTOR_ID = "actor:c1-fabric-controller"
_AUTHORITY_ID = "range-authority:c1-fabric-controller"
_ZONE_REF = "zone:s6-fabric"
_CAPABILITY = "fabric.peer-replacement"
_EFFECT_TYPE = "fabric.replace-peer-a-with-peer-b"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run C1 physical acceptance: Security admits one Actor-requested S6 peer "
            "replacement from exact zone/capability authority before the existing backend "
            "effect changes the isolated fabric."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--vcpus", type=int, default=2)
    parser.add_argument("--max-runtime-seconds", type=int, default=6 * 60)
    return parser


def _request(
    token: str,
    suffix: str,
    *,
    authority_id: str = _AUTHORITY_ID,
    zone_ref: str = _ZONE_REF,
    capability: str = _CAPABILITY,
) -> RangeEffectRequest:
    return RangeEffectRequest(
        request_id=f"range-effect-request:c1-{token}-{suffix}",
        actor_id=_ACTOR_ID,
        authority_id=authority_id,
        zone_ref=zone_ref,
        capability=capability,
        effect_type=_EFFECT_TYPE,
        payload={
            "peerAAddress": "10.253.70.3",
            "peerBAddress": "10.253.70.4",
            "reason": "c1-executable-authority-acceptance",
        },
    )


def _negative_admissions(session: RangeSession, token: str) -> tuple[RangeEffectAdmission, ...]:
    requests = (
        _request(token, "fake-authority", authority_id="range-authority:c1-fake"),
        _request(token, "wrong-zone", zone_ref="zone:other"),
        _request(token, "wrong-capability", capability="fabric.observe"),
    )
    return tuple(session.admit_effect(request, logical_time=1) for request in requests)


def _backend_state(session: RangeSession) -> JsonObject:
    inspected = session.inspect()
    value = inspected.get("backendState")
    if not isinstance(value, dict):
        raise RuntimeError("C1 Range backend state is unavailable")
    return value


def _world_still_peer_a(value: JsonObject) -> bool:
    truth = value.get("fabricTruth")
    return (
        value.get("topologyChurnCompleted") is False
        and value.get("actorReplacementRequest") is None
        and isinstance(truth, dict)
        and truth.get("phase") == "peer-a-present"
        and truth.get("currentPeerAddress") == "10.253.70.3"
    )


def main() -> None:
    args = build_parser().parse_args()
    token = f"{time.time_ns():x}"
    canary_root = args.state_root / "canaries"
    canary_path = canary_root / f"ordivon-c1-topology-authority-{token}.exe"
    compilation = _compile_canary(canary_path)
    session: RangeSession | None = None
    final_state: JsonObject | None = None
    pre_authority_state: JsonObject | None = None
    destroy_receipt: JsonObject | None = None
    negative_admissions: tuple[RangeEffectAdmission, ...] = ()
    valid_admission: RangeEffectAdmission | None = None
    replay_admission: RangeEffectAdmission | None = None
    first_backend_receipt: JsonObject | None = None
    replay_backend_receipt: JsonObject | None = None
    admission_replay_no_extra_events = False
    backend_replay_no_extra_events = False
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
        backend = WindowsTopologyChurnRange(
            WindowsFabricRangeConfig(
                machine=machine,
                canary_path=canary_path,
                canary_digest=str(compilation["canaryDigest"]),
                max_runtime_seconds=args.max_runtime_seconds,
            ),
            replacement_trigger="actor-authorized",
        )
        authority = RangeAuthority(
            authority_id=_AUTHORITY_ID,
            revision="1",
            actor_id=_ACTOR_ID,
            zone_refs=(_ZONE_REF,),
            capabilities=(_CAPABILITY,),
            external_boundary="denied",
            metadata={"purpose": "c1-first-executable-range-authority"},
        )
        session = RangeSession(
            backend,
            RangeSessionSpec(
                session_id=f"range-session:c1-{token}",
                revision="1",
                range_id=backend.range_id,
                actor_ids=(_ACTOR_ID,),
                authorities=(authority,),
                metadata={
                    "purpose": "c1-executable-authority-acceptance",
                    "replacementTrigger": "actor-authorized",
                    "externalNetwork": "structurally-unrouted",
                },
            ),
        )
        session.start()
        session.update_actor_presence(_ACTOR_ID, "active", logical_time=1)
        negative_admissions = _negative_admissions(session, token)

        deadline = time.monotonic() + args.max_runtime_seconds
        while True:
            state = _backend_state(session)
            session.poll_backend()
            if state.get("peerAExitCode") == 0:
                pre_authority_state = state
                break
            if state.get("running") is False:
                raise RuntimeError("C1 Guest stopped before peer-A physical precondition")
            if time.monotonic() >= deadline:
                raise TimeoutError("C1 peer-A physical precondition exceeded the outer bound")
            time.sleep(0.25)

        time.sleep(0.5)
        no_authority_state = _backend_state(session)
        session.poll_backend()
        if not _world_still_peer_a(no_authority_state):
            raise RuntimeError("C1 world changed before an admitted Actor effect request")
        pre_authority_state = no_authority_state

        valid_request = _request(token, "valid")
        valid_admission = session.admit_effect(valid_request, logical_time=2)
        event_count = len(session.events)
        replay_admission = session.admit_effect(valid_request, logical_time=99)
        admission_replay_no_extra_events = len(session.events) == event_count
        if not valid_admission.admitted:
            raise RuntimeError(f"C1 valid authority was rejected: {valid_admission.reason}")

        first_backend_receipt = backend.request_peer_replacement(
            session.instance,
            valid_admission,
        )
        session.poll_backend()
        second_poll_before = len(session.events)
        replay_backend_receipt = backend.request_peer_replacement(
            session.instance,
            valid_admission,
        )
        session.poll_backend()
        backend_replay_no_extra_events = len(session.events) == second_poll_before

        while True:
            state = _backend_state(session)
            session.poll_backend()
            if state.get("running") is False:
                final_state = state
                break
            if time.monotonic() >= deadline:
                failure = TimeoutError(
                    "C1 actor-authorized topology effect exceeded the outer bound"
                )
                session.terminate("outer-timeout", logical_time=4)
                session.poll_backend()
                final_state = _backend_state(session)
                break
            time.sleep(1)
        session.poll_backend()
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
    phases = _topology_phases(events)
    guest_claim = None if final_state is None else final_state.get("guestClaim")
    sensor = None if final_state is None else final_state.get("sensorObservation")
    history = None if final_state is None else final_state.get("topologyHistory")
    fabric_truth = None if final_state is None else final_state.get("fabricTruth")
    history_phases = (
        [item.get("phase") for item in history if isinstance(item, dict)]
        if isinstance(history, list)
        else []
    )
    completed_events = [
        event for event in events if event.get("eventType") == "fabric.peer-replacement-completed"
    ]
    expected_effect_id = (
        None if first_backend_receipt is None else first_backend_receipt.get("effectId")
    )
    effect_identity_propagated = bool(completed_events) and all(
        isinstance(event.get("payload"), dict)
        and event["payload"].get("effectId") == expected_effect_id
        for event in completed_events
    )

    external_acceptance = {
        "negativeAuthorityCasesRejected": len(negative_admissions) == 3
        and all(not item.admitted for item in negative_admissions)
        and [item.reason for item in negative_admissions]
        == ["unknown-authority", "zone-not-granted", "capability-not-granted"],
        "physicalPreconditionReachedBeforeAuthority": pre_authority_state is not None
        and pre_authority_state.get("peerAExitCode") == 0,
        "worldUnchangedBeforeValidAuthority": pre_authority_state is not None
        and _world_still_peer_a(pre_authority_state),
        "validAuthorityAdmitted": valid_admission is not None and valid_admission.admitted,
        "admissionExactReplayConverged": valid_admission is not None
        and replay_admission == valid_admission
        and admission_replay_no_extra_events,
        "backendRequestExactReplayConverged": first_backend_receipt is not None
        and replay_backend_receipt == first_backend_receipt
        and backend_replay_no_extra_events,
        "effectReceiptDoesNotClaimWorldTruth": first_backend_receipt is not None
        and first_backend_receipt.get("worldEffectVerified") is False,
        "actorRequestBound": "fabric.peer-replacement-request-bound" in event_types,
        "replacementStarted": "fabric.peer-replacement-started" in event_types,
        "replacementCompleted": "fabric.peer-replacement-completed" in event_types,
        "effectIdentityPropagated": effect_identity_propagated,
        "peerARemovalObserved": "peer-a-removed" in phases,
        "peerBAdditionObserved": "peer-b-present" in phases,
        "topologyHistoryRetained": history_phases
        == ["peer-a-present", "peer-a-removed", "peer-b-present"],
        "currentTopologyIsPeerB": isinstance(fabric_truth, dict)
        and fabric_truth.get("phase") == "peer-b-present"
        and fabric_truth.get("currentPeerAddress") == "10.253.70.4",
        "bothChallengeFlowsObserved": isinstance(sensor, dict)
        and sensor.get("peerATrafficObserved") is True
        and sensor.get("peerBTrafficObserved") is True,
        "guestObservedBothPeers": _guest_claim_passes(guest_claim),
        "singleNetworkDevicePresent": final_state is not None
        and final_state.get("networkDevicePresent") is True,
        "residualClosureClean": destroy_receipt is not None
        and destroy_receipt.get("clean") is True,
    }
    passed = all(external_acceptance.values()) and failure is None
    receipt: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.c1-executable-authority-acceptance",
        "status": "accepted" if passed else "failed",
        "compilation": compilation,
        "authority": None if session is None else session.spec.authorities[0].to_dict(),
        "negativeAdmissions": [item.to_dict() for item in negative_admissions],
        "validAdmission": None if valid_admission is None else valid_admission.to_dict(),
        "firstBackendReceipt": first_backend_receipt,
        "replayBackendReceipt": replay_backend_receipt,
        "preAuthorityBackendState": pre_authority_state,
        "externalAcceptance": external_acceptance,
        "finalBackendState": final_state,
        "destroyReceipt": destroy_receipt,
        "events": events,
        "failure": None
        if failure is None
        else {"errorType": type(failure).__name__, "errorMessage": str(failure)},
    }
    _write_receipt(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
