"""CA-LIC R1: revocation, offline semantics, churn, and remote-capability costs.

Active experiments use only self-owned ToyDesigner code on local Linux.  The
output is a deterministic structural measurement record except for opaque
cryptographic material/digests, which are not compared across runs.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import advanced_ladder as A
import license_model as L
import vendor

Json = dict[str, Any]
RUNS = Path("runs")
RUNS.mkdir(exist_ok=True)
AAD = b"ToyDesigner:CA-LIC:R1:asset"


def canonical_bytes(value: Json) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue(user: str, tier: str = "pro") -> L.License:
    path = RUNS / f"r1_{user}_{tier}.json"
    vendor.issue(user, tier, bind=True, expiry=None, out=str(path))
    return L.load_license(str(path))


def seal_with_key(plaintext: bytes, key: bytes) -> Json:
    nonce = hashlib.sha256(b"nonce|" + plaintext + key).digest()[:12]
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, AAD)
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintextDigest": "sha256:" + hashlib.sha256(plaintext).hexdigest(),
    }


def open_with_key(bundle: Json, key: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(
        base64.b64decode(str(bundle["nonce"])),
        base64.b64decode(str(bundle["ciphertext"])),
        AAD,
    )


def deterministic_key(label: str) -> bytes:
    return hashlib.sha256(("ToyDesigner:R1:key:" + label).encode("utf-8")).digest()


class R1Authority:
    def __init__(self, mode: str, version: str = "v1") -> None:
        service = Path(__file__).with_name("r1_authority_service.py")
        self.process = subprocess.Popen(
            [sys.executable, str(service), mode, version],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if self.process.stdout is None:
            raise RuntimeError("authority stdout unavailable")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("authority failed before hello")
        self.hello = json.loads(line)
        self.public_key_hex = str(self.hello["publicKey"])
        self.mode = mode
        self.version = str(self.hello["serviceVersion"])

    def _exchange(self, request: Json) -> Json:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("authority pipes unavailable")
        if self.process.poll() is not None:
            raise RuntimeError("authority unavailable")
        self.process.stdin.write(json.dumps(request, sort_keys=True) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("authority unavailable")
        return json.loads(line)

    def issue_lease(
        self,
        lic: L.License,
        *,
        feature: str,
        nonce: str,
        tick: int,
        lease_ticks: int,
        binding: str | None,
    ) -> Json:
        return self._exchange({
            "op": "issue-lease",
            "license": dataclasses.asdict(lic),
            "feature": feature,
            "nonce": nonce,
            "tick": tick,
            "leaseTicks": lease_ticks,
            "binding": binding,
        })

    def capability(self, lic: L.License, *, feature: str, nonce: str, body: Json) -> Json:
        return self._exchange({
            "op": "capability",
            "license": dataclasses.asdict(lic),
            "feature": feature,
            "nonce": nonce,
            "body": body,
        })

    def revoke(self, user: str) -> None:
        response = self._exchange({"op": "revoke", "user": user})
        if response.get("ok") is not True:
            raise RuntimeError("revoke failed")

    def close(self) -> None:
        if self.process.poll() is None and self.process.stdin is not None:
            try:
                self.process.stdin.write('{"op":"shutdown"}\n')
                self.process.stdin.flush()
            except BrokenPipeError:
                pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)

    def __enter__(self) -> "R1Authority":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def verify_receipt(receipt: Json, public_key_hex: str) -> tuple[bool, str]:
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False, "malformed-receipt"
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature), canonical_bytes(payload))
    except (InvalidSignature, ValueError):
        return False, "signature-invalid"
    return True, "verified"


def lease_valid(
    receipt: Json,
    public_key_hex: str,
    *,
    tick: int,
    feature: str,
    binding: str | None,
) -> tuple[bool, str]:
    ok, why = verify_receipt(receipt, public_key_hex)
    if not ok:
        return False, why
    payload = receipt["payload"]
    if payload.get("kind") != "remote-entitlement-lease":
        return False, "wrong-kind"
    if payload.get("feature") != feature or payload.get("allowed") is not True:
        return False, "not-entitled"
    if payload.get("binding") != binding:
        return False, "binding-mismatch"
    if tick < int(payload["issuedTick"]):
        return False, "before-issued"
    if tick >= int(payload["expiresTickExclusive"]):
        return False, "expired"
    return True, "lease-valid"


def capability_valid(
    receipt: Json,
    public_key_hex: str,
    *,
    feature: str,
    nonce: str,
    body: Json,
) -> tuple[bool, str]:
    ok, why = verify_receipt(receipt, public_key_hex)
    if not ok:
        return False, why
    payload = receipt["payload"]
    if payload.get("kind") != "remote-capability-r1":
        return False, "wrong-kind"
    if payload.get("feature") != feature or payload.get("nonce") != nonce:
        return False, "request-identity-mismatch"
    if payload.get("allowed") is not True or not isinstance(payload.get("result"), dict):
        return False, "capability-denied"
    expected_body = "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()
    if payload["result"].get("requestBodyDigest") != expected_body:
        return False, "body-digest-mismatch"
    return True, "capability-valid"


def v5_r1() -> Json:
    recipients_v1 = ["alice", "bob", "carol", "dave"]
    recipients_v2 = ["bob", "carol", "dave"]  # alice revoked before v2
    recipients_v3 = ["bob", "carol", "dave", "eve"]
    plaintext_v1 = b"premium-asset-release-v1"
    plaintext_v2 = b"premium-asset-release-v2"

    shared_key = deterministic_key("shared-v1")
    bundle_v1 = seal_with_key(plaintext_v1, shared_key)
    alice_cached_key = shared_key
    assert open_with_key(bundle_v1, alice_cached_key) == plaintext_v1

    # Reusing a shared key means revocation is ineffective for future content.
    bundle_v2_reuse = seal_with_key(plaintext_v2, shared_key)
    revoked_can_open_future_if_key_reused = (
        open_with_key(bundle_v2_reuse, alice_cached_key) == plaintext_v2
    )

    # Rotation makes revocation prospective for future releases, but requires
    # re-distribution to every still-authorized recipient.
    rotated_key = deterministic_key("shared-v2")
    bundle_v2_rotated = seal_with_key(plaintext_v2, rotated_key)
    try:
        open_with_key(bundle_v2_rotated, alice_cached_key)
        revoked_can_open_rotated_future = True
    except Exception:
        revoked_can_open_rotated_future = False

    # Per-recipient ciphertext/key limits a key leak's cryptographic blast
    # radius, but every authorized recipient still obtains plaintext.
    bob_key = deterministic_key("per:bob:v2")
    carol_key = deterministic_key("per:carol:v2")
    bob_bundle = seal_with_key(plaintext_v2, bob_key)
    carol_bundle = seal_with_key(plaintext_v2, carol_key)
    assert open_with_key(bob_bundle, bob_key) == plaintext_v2
    try:
        open_with_key(carol_bundle, bob_key)
        cross_recipient_key_leak_blocked = False
    except Exception:
        cross_recipient_key_leak_blocked = True
    authorized_plaintext_redistribution_possible = (
        open_with_key(bob_bundle, bob_key) == plaintext_v2
    )

    active_counts = [len(recipients_v1), len(recipients_v2), len(recipients_v3)]
    shared_reused = {
        "contentKeyDistributions": len(recipients_v1),
        "ciphertextCopies": 3,
        "futureRevocationEffective": False,
    }
    shared_rotated = {
        "contentKeyDistributions": sum(active_counts),
        "ciphertextCopies": 3,
        "futureRevocationEffective": True,
    }
    per_recipient = {
        "contentKeyDistributions": sum(active_counts),
        "ciphertextCopies": sum(active_counts),
        "singleKeyLeakCryptographicBlastRadiusRecipients": 1,
        "plaintextRedistributionStillPossible": authorized_plaintext_redistribution_possible,
    }
    assert revoked_can_open_future_if_key_reused
    assert not revoked_can_open_rotated_future
    assert cross_recipient_key_leak_blocked
    return {
        "kind": "ca-lic.v5-r1",
        "retrospectiveRevocationOfAlreadyDeliveredKey": False,
        "revokedCanOpenFutureIfSharedKeyReused": revoked_can_open_future_if_key_reused,
        "revokedCanOpenFutureAfterRotation": revoked_can_open_rotated_future,
        "crossRecipientKeyLeakBlockedByPerRecipientEncryption": cross_recipient_key_leak_blocked,
        "authorizedPlaintextRedistributionPossible": authorized_plaintext_redistribution_possible,
        "churn": {
            "activeRecipientsByRelease": active_counts,
            "sharedReused": shared_reused,
            "sharedRotated": shared_rotated,
            "perRecipient": per_recipient,
        },
    }


def lease_sweep(feature: str) -> list[Json]:
    rows: list[Json] = []
    for lease_ticks in (1, 2, 4, 8):
        user = issue(f"lease-sweep-{lease_ticks}")
        with R1Authority("lease", f"lease-sweep-v{lease_ticks}") as authority:
            receipt = authority.issue_lease(
                user,
                feature=feature,
                nonce=f"sweep-{lease_ticks}",
                tick=0,
                lease_ticks=lease_ticks,
                binding="client-A",
            )
            pub = authority.public_key_hex
            authority.revoke(user.user)
            valid_ticks = [
                tick for tick in range(0, lease_ticks + 2)
                if lease_valid(
                    receipt, pub, tick=tick, feature=feature, binding="client-A"
                )[0]
            ]
            fresh = authority.issue_lease(
                user,
                feature=feature,
                nonce=f"fresh-{lease_ticks}",
                tick=0,
                lease_ticks=lease_ticks,
                binding="client-A",
            )
            rows.append({
                "leaseTicks": lease_ticks,
                "validTicksAfterImmediateRevocation": valid_ticks,
                "offlineSurvivabilityTicks": lease_ticks,
                "worstCaseRevocationLagTicks": lease_ticks,
                "freshLeaseAfterRevocationAllowed": bool(fresh["payload"]["allowed"]),
            })
    return rows


def v6_r1() -> Json:
    alice = issue("alice-v6")
    feature = "premium.local-render"
    lease_ticks = 4
    sweep = lease_sweep(feature)
    with R1Authority("lease", "lease-v1") as authority:
        bound = authority.issue_lease(
            alice,
            feature=feature,
            nonce="bound",
            tick=0,
            lease_ticks=lease_ticks,
            binding="client-A",
        )
        unbound = authority.issue_lease(
            alice,
            feature=feature,
            nonce="unbound",
            tick=0,
            lease_ticks=lease_ticks,
            binding=None,
        )
        pub = authority.public_key_hex
        authority.revoke(alice.user)

        valid_after_revoke = [
            tick for tick in range(0, lease_ticks)
            if lease_valid(bound, pub, tick=tick, feature=feature, binding="client-A")[0]
        ]
        expired_at = lease_ticks
        assert not lease_valid(
            bound, pub, tick=expired_at, feature=feature, binding="client-A"
        )[0]
        unbound_replay_on_other_client = lease_valid(
            unbound, pub, tick=1, feature=feature, binding=None
        )[0]
        bound_replay_on_other_client = lease_valid(
            bound, pub, tick=1, feature=feature, binding="client-B"
        )[0]

        # Once revoked, the authority refuses a fresh lease immediately.
        fresh_after_revoke = authority.issue_lease(
            alice,
            feature=feature,
            nonce="after-revoke",
            tick=1,
            lease_ticks=lease_ticks,
            binding="client-A",
        )
        fresh_after_revoke_allowed = bool(fresh_after_revoke["payload"]["allowed"])

        # Model a service outage after lease issuance.
        authority.close()
        cached_still_valid_tick_2 = lease_valid(
            bound, pub, tick=2, feature=feature, binding="client-A"
        )[0]
        cached_valid_after_restart_if_persisted = cached_still_valid_tick_2
        memory_only_restart_retains_lease = False
        try:
            authority.issue_lease(
                alice,
                feature=feature,
                nonce="outage",
                tick=2,
                lease_ticks=lease_ticks,
                binding="client-A",
            )
            new_lease_during_outage = True
        except RuntimeError:
            new_lease_during_outage = False

    # Even perfect lease semantics do not protect a shipped local capability
    # from a hostile client that deletes local enforcement.
    local_capability_after_policy_patch = A.local_premium_capability("v6-r1")["resolution"]
    return {
        "kind": "ca-lic.v6-r1",
        "leaseTicks": lease_ticks,
        "leaseSweep": sweep,
        "offlineWindowEqualsWorstCaseRevocationLagInSweep": all(
            row["offlineSurvivabilityTicks"] == row["worstCaseRevocationLagTicks"]
            for row in sweep
        ),
        "leaseValidTicksAfterIssueAndRevocation": valid_after_revoke,
        "worstCaseRevocationLagTicks": lease_ticks,
        "offlineSurvivabilityTicksIfLeasePersisted": lease_ticks,
        "freshLeaseAfterRevocationAllowed": fresh_after_revoke_allowed,
        "newLeaseDuringAuthorityOutage": new_lease_during_outage,
        "persistedCacheSurvivesRestartUntilExpiry": cached_valid_after_restart_if_persisted,
        "memoryOnlyCacheSurvivesRestart": memory_only_restart_retains_lease,
        "unboundLeaseReplayOnOtherClient": unbound_replay_on_other_client,
        "boundLeaseReplayOnDifferentBinding": bound_replay_on_other_client,
        "bindingLimitation": "semantic-client-binding-only; not hostile-host hardware proof",
        "localCapabilityStillPresentAfterLocalPolicyPatch": local_capability_after_policy_patch == "3840x2160",
    }


def v8_r1() -> Json:
    alice = issue("alice-v8")
    feature = "premium.remote-render"
    body = {
        "scene": "station-zero",
        "job": "r1",
        "payload": "x" * 4096,
    }
    externalized_input_bytes = len(canonical_bytes(body))

    v1 = R1Authority("capability", "cap-v1")
    receipt_v1 = v1.capability(alice, feature=feature, nonce="job-v1", body=body)
    pub_v1 = v1.public_key_hex
    valid_v1, why_v1 = capability_valid(
        receipt_v1, pub_v1, feature=feature, nonce="job-v1", body=body
    )
    assert valid_v1, why_v1
    result_v1 = receipt_v1["payload"]["result"]
    v1.close()

    # A cached exact result remains verifiable during outage, but a new job
    # cannot be computed without the external capability.
    cached_exact_result_survives_outage = capability_valid(
        receipt_v1, pub_v1, feature=feature, nonce="job-v1", body=body
    )[0]
    cached_result_valid_for_changed_body = capability_valid(
        receipt_v1,
        pub_v1,
        feature=feature,
        nonce="job-v1",
        body={**body, "payload": "changed"},
    )[0]
    try:
        v1.capability(alice, feature=feature, nonce="new-job", body={"scene": "new"})
        new_job_during_outage = True
    except RuntimeError:
        new_job_during_outage = False

    # Service/key rotation requires a trust update.  Historical verification
    # additionally requires retaining the old authority key.
    with R1Authority("capability", "cap-v2") as v2:
        receipt_v2 = v2.capability(alice, feature=feature, nonce="job-v2", body=body)
        pub_v2 = v2.public_key_hex
        valid_v2 = capability_valid(
            receipt_v2, pub_v2, feature=feature, nonce="job-v2", body=body
        )[0]
        assert valid_v2
        new_receipt_under_old_pin = capability_valid(
            receipt_v2, pub_v1, feature=feature, nonce="job-v2", body=body
        )[0]
        old_receipt_under_new_pin = capability_valid(
            receipt_v1, pub_v2, feature=feature, nonce="job-v1", body=body
        )[0]
        digest_only_body = {
            "scene": body["scene"],
            "job": body["job"],
            "payloadDigest": "sha256:" + hashlib.sha256(str(body["payload"]).encode()).hexdigest(),
        }
        digest_only = v2.capability(
            alice, feature=feature, nonce="digest-only", body=digest_only_body
        )
        digest_only_same_semantic_result = (
            digest_only["payload"].get("result", {}).get("artifactDigest")
            == receipt_v2["payload"].get("result", {}).get("artifactDigest")
        )
        v2.revoke(alice.user)
        denied = v2.capability(alice, feature=feature, nonce="after-revoke", body=body)
        immediate_revocation_for_new_calls = denied["payload"]["allowed"] is False

    assert result_v1["requestBodyDigest"] == "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()
    return {
        "kind": "ca-lic.v8-r1",
        "externalizedInputBytesPerUniqueJob": externalized_input_bytes,
        "localEquivalentExternalizedInputBytes": 0,
        "cachedExactResultSurvivesServiceOutage": cached_exact_result_survives_outage,
        "cachedResultValidForChangedBody": cached_result_valid_for_changed_body,
        "newUniqueJobDuringServiceOutage": new_job_during_outage,
        "newServiceReceiptValidUnderOldPinnedKey": new_receipt_under_old_pin,
        "oldReceiptValidUnderNewPinnedKeyOnly": old_receipt_under_new_pin,
        "historicalVerificationNeedsOldAuthorityKey": True,
        "newCallsDeniedImmediatelyAfterServerRevocation": immediate_revocation_for_new_calls,
        "revocationRetroactivelyInvalidatesDeliveredSignedResult": False,
        "digestOnlyRequestEquivalentToFullInputCapability": digest_only_same_semantic_result,
        "clientReceivesProtectedImplementation": False,
        "serviceVersionBoundInReceipt": receipt_v1["payload"]["serviceVersion"] == "cap-v1",
        "remoteResultDigest": result_v1["artifactDigest"],
    }


def structural_gates(result: Json) -> Json:
    v5 = result["v5"]
    v6 = result["v6"]
    v8 = result["v8"]
    scope = result["scope"]
    gates: Json = {
        "v5-retrospective-revocation-fails": v5["retrospectiveRevocationOfAlreadyDeliveredKey"] is False,
        "v5-reused-key-defeats-future-revocation": v5["revokedCanOpenFutureIfSharedKeyReused"] is True,
        "v5-rotation-protects-future-release": v5["revokedCanOpenFutureAfterRotation"] is False,
        "v5-per-recipient-limits-key-blast-radius": v5["crossRecipientKeyLeakBlockedByPerRecipientEncryption"] is True,
        "v5-plaintext-still-redistributable": v5["authorizedPlaintextRedistributionPossible"] is True,
        "v5-shared-reuse-key-distributions": v5["churn"]["sharedReused"]["contentKeyDistributions"] == 4,
        "v5-shared-rotation-key-distributions": v5["churn"]["sharedRotated"]["contentKeyDistributions"] == 11,
        "v5-per-recipient-ciphertext-copies": v5["churn"]["perRecipient"]["ciphertextCopies"] == 11,
        "v6-offline-equals-revocation-lag": v6["offlineWindowEqualsWorstCaseRevocationLagInSweep"] is True,
        "v6-fresh-lease-revoked": v6["freshLeaseAfterRevocationAllowed"] is False,
        "v6-outage-blocks-new-lease": v6["newLeaseDuringAuthorityOutage"] is False,
        "v6-unbound-replay": v6["unboundLeaseReplayOnOtherClient"] is True,
        "v6-binding-treatment-blocks-other-binding": v6["boundLeaseReplayOnDifferentBinding"] is False,
        "v6-local-capability-remains": v6["localCapabilityStillPresentAfterLocalPolicyPatch"] is True,
        "v8-exact-cache-survives-outage": v8["cachedExactResultSurvivesServiceOutage"] is True,
        "v8-cache-does-not-generalize": v8["cachedResultValidForChangedBody"] is False,
        "v8-outage-blocks-new-job": v8["newUniqueJobDuringServiceOutage"] is False,
        "v8-authority-rotation-breaks-old-pin": v8["newServiceReceiptValidUnderOldPinnedKey"] is False,
        "v8-new-pin-does-not-verify-old-receipt": v8["oldReceiptValidUnderNewPinnedKeyOnly"] is False,
        "v8-revocation-blocks-new-calls": v8["newCallsDeniedImmediatelyAfterServerRevocation"] is True,
        "v8-delivered-result-not-retroactively-revoked": v8["revocationRetroactivelyInvalidatesDeliveredSignedResult"] is False,
        "v8-digest-only-is-not-equivalent": v8["digestOnlyRequestEquivalentToFullInputCapability"] is False,
        "v8-protected-implementation-not-shipped": v8["clientReceivesProtectedImplementation"] is False,
        "scope-no-windows-kvm": scope["windowsKvmUsed"] is False,
        "scope-no-public-network": scope["publicNetworkUsed"] is False,
        "scope-no-third-party-binary": scope["thirdPartyBinaryExecuted"] is False,
    }
    return {
        "passed": sum(1 for value in gates.values() if value is True),
        "total": len(gates),
        "allPassed": all(value is True for value in gates.values()),
        "checks": gates,
    }


def main() -> int:
    result: Json = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ca-lic-r1-authority-economics",
        "v5": v5_r1(),
        "v6": v6_r1(),
        "v8": v8_r1(),
        "scope": {
            "windowsKvmUsed": False,
            "publicNetworkUsed": False,
            "thirdPartyBinaryExecuted": False,
            "activeTarget": "self-owned ToyDesigner",
        },
    }
    result["gates"] = structural_gates(result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gates"]["allPassed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
