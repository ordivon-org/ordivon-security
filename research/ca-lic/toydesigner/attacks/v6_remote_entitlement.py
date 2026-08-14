"""V6: authentic remote yes/no does not protect a capability that remains local."""
from __future__ import annotations

from pathlib import Path

import advanced_ladder as A
import license_model as L
import vendor

Path("runs").mkdir(exist_ok=True)
vendor.issue("mallory", "free", bind=True, expiry=None, out="runs/v6_free.json")
lic = L.load_license("runs/v6_free.json")

with A.ExternalAuthorityClient.start("entitlement") as authority:
    receipt = authority.request(
        lic, feature="premium.local-render", nonce="v6-attack"
    )
    ok, why = A.verify_external_receipt(
        receipt, authority.public_key_hex,
        expected_kind="remote-entitlement",
        expected_feature="premium.local-render",
        expected_nonce="v6-attack",
    )
    assert ok and receipt["payload"]["allowed"] is False, why
    print("  [REMOTE] authentic authority response = DENY")

    try:
        A.require_remote_entitlement(
            receipt, authority.public_key_hex,
            feature="premium.local-render", nonce="v6-attack"
        )
        raise AssertionError("remote deny unexpectedly accepted")
    except L.NotEntitled:
        pass

    original = A.require_remote_entitlement
    A.require_remote_entitlement = lambda *args, **kwargs: None
    try:
        A.require_remote_entitlement(
            receipt, authority.public_key_hex,
            feature="premium.local-render", nonce="v6-attack"
        )
        result = A.local_premium_capability("scene-v6")
    finally:
        A.require_remote_entitlement = original

assert result["resolution"] == "3840x2160"
print("  [PATCH] local enforcement removed; shipped premium implementation still runs")
print("MEAS v6 signed_remote_decision=effective replay_nonce=bound local_patch_sites=1 boundary_changed=false")
print("RESULT REMOTE ENTITLEMENT BYPASS SUCCEEDED LOCALLY (V6)")
