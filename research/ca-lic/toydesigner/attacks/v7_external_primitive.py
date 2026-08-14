"""V7: an external/hardware-shaped primitive cannot be replaced by a local UI patch."""
from __future__ import annotations

from pathlib import Path

import advanced_ladder as A
import license_model as L
import vendor

Path("runs").mkdir(exist_ok=True)
vendor.issue("mallory", "free", bind=True, expiry=None, out="runs/v7_free.json")
vendor.issue("alice", "pro", bind=True, expiry=None, out="runs/v7_pro.json")
free = L.load_license("runs/v7_free.json")
pro = L.load_license("runs/v7_pro.json")

with A.ExternalAuthorityClient.start("hardware") as authority:
    deny = authority.request(
        free, feature="frame-lock", nonce="v7-free", body={"frame": "99"}
    )
    denied_ok, _ = A.verify_external_capability(
        deny, authority.public_key_hex,
        kind="hardware-primitive", feature="frame-lock", nonce="v7-free"
    )
    assert not denied_ok

    # A local attacker can invent a result object but cannot sign it as the
    # external authority. The independent verifier rejects it.
    forged = {
        "payload": {
            "kind": "hardware-primitive",
            "feature": "frame-lock",
            "nonce": "v7-free",
            "allowed": True,
            "tier": "pro",
            "result": {"frame": "99", "ticket": "locally-faked"},
        },
        "signature": "00" * 64,
    }
    forged_ok, forged_why = A.verify_external_capability(
        forged, authority.public_key_hex,
        kind="hardware-primitive", feature="frame-lock", nonce="v7-free"
    )
    assert not forged_ok
    print(f"  [BLOCK] fake local primitive rejected: {forged_why}")

    valid = authority.request(
        pro, feature="frame-lock", nonce="v7-pro", body={"frame": "99"}
    )
    valid_ok, valid_why = A.verify_external_capability(
        valid, authority.public_key_hex,
        kind="hardware-primitive", feature="frame-lock", nonce="v7-pro"
    )
    assert valid_ok, valid_why
    print("  [ALLOW] entitled external primitive yields independently verifiable ticket")

print("MEAS v7 local_ui_patch=insufficient external_private_state=required boundary_changed=true physical_hardware_proof=false")
print("RESULT EXTERNAL PRIMITIVE HOLDS BOUNDARY (V7)")
