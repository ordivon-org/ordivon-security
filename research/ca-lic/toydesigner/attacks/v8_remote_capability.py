"""V8: the protected capability itself stays external; local patching can only fake UI."""
from __future__ import annotations

from pathlib import Path

import advanced_ladder as A
import license_model as L
import vendor

Path("runs").mkdir(exist_ok=True)
vendor.issue("mallory", "free", bind=True, expiry=None, out="runs/v8_free.json")
vendor.issue("alice", "pro", bind=True, expiry=None, out="runs/v8_pro.json")
free = L.load_license("runs/v8_free.json")
pro = L.load_license("runs/v8_pro.json")

with A.ExternalAuthorityClient.start("capability") as authority:
    deny = authority.request(
        free,
        feature="premium.remote-render",
        nonce="v8-free",
        body={"scene": "station-zero", "job": "free-attempt"},
    )
    deny_ok, _ = A.verify_external_capability(
        deny, authority.public_key_hex,
        kind="remote-capability", feature="premium.remote-render", nonce="v8-free"
    )
    assert not deny_ok

    # A local fake can imitate the shape but not the service signature/result.
    fake = {
        "payload": {
            "kind": "remote-capability",
            "feature": "premium.remote-render",
            "nonce": "v8-free",
            "allowed": True,
            "tier": "pro",
            "result": {
                "scene": "station-zero",
                "job": "free-attempt",
                "resolution": "3840x2160",
                "artifactDigest": "sha256:" + "0" * 64,
            },
        },
        "signature": "00" * 64,
    }
    fake_ok, fake_why = A.verify_external_capability(
        fake, authority.public_key_hex,
        kind="remote-capability", feature="premium.remote-render", nonce="v8-free"
    )
    assert not fake_ok
    print(f"  [BLOCK] local fake output has no external authority: {fake_why}")

    valid = authority.request(
        pro,
        feature="premium.remote-render",
        nonce="v8-pro",
        body={"scene": "station-zero", "job": "pro-job"},
    )
    valid_ok, valid_why = A.verify_external_capability(
        valid, authority.public_key_hex,
        kind="remote-capability", feature="premium.remote-render", nonce="v8-pro"
    )
    assert valid_ok, valid_why
    assert valid["payload"]["result"]["artifactDigest"].startswith("sha256:")
    print("  [ALLOW] entitled client receives signed result from non-shipped capability")

print("MEAS v8 shipped_pro_implementation=false local_patch=insufficient external_service_required=true boundary_changed=true")
print("RESULT REMOTE CAPABILITY HOLDS BOUNDARY (V8)")
