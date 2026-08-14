"""V5: encrypted shipped asset changes the problem from gate bypass to key possession."""
from __future__ import annotations

import base64

import advanced_ladder as A

plaintext = b"TOYDESIGNER_PREMIUM_IMPLEMENTATION_V5"
bundle, key = A.vendor_seal_asset(plaintext)
free = A.vendor_issue_asset_entitlement("eve", "free", bundle, key)
pro = A.vendor_issue_asset_entitlement("alice", "pro", bundle, key)

# Free client: patching semantic fields/verifier cannot conjure an absent content key.
free["payload"]["tier"] = "pro"
original_verify = A.verify_asset_entitlement
A.verify_asset_entitlement = lambda entitlement, bundle: (True, "patched local verifier")
try:
    try:
        A.open_asset_with_entitlement(bundle, free)
        raise AssertionError("free client unexpectedly decrypted asset")
    except (TypeError, KeyError, ValueError):
        no_key = True
finally:
    A.verify_asset_entitlement = original_verify
assert no_key
print("  [BLOCK] local verifier patch cannot recover an absent content key")

# Authorized Pro client must receive the key. Once it reaches the hostile client,
# it can be copied and used offline: encryption protects non-recipients, not an
# asset from an already-authorized recipient.
opened = A.open_asset_with_entitlement(bundle, pro)
assert opened == plaintext
extracted_key = base64.b64decode(pro["payload"]["contentKey"])
assert A.open_asset_with_key(bundle, extracted_key) == plaintext
print("  [EXTRACT] authorized Pro delivery exposes reusable content key to that client")

print("MEAS v5 free_local_patch=blocked authorized_key_extraction=succeeds boundary_changed=partial")
print("RESULT ASSET PLACEMENT CHANGED ATTACK GRAPH (V5)")
