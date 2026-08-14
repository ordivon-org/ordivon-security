"""Defense baselines for ToyDesigner V4-V8.

Every advanced attack script is meaningful only if its corresponding defense
first holds.  This baseline performs no Windows/KVM work and contacts no
network service; V6-V8 use a local stdin/stdout external-authority simulator.
"""
from __future__ import annotations

from pathlib import Path
import tempfile

import advanced_ladder as A
import license_model as L
import vendor

RUNS = Path("runs")
RUNS.mkdir(exist_ok=True)


def issue(name: str, tier: str) -> L.License:
    path = RUNS / f"advanced_{name}_{tier}.json"
    vendor.issue(name, tier, bind=True, expiry=None, out=str(path))
    return L.load_license(str(path))


def main() -> int:
    checks: list[tuple[str, bool]] = []

    # V4: clean bytes pass; changed bytes fail.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "premium.py").write_text("def run():\n    return 'premium'\n", encoding="utf-8")
        manifest = A.build_integrity_manifest(root, ["premium.py"])
        checks.append(("V4 clean integrity", A.verify_integrity_manifest(root, manifest)[0]))
        (root / "premium.py").write_text("def run():\n    return 'patched'\n", encoding="utf-8")
        checks.append(("V4 tamper detected", not A.verify_integrity_manifest(root, manifest)[0]))

    # V5: free has ciphertext but no key; Pro can decrypt exact plaintext.
    plaintext = b"TOYDESIGNER_PREMIUM_MODULE_V5"
    bundle, key = A.vendor_seal_asset(plaintext)
    free_asset = A.vendor_issue_asset_entitlement("baseline-free", "free", bundle, key)
    pro_asset = A.vendor_issue_asset_entitlement("baseline-pro", "pro", bundle, key)
    try:
        A.open_asset_with_entitlement(bundle, free_asset)
        free_denied = False
    except L.NotEntitled:
        free_denied = True
    checks.append(("V5 free key absent", free_denied))
    checks.append(("V5 pro decrypt exact", A.open_asset_with_entitlement(bundle, pro_asset) == plaintext))

    free = issue("remote", "free")
    pro = issue("remote", "pro")

    # V6: signed remote denial/allow works.
    with A.ExternalAuthorityClient.start("entitlement") as authority:
        deny = authority.request(free, feature="premium.local-render", nonce="v6-free")
        allow = authority.request(pro, feature="premium.local-render", nonce="v6-pro")
        try:
            A.require_remote_entitlement(
                deny, authority.public_key_hex,
                feature="premium.local-render", nonce="v6-free"
            )
            deny_held = False
        except L.NotEntitled:
            deny_held = True
        checks.append(("V6 remote deny holds", deny_held))
        try:
            A.require_remote_entitlement(
                allow, authority.public_key_hex,
                feature="premium.local-render", nonce="v6-pro"
            )
            allow_held = True
        except L.NotEntitled:
            allow_held = False
        checks.append(("V6 remote allow verifies", allow_held))

    # V7: only Pro receives an independently verifiable primitive result.
    with A.ExternalAuthorityClient.start("hardware") as authority:
        deny = authority.request(
            free, feature="frame-lock", nonce="v7-free", body={"frame": "42"}
        )
        allow = authority.request(
            pro, feature="frame-lock", nonce="v7-pro", body={"frame": "42"}
        )
        checks.append((
            "V7 free primitive denied",
            not A.verify_external_capability(
                deny, authority.public_key_hex,
                kind="hardware-primitive", feature="frame-lock", nonce="v7-free"
            )[0],
        ))
        checks.append((
            "V7 pro primitive verified",
            A.verify_external_capability(
                allow, authority.public_key_hex,
                kind="hardware-primitive", feature="frame-lock", nonce="v7-pro"
            )[0],
        ))

    # V8: full premium result exists only on external service path.
    with A.ExternalAuthorityClient.start("capability") as authority:
        deny = authority.request(
            free, feature="premium.remote-render", nonce="v8-free",
            body={"scene": "A", "job": "1"},
        )
        allow = authority.request(
            pro, feature="premium.remote-render", nonce="v8-pro",
            body={"scene": "A", "job": "1"},
        )
        checks.append((
            "V8 free remote capability denied",
            not A.verify_external_capability(
                deny, authority.public_key_hex,
                kind="remote-capability", feature="premium.remote-render", nonce="v8-free"
            )[0],
        ))
        checks.append((
            "V8 pro remote capability verified",
            A.verify_external_capability(
                allow, authority.public_key_hex,
                kind="remote-capability", feature="premium.remote-render", nonce="v8-pro"
            )[0],
        ))

    failures = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print(f"advanced baseline: {len(checks) - len(failures)}/{len(checks)} PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
