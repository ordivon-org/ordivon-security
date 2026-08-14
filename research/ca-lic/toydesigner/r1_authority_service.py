"""ToyDesigner CA-LIC R1 external authority simulator.

Linux/stdin-stdout only.  It exists to make V6 lease semantics and V8 remote
capability semantics executable without touching Windows/KVM or a public
network.  Process separation is a semantic trust-domain model, not a claim of
physical resistance to a hostile OS owner.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import license_model as L

Json = dict[str, Any]


def canonical_bytes(value: Json) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signed(private: Ed25519PrivateKey, payload: Json) -> Json:
    return {"payload": payload, "signature": private.sign(canonical_bytes(payload)).hex()}


def verified_license(raw: object) -> tuple[L.License | None, str]:
    if not isinstance(raw, dict):
        return None, "malformed-license"
    try:
        lic = L.License(**raw)
    except TypeError:
        return None, "malformed-license"
    ok, why = L.verify_license(lic, "V1")
    return (lic, "verified") if ok else (None, why)


def is_pro(lic: L.License | None) -> bool:
    return lic is not None and lic.tier == "pro"


def main(argv: list[str]) -> int:
    if len(argv) not in {2, 3} or argv[1] not in {"lease", "capability"}:
        print("usage: r1_authority_service.py lease|capability [version]", file=sys.stderr)
        return 2
    mode = argv[1]
    version = argv[2] if len(argv) == 3 else "v1"
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    service_secret = os.urandom(32)
    revoked: set[str] = set()
    print(json.dumps({
        "kind": "toydesigner.r1-authority-hello",
        "mode": mode,
        "serviceVersion": version,
        "publicKey": public.hex(),
    }, sort_keys=True), flush=True)

    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        op = request.get("op")
        if op == "shutdown":
            return 0
        if op == "revoke":
            user = str(request.get("user", ""))
            revoked.add(user)
            print(json.dumps({"ok": True, "revoked": user}, sort_keys=True), flush=True)
            continue

        lic, credential_status = verified_license(request.get("license"))
        user = lic.user if lic is not None else "invalid"
        allowed = is_pro(lic) and user not in revoked
        feature = str(request.get("feature", ""))
        nonce = str(request.get("nonce", ""))

        if mode == "lease" and op == "issue-lease":
            tick = int(request.get("tick", 0))
            lease_ticks = max(1, int(request.get("leaseTicks", 1)))
            binding = request.get("binding")
            if binding is not None:
                binding = str(binding)
            payload: Json = {
                "kind": "remote-entitlement-lease",
                "feature": feature,
                "nonce": nonce,
                "user": user,
                "allowed": allowed,
                "credentialStatus": credential_status,
                "issuedTick": tick,
                "expiresTickExclusive": tick + lease_ticks,
                "binding": binding,
                "serviceVersion": version,
            }
            print(json.dumps(signed(private, payload), sort_keys=True), flush=True)
            continue

        if mode == "capability" and op == "capability":
            body = request.get("body") if isinstance(request.get("body"), dict) else {}
            body_bytes = canonical_bytes(body)
            result: Json | None = None
            if allowed:
                material = hashlib.sha256(
                    service_secret
                    + version.encode("utf-8")
                    + b"|"
                    + body_bytes
                ).hexdigest()
                result = {
                    "artifactDigest": "sha256:" + material,
                    "requestBodyDigest": "sha256:" + hashlib.sha256(body_bytes).hexdigest(),
                    "serviceVersion": version,
                }
            payload = {
                "kind": "remote-capability-r1",
                "feature": feature,
                "nonce": nonce,
                "user": user,
                "allowed": allowed,
                "credentialStatus": credential_status,
                "serviceVersion": version,
                "result": result,
            }
            print(json.dumps(signed(private, payload), sort_keys=True), flush=True)
            continue

        print(json.dumps({"error": "unsupported-operation"}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
