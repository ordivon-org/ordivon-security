"""Ephemeral stdin/stdout authority simulator for ToyDesigner V6-V8.

It has no network access and creates a fresh signing key per process.  The
caller receives only the public key.  This process separation is used to make
trust-domain contracts executable; it is not evidence of physical isolation
from a hostile OS owner.
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


def tier_allows(tier: str, need: str) -> bool:
    rank = {name: index for index, name in enumerate(L.TIERS)}
    return rank.get(tier, -1) >= rank[need]


def signed(private: Ed25519PrivateKey, payload: Json) -> Json:
    return {"payload": payload, "signature": private.sign(canonical_bytes(payload)).hex()}


def verified_license(raw: object) -> tuple[L.License | None, str]:
    if not isinstance(raw, dict):
        return None, "malformed license"
    try:
        lic = L.License(**raw)
    except TypeError:
        return None, "malformed license"
    ok, why = L.verify_license(lic, "V1")
    return (lic, "verified") if ok else (None, why)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"entitlement", "hardware", "capability"}:
        print("usage: external_authority_service.py entitlement|hardware|capability", file=sys.stderr)
        return 2
    mode = argv[1]
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    service_secret = os.urandom(32)
    print(json.dumps({
        "kind": "toydesigner.external-authority-hello",
        "mode": mode,
        "publicKey": public.hex(),
    }, sort_keys=True), flush=True)

    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        if request.get("op") == "shutdown":
            return 0
        if request.get("op") != "request":
            continue
        feature = str(request.get("feature", ""))
        nonce = str(request.get("nonce", ""))
        body = request.get("body") if isinstance(request.get("body"), dict) else {}
        lic, why = verified_license(request.get("license"))
        tier = lic.tier if lic is not None else "invalid"
        allowed = lic is not None and tier_allows(tier, "pro")

        if mode == "entitlement":
            payload: Json = {
                "kind": "remote-entitlement",
                "feature": feature,
                "nonce": nonce,
                "allowed": allowed,
                "tier": tier,
                "credentialStatus": why,
            }
        elif mode == "hardware":
            result: Json | None = None
            if allowed:
                frame = str(body.get("frame", "0"))
                # The primitive result depends on service-private state and is
                # signed.  A patched client can lie about UI state but cannot
                # manufacture an independently verifiable ticket.
                material = hashlib.sha256(service_secret + frame.encode()).hexdigest()
                result = {"frame": frame, "ticket": material}
            payload = {
                "kind": "hardware-primitive",
                "feature": feature,
                "nonce": nonce,
                "allowed": allowed,
                "tier": tier,
                "credentialStatus": why,
                "result": result,
            }
        else:
            result = None
            if allowed:
                scene = str(body.get("scene", "scene"))
                job = str(body.get("job", "job"))
                render_secret = hashlib.sha256(
                    service_secret + scene.encode() + b"|" + job.encode()
                ).hexdigest()
                result = {
                    "scene": scene,
                    "job": job,
                    "resolution": "3840x2160",
                    "artifactDigest": "sha256:" + render_secret,
                }
            payload = {
                "kind": "remote-capability",
                "feature": feature,
                "nonce": nonce,
                "allowed": allowed,
                "tier": tier,
                "credentialStatus": why,
                "result": result,
            }
        print(json.dumps(signed(private, payload), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
