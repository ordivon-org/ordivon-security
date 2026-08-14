"""ToyDesigner CA-LIC V4-V8 authority-topology lab.

This module is intentionally a self-owned research target.  It models five
materially different protection shapes rather than adding more local booleans:

V4  local integrity checking          -- detects tamper, enforcement stays local
V5  encrypted shipped asset           -- plaintext is absent until a key is delivered
V6  remote entitlement decision       -- authority answers remotely, capability stays local
V7  external/hardware-shaped primitive-- external authority performs a required primitive
V8  remote capability                 -- protected implementation/result stays external

The external authority process is a semantic trust-domain simulator, not a
claim of hardware isolation on this Linux host.  Physical TPM/dongle/TEE work
is deliberately out of scope for this round.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import license_model as L
import vendor

Json = dict[str, Any]
_AAD = b"ToyDesigner:CA-LIC:V5:premium-asset:v1"


def canonical_bytes(value: Json) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _vendor_private_key() -> Ed25519PrivateKey:
    raw = Path(vendor.PRIV_PATH).read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("ToyDesigner vendor key must be Ed25519")
    return key


def _vendor_public_key() -> Ed25519PublicKey:
    raw = Path(L.PUBKEY_PATH).read_bytes()
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("ToyDesigner vendor public key must be Ed25519")
    return key


def sign_vendor_payload(payload: Json) -> str:
    return _vendor_private_key().sign(canonical_bytes(payload)).hex()


def verify_vendor_payload(payload: Json, signature: str) -> bool:
    try:
        _vendor_public_key().verify(bytes.fromhex(signature), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# V4 — local integrity checking
# ---------------------------------------------------------------------------

def build_integrity_manifest(root: Path, relative_paths: list[str]) -> Json:
    files = {
        rel: sha256_bytes((root / rel).read_bytes())
        for rel in sorted(relative_paths)
    }
    payload: Json = {
        "schemaVersion": 1,
        "kind": "toydesigner.v4-integrity-manifest",
        "files": files,
    }
    return {"payload": payload, "signature": sign_vendor_payload(payload)}


def verify_integrity_manifest(root: Path, manifest: Json) -> tuple[bool, str]:
    payload = manifest.get("payload")
    signature = manifest.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False, "malformed manifest"
    if not verify_vendor_payload(payload, signature):
        return False, "manifest signature invalid"
    files = payload.get("files")
    if not isinstance(files, dict):
        return False, "manifest files invalid"
    for rel, expected in files.items():
        if not isinstance(rel, str) or not isinstance(expected, str):
            return False, "manifest entry invalid"
        path = root / rel
        if not path.is_file():
            return False, f"missing:{rel}"
        actual = sha256_bytes(path.read_bytes())
        if actual != expected:
            return False, f"digest-mismatch:{rel}"
    return True, "integrity verified"


def require_integrity(root: Path, manifest: Json) -> None:
    ok, why = verify_integrity_manifest(root, manifest)
    if not ok:
        raise L.NotEntitled(f"integrity failure: {why}")


def local_premium_capability(scene: str) -> Json:
    """A premium implementation that is fully present on the client."""
    return {
        "kind": "local-premium-render",
        "scene": scene,
        "resolution": "3840x2160",
        "frames": 60,
    }


# ---------------------------------------------------------------------------
# V5 — encrypted shipped asset, key delivered only to entitled clients
# ---------------------------------------------------------------------------

def vendor_seal_asset(plaintext: bytes) -> tuple[Json, bytes]:
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, _AAD)
    bundle: Json = {
        "schemaVersion": 1,
        "kind": "toydesigner.v5-encrypted-asset",
        "algorithm": "ChaCha20-Poly1305",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintextDigest": sha256_bytes(plaintext),
    }
    return bundle, key


def asset_bundle_digest(bundle: Json) -> str:
    return sha256_bytes(canonical_bytes(bundle))


def vendor_issue_asset_entitlement(user: str, tier: str, bundle: Json, key: bytes) -> Json:
    if tier not in L.TIERS:
        raise ValueError(f"unknown tier: {tier}")
    payload: Json = {
        "schemaVersion": 1,
        "kind": "toydesigner.v5-asset-entitlement",
        "user": user,
        "tier": tier,
        "assetDigest": asset_bundle_digest(bundle),
        # The key is deliberately absent for non-Pro clients.  For Pro it must
        # eventually reach the hostile client, which is the V5 residual risk.
        "contentKey": base64.b64encode(key).decode("ascii") if tier == "pro" else None,
    }
    return {"payload": payload, "signature": sign_vendor_payload(payload)}


def verify_asset_entitlement(entitlement: Json, bundle: Json) -> tuple[bool, str]:
    payload = entitlement.get("payload")
    signature = entitlement.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False, "malformed entitlement"
    if not verify_vendor_payload(payload, signature):
        return False, "entitlement signature invalid"
    if payload.get("assetDigest") != asset_bundle_digest(bundle):
        return False, "asset digest mismatch"
    if payload.get("tier") != "pro":
        return False, "asset key not entitled"
    if not isinstance(payload.get("contentKey"), str):
        return False, "content key absent"
    return True, "asset entitlement verified"


def open_asset_with_entitlement(bundle: Json, entitlement: Json) -> bytes:
    ok, why = verify_asset_entitlement(entitlement, bundle)
    if not ok:
        raise L.NotEntitled(why)
    payload = entitlement["payload"]
    key = base64.b64decode(payload["contentKey"])
    return open_asset_with_key(bundle, key)


def open_asset_with_key(bundle: Json, key: bytes) -> bytes:
    nonce = base64.b64decode(str(bundle["nonce"]))
    ciphertext = base64.b64decode(str(bundle["ciphertext"]))
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, _AAD)
    if sha256_bytes(plaintext) != bundle["plaintextDigest"]:
        raise ValueError("decrypted asset digest mismatch")
    return plaintext


# ---------------------------------------------------------------------------
# V6-V8 — external authority process and client verification
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ExternalAuthorityClient:
    mode: str
    process: subprocess.Popen[str]
    public_key_hex: str

    @classmethod
    def start(cls, mode: str) -> "ExternalAuthorityClient":
        service = Path(__file__).with_name("external_authority_service.py")
        process = subprocess.Popen(
            [sys.executable, str(service), mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if process.stdout is None:
            raise RuntimeError("external authority stdout unavailable")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("external authority failed before hello")
        hello = json.loads(line)
        if hello.get("kind") != "toydesigner.external-authority-hello":
            raise RuntimeError(f"unexpected external authority hello: {hello}")
        return cls(mode=mode, process=process, public_key_hex=str(hello["publicKey"]))

    def request(
        self,
        lic: L.License,
        *,
        feature: str,
        nonce: str,
        body: Json | None = None,
    ) -> Json:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("external authority pipes unavailable")
        request: Json = {
            "op": "request",
            "feature": feature,
            "nonce": nonce,
            "license": dataclasses.asdict(lic),
            "body": body or {},
        }
        self.process.stdin.write(json.dumps(request, sort_keys=True) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("external authority closed without response")
        return json.loads(line)

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

    def __enter__(self) -> "ExternalAuthorityClient":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def _external_public_key(public_key_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))


def verify_external_receipt(
    receipt: Json,
    public_key_hex: str,
    *,
    expected_kind: str,
    expected_feature: str,
    expected_nonce: str,
) -> tuple[bool, str]:
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False, "malformed external receipt"
    try:
        _external_public_key(public_key_hex).verify(
            bytes.fromhex(signature), canonical_bytes(payload)
        )
    except (InvalidSignature, ValueError):
        return False, "external receipt signature invalid"
    if payload.get("kind") != expected_kind:
        return False, "external receipt kind mismatch"
    if payload.get("feature") != expected_feature:
        return False, "external receipt feature mismatch"
    if payload.get("nonce") != expected_nonce:
        return False, "external receipt nonce mismatch"
    return True, "external receipt verified"


def require_remote_entitlement(
    receipt: Json,
    public_key_hex: str,
    *,
    feature: str,
    nonce: str,
) -> None:
    ok, why = verify_external_receipt(
        receipt,
        public_key_hex,
        expected_kind="remote-entitlement",
        expected_feature=feature,
        expected_nonce=nonce,
    )
    if not ok:
        raise L.NotEntitled(why)
    if receipt["payload"].get("allowed") is not True:
        raise L.NotEntitled("remote authority denied entitlement")


def verify_external_capability(
    receipt: Json,
    public_key_hex: str,
    *,
    kind: str,
    feature: str,
    nonce: str,
) -> tuple[bool, str]:
    ok, why = verify_external_receipt(
        receipt,
        public_key_hex,
        expected_kind=kind,
        expected_feature=feature,
        expected_nonce=nonce,
    )
    if not ok:
        return False, why
    if receipt["payload"].get("allowed") is not True:
        return False, "external authority denied capability"
    if not isinstance(receipt["payload"].get("result"), dict):
        return False, "external capability result absent"
    return True, "external capability verified"
