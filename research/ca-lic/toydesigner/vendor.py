"""Vendor side of ToyDesigner: keygen + license issuance.

Usage:
  python vendor.py keygen                  # generate keys/ once
  python vendor.py issue <user> <tier> [-m] [-e YYYY-MM-DD] [-o out.json]
    -m    bind to the current machine's system code (V2/V3 licenses)
    -e    expiry date (default none)
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import sys

import license_model as L
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEYS_DIR = L.KEYS_DIR
PRIV_PATH = os.path.join(KEYS_DIR, "vendor_priv.pem")


def keygen() -> None:
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(PRIV_PATH) and os.path.exists(L.PUBKEY_PATH):
        print("keys/ already exists; refusing to overwrite")
        return
    priv = Ed25519PrivateKey.generate()
    with open(PRIV_PATH, "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(L.PUBKEY_PATH, "wb") as f:
        f.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"wrote {PRIV_PATH}\nwrote {L.PUBKEY_PATH}")


def issue(user: str, tier: str, bind: bool, expiry: str | None, out: str) -> None:
    if tier not in L.TIERS:
        sys.exit(f"bad tier {tier!r}; choose from {L.TIERS}")
    with open(PRIV_PATH, "rb") as f:
        raw = f.read()
    priv = serialization.load_pem_private_key(raw, password=None)
    assert hasattr(priv, "sign"), "expected an Ed25519 private key"
    lic = L.License(
        user=user,
        tier=tier,
        system_code=L.get_system_code() if bind else None,
        issued_utc=datetime.datetime.now(datetime.UTC).isoformat(),
        expiry_utc=expiry,
        signature="",
    )
    lic.signature = priv.sign(lic.payload_bytes()).hex()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(lic), f, indent=2)
    print(f"issued {tier} license for {user} -> {out} "
          f"(bound={bind}, expiry={expiry or 'none'})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    p = sub.add_parser("issue")
    p.add_argument("user")
    p.add_argument("tier")
    p.add_argument("-m", "--machine", action="store_true")
    p.add_argument("-e", "--expiry")
    p.add_argument("-o", "--out", default="license.json")
    a = ap.parse_args()
    if a.cmd == "keygen":
        keygen()
    else:
        issue(a.user, a.tier, a.machine, a.expiry, a.out)
