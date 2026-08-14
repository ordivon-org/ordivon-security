"""License model + verification chain for ToyDesigner (CA-LIC lab target).

Mirrors the shape of 目标产品's entitlement surface observed in
核心库.dll: license object with tier/status/system_code, tiered features,
scattered gates, TD-style denial strings.

Defense levels (the V ladder), each adds ONE defense mechanism:
  V0: plain boolean gate     -- tier trusted as-is, no crypto at all
  V1: Ed25519 signature      -- unforgeable credential (asymmetric key)
  V2: + machine binding      -- license.system_code must equal host code
  V3: same verification as V2, but gates scattered across modules

Each level exists to demonstrate one structural lesson:
  V0 -> credential forgery is free (flip a boolean)
  V1 -> credential forgery is stopped, yet enforcement is still a local
        boolean the attacker can flip: verification != enforcement
  V2 -> authority is anchored to a machine value whose *reporting* the
        attacker also controls (the client states its own identity)
  V3 -> the attack surface grows with the number of gate sites: breaking
        N gates costs ~N patches (effort scales, structure does not change)

The vendor public key is "embedded in the product" (keys/vendor_pub.pem),
exactly like a real shipped client. The private key never ships.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import platform
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
PUBKEY_PATH = os.path.join(KEYS_DIR, "vendor_pub.pem")

TIERS = ("free", "non-commercial", "commercial", "pro")
_TIER_RANK = {t: i for i, t in enumerate(TIERS)}


class NotEntitled(Exception):
    """Raised at a gate. Message mirrors TD's user-facing strings."""


def get_system_code() -> str:
    """Machine anchor. Deliberately a *client-reported* value: in this lab
    the attacker controls what this function returns (monkeypatch), which is
    the whole point of V2's lesson. A real product would bury the same
    weakness under obfuscation or hardware anchoring."""
    raw = f"{platform.node()}|{uuid.getnode():012x}|{platform.machine()}|{os.name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _public_key():
    with open(PUBKEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


@dataclasses.dataclass
class License:
    user: str
    tier: str
    system_code: str | None        # None = portable license (V1 only)
    issued_utc: str
    expiry_utc: str | None
    signature: str                 # hex; ed25519 over canonical payload

    # --- TD-shaped surface -------------------------------------------------
    @property
    def type(self) -> str:
        return self.tier

    @property
    def status(self) -> int:
        return 0 if self.tier in ("commercial", "pro") else -1

    def is_pro(self) -> bool:
        return self.tier == "pro"

    def is_non_commercial(self) -> bool:
        return self.tier == "non-commercial"

    def require_tier(self, need: str, msg: str) -> None:
        if _TIER_RANK.get(self.tier, 0) < _TIER_RANK[need]:
            raise NotEntitled(msg)

    def require_pro(self, msg: str) -> None:
        self.require_tier("pro", msg)

    # --- canonical payload (what the vendor signs / client verifies) -------
    def payload_bytes(self) -> bytes:
        d = dataclasses.asdict(self)
        d.pop("signature")
        return json.dumps(d, sort_keys=True).encode()


# --------------------------------------------------------------------------
# Verification chain (per defense level)
# --------------------------------------------------------------------------

def _check_signature(lic: License) -> tuple[bool, str]:
    try:
        key = _public_key()
        if not isinstance(key, Ed25519PublicKey):
            return False, "unexpected public key type"
        key.verify(bytes.fromhex(lic.signature), lic.payload_bytes())
        return True, "signature ok"
    except (InvalidSignature, ValueError, OSError) as e:
        return False, f"signature invalid: {e.__class__.__name__}"


def _check_binding(lic: License) -> tuple[bool, str]:
    if not lic.system_code:
        return False, "portable license not allowed at this level"
    if lic.system_code != get_system_code():
        return False, "created with different system code"
    return True, "binding ok"


def _check_expiry(lic: License) -> tuple[bool, str]:
    if not lic.expiry_utc:
        return True, "no expiry"
    exp = datetime.datetime.fromisoformat(lic.expiry_utc)
    if exp < datetime.datetime.now(datetime.UTC):
        return False, "license expired"
    return True, "expiry ok"


def verify_license(lic: License, defense_level: str) -> tuple[bool, str]:
    """Returns (ok, reason). Called once at startup AND from gates (V3)."""
    if defense_level == "V0":
        return True, "V0: plain gate trusts tier as-is"
    if defense_level in ("V1", "V2", "V3"):
        ok, why = _check_signature(lic)
        if not ok:
            return False, why
        if defense_level in ("V2", "V3"):
            ok, why = _check_binding(lic)
            if not ok:
                return False, why
        ok, why = _check_expiry(lic)
        if not ok:
            return False, why
        return True, "verified"
    raise ValueError(f"unknown defense level: {defense_level}")


def load_license(path: str) -> License:
    with open(path, encoding="utf-8") as f:
        return License(**json.load(f))
