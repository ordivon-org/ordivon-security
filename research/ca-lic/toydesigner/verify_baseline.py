"""Baseline: the gates must actually work BEFORE we attack them.

Runs the full feature matrix at each tier (free / commercial / pro) under
V3 verification and asserts the expected allow/deny table. If this fails,
the lab target is broken, not the attack.

Expected matrix:
  feature        free    commercial  pro
  render_720p    OK      OK          OK
  render_4k      DENIED  DENIED      OK
  shared_memory  DENIED  OK          OK
  multi_node_sync DENIED DENIED      OK
  private_toe    DENIED  DENIED      OK
"""
from __future__ import annotations

import sys

import app as appmod
import features
import license_model as L
import vendor

EXPECT = {
    "free":       {"render_720p": True,  "render_4k": False, "shared_memory": False,
                   "multi_node_sync": False, "private_toe": False},
    "commercial": {"render_720p": True,  "render_4k": False, "shared_memory": True,
                   "multi_node_sync": False, "private_toe": False},
    "pro":        {"render_720p": True,  "render_4k": True,  "shared_memory": True,
                   "multi_node_sync": True,  "private_toe": True},
}

LEVEL = "V3"


def main() -> int:
    failures = 0
    for tier, exp in EXPECT.items():
        vendor.issue(f"baseline-{tier}", tier, bind=True, expiry=None,
                     out=f"runs/lic_{tier}.json")
        lic = L.load_license(f"runs/lic_{tier}.json")
        ok, why = L.verify_license(lic, LEVEL)
        assert ok, f"{tier}: license rejected at {LEVEL}: {why}"
        features.lic = lic
        matrix = dict((n, a) for n, a, _ in appmod.run_matrix(lic))
        for feat, allowed in exp.items():
            got = matrix[feat]
            mark = "PASS" if got == allowed else "FAIL"
            if got != allowed:
                failures += 1
            print(f"  [{mark}] {tier:<10} {feat:<16} expected={allowed} got={got}")
    # also verify a forged tier flip is REJECTED at V1+ (signature holds)
    vendor.issue("forge-test", "free", bind=True, expiry=None, out="runs/lic_forge.json")
    lic = L.load_license("runs/lic_forge.json")
    lic.tier = "pro"  # attacker edits the file semantics (runtime object)
    ok, why = L.verify_license(lic, LEVEL)
    print(f"  [{'PASS' if not ok else 'FAIL'}] forged tier flip rejected "
          f"({why})")
    failures += 0 if not ok else 1
    print(f"baseline: {'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
