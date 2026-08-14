# ToyDesigner CA-LIC R1 measurements — 2026-08-15

Reproduce with `./run_r1.sh`. Active target is self-owned ToyDesigner on local
Linux. No public network, Windows/KVM, or third-party binary execution occurs.

## V5-R1 — recipient scope, revocation and update churn

Deterministic three-release active-recipient sequence: `4 -> 3 -> 4`.

| Strategy | Key distributions | Ciphertext copies | Future revocation | Leak scope |
| --- | ---: | ---: | --- | --- |
| shared key reused | 4 | 3 | fails | one leaked key covers every release using that key |
| shared key rotated per release | 11 | 3 | works prospectively | release-scoped shared key |
| per-recipient encryption | 11 | 11 | works prospectively | one stolen key cannot decrypt another recipient's ciphertext |

Observed falsifiers:

- revoking Alice does **not** retract the already delivered v1 key;
- if v2 reuses that key, revoked Alice decrypts v2;
- rotating v2's key blocks Alice from v2 but forces redistribution to every
  still-authorized recipient;
- per-recipient encryption reduces the cryptographic blast radius of one key
  leak to one recipient, but Bob still obtains the plaintext and can redistribute
  those bytes.

Candidate law: **revocation of delivered decryptability is prospective, not
retrospective**. Rotation can protect future releases; it cannot erase plaintext
or keys already exposed to an authorized hostile client.

## V6-R1 — lease / offline / revocation semantics

TTL sweep after an immediate server-side revoke:

| lease TTL | locally valid ticks after revoke | offline survivability | worst-case stale-authority window |
| ---: | --- | ---: | ---: |
| 1 | `[0]` | 1 | 1 |
| 2 | `[0,1]` | 2 | 2 |
| 4 | `[0,1,2,3]` | 4 | 4 |
| 8 | `[0..7]` | 8 | 8 |

For every treatment:

```text
offline survivability == worst-case revocation lag
```

Fresh lease issuance after revoke fails immediately. Existing signed leases
remain locally valid until expiry. A persisted cache can survive restart until
expiry; a memory-only policy intentionally cannot. An unbound lease replays on
another client; a signed semantic client binding blocks that treatment, but the
lab does **not** claim hostile-host hardware binding.

The premium implementation remains local, so deleting local policy still runs
it. Lease quality therefore improves governance/availability semantics without
turning V6 into V8.

## V8-R1 — remote capability costs

One unique job externalized **4144 canonical JSON bytes** in this treatment;
the local equivalent externalizes zero bytes.

- an exact signed result remains verifiable after service outage;
- that cached result fails applicability for a changed request body;
- a new unique job cannot be computed while the service is unavailable;
- a newly rotated service authority key is not accepted by the old pin;
- an old receipt is not accepted under only the new pin, so historical
  verification requires retaining old authority identity;
- server-side revoke denies the next new capability call immediately;
- revocation does not retroactively invalidate a result already delivered;
- replacing the full 4 KiB payload with only its digest changes the capability
  input and produces a non-equivalent result in this target.

Candidate law: **capability externalization trades local extraction risk for
availability, input-disclosure, authority-identity and service-lifecycle risk**.

## Cross-round synthesis

```text
V5: don't deliver the key  -> stronger secrecy, distribution/revocation churn
V6: deliver a signed lease -> offline availability, stale-revocation window
V8: keep capability remote -> strong future-use control, live service dependency
```

No single topology dominates every objective. The correct choice depends on
what must remain secret, whether offline operation is required, how quickly
revocation must converge, what input can leave the client, and whether old
results must remain independently verifiable after authority rotation.
