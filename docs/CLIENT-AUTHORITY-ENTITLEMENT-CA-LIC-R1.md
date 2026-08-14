---
schema_version: 1
id: security.client-authority-entitlement-ca-lic-r1
title: CA-LIC R1 — Revocation, Offline Authority, Churn and Remote-Capability Cost
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-15
summary: Controlled ToyDesigner V5/V6/V8 follow-up measuring recipient/key churn, prospective revocation, lease offline-vs-revocation coupling, external capability availability/input exposure, authority-key lifecycle, and cross-system authority-topology observations.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security
related:
  - security.client-authority-entitlement-ca-lic
  - security.research-boundary
  - security.research-agenda
---
# CA-LIC R1 — Revocation, Offline Authority, Churn and Remote-Capability Cost

## Question

CA-LIC V0-V8 established that moving a **decision** outside the client is not
the same as moving a **secret, necessary operation, or capability** outside the
client. R1 asks the next question:

> Once authority has moved, what does the vendor pay in revocation lag,
> redistribution churn, availability, privacy/input exposure, and authority
> lifecycle?

R1 keeps Windows/KVM frozen. All active falsification uses only self-owned
ToyDesigner code on local Linux with no public network and no third-party binary
execution.

## Treatments

### V5-R1 — encrypted asset after authorization

Three deterministic release populations are used:

```text
release 1: 4 authorized recipients
release 2: 3 recipients after Alice is revoked
release 3: 4 recipients after one new recipient joins
```

Three key-distribution strategies are compared:

| strategy | key distributions | ciphertext copies | future revoke behavior |
| --- | ---: | ---: | --- |
| shared key reused | 4 | 3 | revoked recipient keeps future access while key is reused |
| shared key rotated each release | 11 | 3 | revoked recipient loses future releases after rotation |
| per-recipient encryption | 11 | 11 | one stolen key cannot decrypt another recipient's ciphertext |

The strong falsifier is information already delivered to an authorized hostile
client. Alice's cached release-1 key remains usable after revocation. If release
2 reuses the same key, she decrypts release 2. Rotating the key prevents that
future access, but requires redistribution to every active recipient.
Per-recipient encryption reduces **cryptographic key blast radius**, but an
authorized recipient still receives plaintext and can redistribute those bytes.

R1 therefore rejects `revocation == take back delivered capability`.

### V6-R1 — signed lease and offline operation

A signed remote entitlement lease is issued and then the account is immediately
revoked at the authority. TTL is swept over `1, 2, 4, 8` logical ticks.

| lease TTL | valid local ticks after immediate revoke | offline window | worst-case revoke lag |
| ---: | --- | ---: | ---: |
| 1 | `[0]` | 1 | 1 |
| 2 | `[0,1]` | 2 | 2 |
| 4 | `[0,1,2,3]` | 4 | 4 |
| 8 | `[0..7]` | 8 | 8 |

All four treatments satisfy:

```text
offline survivability == worst-case stale-authority window
```

Fresh lease issuance fails immediately after server-side revocation. Existing
leases remain valid locally until expiry. A persisted lease survives a process
restart until expiry; a memory-only cache intentionally does not. An unbound
lease replays in the second-client treatment. A signed semantic client binding
blocks the mismatched-binding treatment, but this is **not** claimed as
hostile-host hardware binding.

Most importantly, the premium implementation is still local. A hostile client
that deletes local policy can still invoke it. V6-R1 therefore improves
licensing governance and availability semantics without changing V6 into V8.

### V8-R1 — remote capability lifecycle

The protected implementation remains outside the client. One treatment sends a
canonical 4144-byte request body to the external capability.

Observed results:

- the exact signed result remains independently verifiable after service outage;
- the cached result does not apply to a changed request body;
- a new unique job cannot be computed while the service is unavailable;
- a newly rotated service key is rejected by the old pinned authority key;
- the old receipt is not verifiable using only the new authority key;
- historical verification therefore requires old authority identity retention;
- server-side revocation denies the next new capability request immediately;
- revocation does not invalidate a result that was already delivered;
- replacing the full payload with only its digest changes the input and does not
  reproduce the full-input capability result in this target.

V8 therefore removes local implementation extraction but creates live service,
input-disclosure, trust-anchor rotation and provenance obligations.

## Acceptance gates

The R1 runner exposes **26 structural gates**. Current clean treatment passes
`26/26`, including explicit gates for:

- prospective-not-retrospective V5 revocation;
- key rotation and per-recipient leak scope;
- V6 offline/revocation-lag equality across four TTLs;
- outage and replay/binding treatments;
- V6 local-capability persistence;
- V8 exact-cache applicability, outage, authority rotation and immediate future
  revocation;
- delivered-result irreversibility;
- no Windows/KVM, public-network, or third-party-binary consumption.

Reproduction entry:

```text
research/ca-lic/toydesigner/run_r1.sh
```

Detailed measurements are retained in
`research/ca-lic/toydesigner/R1_MEASUREMENTS.md`.

## Real-system cross-check

R1 separately records only vendor-documented observations in
`research/ca-lic/AUTHORITY-TOPOLOGY-OBSERVATIONS-R1.md` and the matching
machine-readable matrix. No named third-party system is actively tested.

The cross-check covers TouchDesigner, JetBrains License Vault, Adobe desktop
licensing, iLok, Denuvo Anti-Piracy/Anti-Tamper, Apple Secure Enclave/App Attest,
and AWS KMS.

The important convergence is structural:

- TouchDesigner/iLok/Denuvo show that authorization carriers, hardware binding
  or anti-tamper can move/strengthen authority without making the protected
  application a remote capability;
- JetBrains and Adobe expose bounded-offline entitlement semantics that match
  the V6 lease trade;
- Secure Enclave and AWS KMS keep a necessary secret/operation outside ordinary
  client memory, matching the qualitative V7/V8 boundary change.

## Candidate invariants

These remain research candidates rather than universal Security constitution.

### C1 — Delivered-information irreversibility

Once decryptability, plaintext, or a reusable result has been delivered to a
hostile recipient, later entitlement revocation cannot make those delivered
bytes unknown again. Revocation controls **future authority**, not past
information release.

### C2 — Offline/revocation duality for local leases

For a locally verifiable entitlement lease with offline lifetime `T`, a client
revoked immediately after issuance can retain stale local authority for up to
`T` unless a fresh external operation is required. Reducing that stale window
also reduces offline survivability.

### C3 — Carrier externalization != capability externalization

A dongle, cloud session, signed token or remote yes/no server can change the
credential/authorization attack surface while leaving the valuable capability
locally present. This is structurally weaker than requiring an external
operation for every new protected computation.

### C4 — External authority creates identity continuity

Signed external results introduce authority-key/version lifecycle. Rotation
requires a new trust decision; historical verification may require preserving
old authority identity even after current authority moves forward.

### C5 — External capability shifts rather than deletes cost

V8 trades local extraction risk for service availability, request/input
exposure, provider/key lifecycle, operational cost, and result provenance.
There is no topology that dominates every objective.

## Architecture disposition

R1 does **not** admit a licensing SDK, DRM service, lease framework, token cache,
key-rotation subsystem, dongle abstraction, SaaS gateway, or generic authority
manager into Security core.

The experiment earns a better decision model:

```text
Choose authority topology by asking:

what must never be delivered?
what may be cached?
how much offline time is required?
how quickly must revoke converge?
what input may leave the client?
what completed outputs remain valuable after revoke?
how is authority identity rotated and historically verified?
```

Only an ordinary Ordivon consumer with a real protected capability can justify
productizing any of these mechanics.

## Next frontier

- V5-R2 only if attribution/fingerprinting or multi-party redistribution becomes
  a real decision variable; secrecy alone is already bounded by plaintext delivery.
- V6-R2 only if a real consumer needs hardware-backed client binding or a
  specific disconnected-authority policy.
- V8-R2 should be driven by a real owned remote capability and then measure
  redundancy, privacy minimization, provider migration and result provenance.
- Windows/KVM remains frozen until a hypothesis cannot be answered in the
  self-owned Linux lab.
