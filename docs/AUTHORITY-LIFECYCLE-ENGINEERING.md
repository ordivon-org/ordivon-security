---
schema_version: 1
id: security.authority-lifecycle-engineering
title: Authority Lifecycle Engineering
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-15
summary: Engineering disposition for applying CA-LIC authority-topology and revocation research to Security without importing a generic entitlement subsystem: exact grant snapshots, digest-bound admission history, prospective authority change, delivered-information irreversibility, and external-authority identity continuity.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.client-authority-entitlement-ca-lic
  - security.client-authority-entitlement-ca-lic-r1
  - security.range-session-s0
  - security.evaluation-trial-p0
  - security.architecture
  - security.authority
---
# Authority Lifecycle Engineering

## Decision

CA-LIC does not justify adding a license server, lease manager, token cache, entitlement database, hardware-carrier abstraction, or generic remote-authority service to Security.

It changes how existing Security authority must be interpreted and projected:

```text
current grant snapshot
  != permanent capability
  != past admission
  != executor receipt
  != already delivered information/result
```

The smallest engineering response is to keep authority exact and owner-native, make the exact authority identity easy to inspect, preserve the authority digest that admitted each effect, and refuse to pretend later authority changes rewrite past facts.

## Existing structures that already fit the research

### `RangeSessionSpec` freezes one grant snapshot

A `RangeSessionSpec` contains exact `RangeAuthority` values. A running `RangeSession` admits effects against that frozen specification. Each `RangeEffectAdmission` already carries the exact `authorityDigest` used for the decision.

Security currently has no implicit dynamic grant refresh and therefore no hidden locally cached lease semantics. If a future persistent-world consumer requires grants to change while the same world continues, that must be designed as an explicit new authority revision/current-authority mechanism rather than by mutating the old object in place.

The ordinary inspection projection now floats the frozen bindings explicitly as `authorityId + revision + authorityDigest`. This improves Agent/human navigation without creating new authority.

### `EvaluationSpec` is already exact and prospective

`EvaluationSpec` embeds one `AuthorityManifest`, exact Sample identity, environment identity, Guardian policy and requested action set. A later operator decision must create a new specification/authority revision; it does not mutate historical Evaluation evidence.

### Evidence preserves history instead of current permission

Contest/Evaluation evidence bundles record what authority, execution and world observations existed for one run. CA-LIC R1 strengthens the engineering rule: revoking future authority must not rewrite, delete, or reinterpret valid historical admissions/results as if they never occurred.

Security may limit future actions, destroy an owned disposable world, or record that a credential/grant is no longer current. It cannot make already delivered bytes, receipts, observations, or effects unknown again.

## Engineering constraints promoted from CA-LIC

### E1 — Admission binds an exact authority snapshot

Every consequential Security admission should be attributable to an exact grant identity/digest. A human-readable revision label helps navigation; the digest is the exact identity.

### E2 — Authority change is prospective

A future authority revision can change whether a new effect is admitted. It does not retroactively change the admission fact for a request already decided under an earlier exact authority.

If future dynamic authority is introduced, request identity must not silently replay across a changed authority epoch. The design must specify whether request identity commits an expected authority digest or whether a new request identity is mandatory.

### E3 — Offline/local authority spends freshness

Security should not add TTL/lease semantics by default. If a future consumer needs locally verifiable authority while disconnected, the design must state the maximum stale-authority/revocation window created by that choice. Offline support is an authority property, not merely UX metadata.

### E4 — External carrier is not external capability

An external token, hardware carrier, signed response or remote yes/no decision must not be described as if it externalizes the protected Security capability. Only a required external operation/capability changes that trust boundary.

### E5 — External authority creates identity continuity

If Security later consumes signed results from a remote/hardware authority, the producer identity/key/version belongs in execution/evidence identity. Rotation must preserve enough historical identity to verify retained evidence. This does not justify a global Security key manager today.

## Evidence-verifier hardening found during this audit

The engineering audit found a separate defect in Contest and Evaluation evidence verification. Manifest-owned relative paths were previously joined directly to the supplied bundle root. A crafted manifest could point a channel/artifact/operational path outside the bundle or through a symlink and make the verifier read that file while attempting verification.

The implementation now uses one internal fail-closed path resolver:

- root must be a real directory, not a symlink;
- manifest path must be relative and contain no parent traversal;
- no path component may be a symbolic link;
- the resolved regular file must remain under the exact bundle root.

Evaluation evidence sealing also rejects a symlink output root and handles an existing non-directory explicitly.

The same research principle applies: a path string in an untrusted manifest is a claim, not filesystem authority.

## Explicit non-promotions

This round deliberately does not create dynamic `RangeAuthority` mutation, a central revocation registry, Security-owned wall-clock leases/TTL, remote entitlement polling, generic hardware attestation, generic capability proxying, a Security key-rotation service, or retroactive deletion of admissions/evidence after revoke.

Each would require a concrete owned consumer with a failure that the current exact-spec model cannot represent.

## Reopen conditions

Reopen authority-lifecycle engineering only when at least one real Security consumer requires one of these behaviors:

1. authority must change while one persistent world/session continues;
2. a client/Actor must operate disconnected under cached authority;
3. a non-exportable hardware authority is required for a real effect;
4. a protected capability must execute remotely rather than locally;
5. externally signed Security results require key/provider migration while old evidence remains independently verifiable.

Until then, exact immutable grant snapshots plus digest-bound historical admission are the smaller and safer engineering model.

Exact acceptance evidence: [`../evidence/acceptance/security-authority-lifecycle-engineering-1b49f14.json`](../evidence/acceptance/security-authority-lifecycle-engineering-1b49f14.json).
