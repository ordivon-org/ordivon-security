---
schema_version: 1
id: security.client-authority-entitlement-ca-lic
title: Client Authority & Software Entitlement CA-LIC
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-15
summary: Canonical CA-LIC research authority separating credential forgery, local enforcement, protected-asset placement, remote entitlement, external primitive authority, and remote capability through the self-owned ToyDesigner V0-V8 ladder.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security
related:
  - security.authority
  - security.research-boundary
  - security.research-agenda
---
# Client Authority & Software Entitlement CA-LIC

## Question

When valuable capability is delivered to a client controlled by the other party, what authority does the vendor still possess after delivery?

CA-LIC treats this as an authority-topology problem, not a license-file problem. The core distinctions are:

```text
credential forgery resistance
!= local enforcement tamper resistance
!= protected-asset secrecy
!= external authority
!= remote capability
```

The retained five-layer decomposition is:

```text
L0 entitlement representation
L1 entitlement verification
L2 local enforcement
L3 asset protection / materialization
L4 external authority / capability
```

## Research boundary

The accepted executable target is **ToyDesigner**, a self-owned licensing target under `research/ca-lic/toydesigner/`. Third-party software may provide public or sanitized observational evidence, but third-party entitlement bypass mechanics are not a reusable Security capability and are not part of the ordinary Agent surface.

This round intentionally performs no Windows/KVM work, no unknown-sample execution, no third-party installer execution, and no physical dongle/TPM claim. V7 uses an ephemeral external-authority process only as a **hardware-shaped semantic simulator**; it does not prove hostile-host resistance of real hardware.

## V0-V3 — local authority ladder

The first ladder established:

| Version | Added defense | Result |
| --- | --- | --- |
| V0 | plain local tier | credential semantics can be changed directly |
| V1 | signed credential | forgery is blocked; local verifier/gate remains removable |
| V2 | client-reported machine binding | naive copying is blocked; self-reported anchor remains locally forgeable |
| V3 | scattered enforcement | attack cost grows with gate surface; trust domain does not change |

Baseline: 15 feature/tier checks pass before attacks. The experiment does not interpret Python monkeypatch LOC as real binary cracking effort; only relative structural cost is claimed.

## V4-V8 — authority-topology ladder

The second ladder changes one structural variable at a time. Its clean defense baseline passes **10/10** checks.

| Version | Authority shape | Falsifier / attack result | Boundary result |
| --- | --- | --- | --- |
| V4 | signed local integrity manifest | tamper is detected, then one local enforcement patch allows the locally shipped premium module to run | unchanged |
| V5 | encrypted shipped asset; key absent for free tier | patching the free verifier cannot recover a missing content key; an authorized Pro client can decrypt and can also extract the delivered key | partial |
| V6 | signed remote entitlement response + nonce; premium implementation still local | authentic remote `DENY` is preserved, but removing the local decision lets the shipped premium implementation run | unchanged for capability protection |
| V7 | external authority performs a required signed primitive | a local fake cannot produce an independently verifiable ticket; entitled external primitive succeeds | changed for that primitive |
| V8 | protected premium capability executes externally | a local fake can imitate UI/result shape but cannot produce a valid service-authoritative result | changed |

Exact acceptance evidence: [`../evidence/acceptance/ca-lic-v0-v8-1e0033f.json`](../evidence/acceptance/ca-lic-v0-v8-1e0033f.json).

The V6/V8 contrast is the strongest result of this round:

```text
remote license server says "yes/no"
!=
remote system actually performs the protected capability
```

## Hypothesis disposition

### H1 — Same-artifact exposure

**Supported with a boundary qualification.** V1-V4 and V6 retain the premium implementation inside the hostile client trust domain; local defense raises cost without removing the implementation. V5 weakens same-artifact exposure because plaintext is absent until a key is delivered. V8 removes the protected implementation from the client entirely.

### H2 — Local authority collapse

**Supported.** V1, V3, V4 and V6 all show a local client can delete or replace a local decision without forging the vendor/server credential that originally informed the decision.

### H3 — Externalized authority

**Supported semantically, not yet physically.** V7 and V8 require an externally produced, independently verifiable result. A local UI patch is insufficient. The experiment proves the contract/topology distinction; real TPM/dongle/TEE/cloud-host resistance remains a separate physical question.

### H4 — Remote does not mean solved

**Supported.** V6 uses a fresh nonce and a signed remote denial. Replay/forgery resistance improves, but the premium implementation is still locally callable after local enforcement is removed. V8 is materially different because the capability itself is external.

### H5 — Security is economic

**Supported as a model, not reduced to one scalar.** The ladder shows several qualitatively different costs: more local patch sites, key acquisition, external availability, service operation, authorized-recipient leakage, and dependency on an external trust domain. A single "hardness" number would erase these trade-offs.

## Stable model

The current compact model is:

```text
Protection strength for capability X depends on:

1. Is X's implementation shipped?
2. Is a secret required to materialize X?
3. Must that secret enter the hostile client?
4. Is entitlement merely an answer, or does external authority perform work?
5. Can an independent verifier distinguish a real result from a local fake?
6. What availability, latency, privacy, operational and authorized-recipient costs are introduced?
```

This is more predictive than classifying schemes only as `signed`, `machine-bound`, `dongle`, or `online`.

## Publication and disclosure boundary

CA-LIC has three truth roles:

1. **ToyDesigner experimental evidence** — reproducible and publishable as self-owned code.
2. **sanitized third-party observation** — may motivate hypotheses, but does not grant reusable bypass authority.
3. **stable law/candidate** — implementation-independent claims promoted only when multiple treatments support them.

The current Git tree is the publication surface. Current-tree redaction is **not** equivalent to erasing earlier Git objects. This round does not rewrite repository history. If historical erasure is ever required, it must be a separate operator-visible repository migration with remote/clone consequences explicitly considered.

Exact third-party patch offsets, executable payloads, private keys, unknown binaries, and private run material are not canonical CA-LIC publication artifacts.

## Product disposition

CA-LIC remains `research-apparatus`. It is intentionally visible in the full Security surface for provenance but excluded from `security_ordinary_surface_manifest()`. No licensing SDK, DRM framework, generic anti-tamper library, dongle abstraction, or entitlement gateway is admitted.

Reopen productization only when an ordinary Ordivon consumer needs to protect a real capability and can state which authority topology it requires.

## Next questions

- Repeat V5 with multiple authorized recipients and revocation/update churn.
- Compare V6 availability/offline semantics against V8 availability/privacy/latency cost.
- Add a real external hardware/cloud experiment only when an owned consumer requires physical proof.
- Build a cross-system observational matrix at the level of authority placement, without importing third-party bypass procedures.
