---
schema_version: 1
id: security.evidence-freshness-ec1
title: Evidence Freshness EC1
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-09
summary: Physical source-evolution experiment separating derived-evidence integrity from current applicability and showing exact derivation-dependency identity is sufficient for the tested consumer without TTL, clocks, generation freshness, or a new freshness service.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.evidence-computation-ec0
  - security.adversarial-epistemics-ae3c
  - security.research-agenda
---
# Evidence Freshness EC1

## Question

EC0 established exact computation identity but left one real problem open:

> What happens when an old derived fact remains intact while the authoritative evidence it depended on advances?

The naive answer is to introduce timestamps, TTLs, leases, source generations, or a generic Freshness service. EC1 tests a smaller rule first:

```text
projection integrity
!=
projection current applicability
```

For the AE3-C projection, the exact derivation dependencies are already explicit:

```text
historyDigest
currentSensorSetDigest
```

EC1 asks whether comparing those exact identities to the currently authoritative source is enough.

## Apparatus

EC1 remains research apparatus. It adds no Security core type and no model call.

```text
research/experiments/ec1-derived-evidence-freshness/
  applicability.py
  current-source.json
  projection-v1.json
  projection-v2.json
```

`applicability.py` is pure Python standard library. Its SHA-256 is:

```text
sha256:cbd1ae65bbbee726dad43c8e9b6b03f340354d0ef240ebd6c9b0392670eb0bcc
```

It classifies only four states:

```text
APPLICABLE
STALE_NOT_APPLICABLE
UNKNOWN
INVALID
```

The rule revision is:

```text
ec1-exact-derivation-dependency-applicability-v1
```

The rule does not consult wall-clock time, TTL, source age, source-envelope digest, Git generation, Runtime Workspace digest, or a confidence score.

## Retained projection identity

`projection-v1.json` is not a rewritten copy. Its complete file bytes are exactly the retained EC0 A Runtime stdout bytes:

```text
file SHA-256
sha256:e72a7c67a942b304ba828549ff45c7b237f64ca44b786a87e52183397876d675

projectionDigest
sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b

history dependency
sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635

sensor dependency
sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053
```

Later `projection-v2.json` is likewise the exact retained EC0 B Runtime stdout bytes:

```text
file SHA-256
sha256:62e2557343b74695942f83c02231b74277c16ff26efb6d85b4929b284669c240

projectionDigest
sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1

history dependency
sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83

sensor dependency
sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053
```

Thus the stale object remains the same accepted derived bytes while only the current authoritative source changes.

## Phase 1 — initial authoritative source

Commit:

```text
7858ff6e0dd7ee3ce4540e0ba30312d2a38f6877
```

The current source publishes generation 1 with A-history and the accepted sensor set:

```text
source file SHA-256
sha256:323f85257f1ff2d7a1269b81000513a482a8c62f5e0987bd6211679e3def4346

source envelope digest
sha256:f3ba0ad8a09ac804ff0f692d471e099e067fc8ba226776c00fb903120cd73f0a

history
sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635

sensors
sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053
```

Runtime `contained_local` Job:

```text
jobId
job-019fe56f-0f41-7bb3-a3dc-8e0216b5effc

attemptId
attempt-019fe56f-0f41-7bb3-a3dc-8e178e02cd6d

workspaceSourceDigest
sha256:f2d64e6a98bfd6a49e71160b9bd1dd6a8415aabb6db310a02b5e77d20a12f7df

executionPlanDigest
sha256:18af45cf284829cad107298983111f5754ea887bd4a0dbf30a989a9f24256684

stdout
sha256:116d3f09a7337c6cf05f231877cb40c957dc6c3635567818402c327c35006596
```

Result:

```text
projection-v1 → APPLICABLE
```

## Phase 2 — metadata-only source advance

Commit:

```text
257cfc12b77534e932afcbc6c399ac40aee8741d
```

The same authority republishes the source as generation 2. The source envelope changes:

```text
old envelope
sha256:f3ba0ad8a09ac804ff0f692d471e099e067fc8ba226776c00fb903120cd73f0a

new envelope
sha256:5f4c073f74e416662cbb30afc4c9d51ed1fb640d1bf4a8c715b24349d677c726
```

The file SHA-256 becomes:

```text
sha256:28f5f7e9b718e1016e515827d8fc16d686a93e24e726ce8d207b190d7f2acc6c
```

But the derivation dependencies remain byte-identical:

```text
history unchanged = true
sensors unchanged = true
```

Runtime Job:

```text
jobId
job-019fe56f-e0d1-75b2-863e-e9a38617cae8

attemptId
attempt-019fe56f-e0d1-75b2-863e-e9b0bb760297

workspaceSourceDigest
sha256:087c72e828c239cf1f4a191eea85972eab90323980d9c6b382772e7ba5dcac64

executionPlanDigest
sha256:91058c5ad16cf305c821cf85bc17e9ffb4f3d879351dae52eff6a70c041785a0

stdout
sha256:62ab25cfaf3128a0534c64336abb1f4d891cd0e3ad9621969909c097eee09996
```

Result:

```text
projection-v1 → APPLICABLE
```

This is the key falsifier for generation-based freshness:

```text
newer publication != old derivation stale
```

A source can advance operationally without changing the facts on which a particular derivation depends.

## Phase 3 — semantic dependency advance

Commit:

```text
741ff041bb16168a338f7628663ebc481f004816
```

The same authority advances to generation 3. The current sensor set stays exactly the same, but history changes from A to B:

```text
old history
sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635

new history
sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83

sensor set unchanged
sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053

source envelope
sha256:89d145954aee933493ec816389a318dd0a9369a0801b08da5487992211beaa9e

source file SHA-256
sha256:ab830256caa2ffe4022addd43caa9b92ca28152a9a195499ceb075a95adfa923
```

The old projection is still internally integrity-valid. Its own projection digest and complete bytes are unchanged. But its history dependency no longer equals current authority.

### Old projection against current source

```text
jobId
job-019fe571-0507-7b33-ac22-0cd346c34c07

attemptId
attempt-019fe571-0507-7b33-ac22-0ce0cbcb0f4c

workspaceSourceDigest
sha256:a59c17eb18d4fe706e3efbf0855e66136c3bf9213268d8ba00eeec7373049599

executionPlanDigest
sha256:451fee88595edbcf799c96ae2dfa6769b73a23ccbf428ef0bcd450288c3bcb7a

stdout
sha256:57ae6f2db2f8b18bcc88a6fdfee4c3255c415ac167976af3b6c70e6303d8e80b
```

Result:

```text
projectionIntegrity = valid
history dependency match = false
sensor dependency match = true
applicability = STALE_NOT_APPLICABLE
```

### New projection against current source

```text
jobId
job-019fe571-2f09-7dd2-8943-31686ecc8ad4

attemptId
attempt-019fe571-2f09-7dd2-8943-317568d33ea8

executionPlanDigest
sha256:81eb191627d28ec5902f19b628d208953f1061ee486432226ac93b81558e3c56

stdout
sha256:5dd5091498fd15acbdd9d56982f2394893d53141ac36498f07924654de47b475
```

Result:

```text
projection-v2 → APPLICABLE
```

### Current authority unavailable

```text
jobId
job-019fe571-67d3-78a2-b1f9-28e6b7d3050a

attemptId
attempt-019fe571-67d3-78a2-b1f9-28fa5913e802

executionPlanDigest
sha256:2df37b6713c99d8898a186301e2d329d5b24151d7570cfc6b96acb094d689bc8

stdout
sha256:cab79764272a8c026b22615663b1c507372c3ff7a5d8a0f37d8ee526070bbfdb
```

Result:

```text
projectionIntegrity = valid
current authority = unavailable
applicability = UNKNOWN
```

The checker does not infer stale or fresh from age when current authority cannot be observed.

## Fresh Workspace / process replacement

A new detached Runtime Workspace was opened directly from phase-3 commit `741ff041bb16168a338f7628663ebc481f004816`:

```text
workspaceId
security-ec1-fresh-recovery-20260809

workspace sourceStateDigest
sha256:5aa32919ad50b9d32228cf3ad8d918725a4087cdf98dcabf2674e60f47c1ca57
```

One new `contained_local` process, without old Python objects or old Job state, recomputed all three classifications:

```text
old projection → STALE_NOT_APPLICABLE
new projection → APPLICABLE
authority unavailable → UNKNOWN
```

Runtime Job:

```text
jobId
job-019fe571-dcdf-7240-95de-ae65f7e5407e

attemptId
attempt-019fe571-dcdf-7240-95de-ae7ae8044c84

executionPlanDigest
sha256:5d66c6f153030db2c28cd7a5a28bfc57880d9f30702db9aa2f7f1575a843d1e9

stdout
sha256:b2b498e2c6fd28ec5143bd746dc155e0fbb44ff3b0dc1b636c59763b64b010c9

terminal evidence
sha256:af757fa890a34f03915c778671df944dd5664ee8fbbac66fa97c0c652a71ecad
```

No durable freshness database or process-local generation cache is required for this consumer.

## Runtime physical source identity is not domain applicability identity

The evolving EC1 Workspace and the fresh recovery Workspace expose another useful distinction. Runtime correctly binds complete physical Workspace source state, but its source-state digest is broader than this domain derivation's semantic dependency set.

Phase 3 in the evolved Workspace binds:

```text
sha256:a59c17eb18d4fe706e3efbf0855e66136c3bf9213268d8ba00eeec7373049599
```

The fresh Workspace at the same Git HEAD binds:

```text
sha256:5aa32919ad50b9d32228cf3ad8d918725a4087cdf98dcabf2674e60f47c1ca57
```

Both correctly classify the same committed projection/source pair. Therefore:

```text
Runtime physical source-state identity
!=
domain derivation applicability identity
```

Runtime's digest remains essential physical execution evidence. Security must not reinterpret it as a domain freshness clock.

## Result

EC1 accepts these scoped claims:

1. an integrity-valid derived projection can become not applicable after one of its exact authoritative dependencies advances;
2. a newer source generation or different whole-source envelope does not by itself make a derivation stale when its exact dependencies remain unchanged;
3. exact dependency equality is sufficient to classify the tested AE3-C projection as currently applicable;
4. exact dependency mismatch is sufficient to classify the retained old projection as stale/not applicable;
5. absence of current authoritative dependency identity yields `UNKNOWN`, not guessed freshness;
6. the classification survives complete process and Workspace replacement;
7. no clock, timestamp, TTL, lease, Trust/Reputation state, durable freshness database, or generic Freshness service is forced by this consumer;
8. Runtime physical source-state identity remains a separate execution concern and is not the domain applicability rule.

The strongest current candidate law is:

```text
Integrity proves what evidence is.
Applicability asks whether its declared dependencies are still current.
```

For exact derived evidence whose authoritative dependencies are observable:

```text
integrity valid
+ exact dependency match
→ APPLICABLE

integrity valid
+ exact dependency mismatch
→ STALE_NOT_APPLICABLE

integrity valid
+ current dependency authority unavailable
→ UNKNOWN
```

## What EC1 does not prove

EC1 does not establish a universal freshness protocol. It does not test:

- sources whose semantic dependencies cannot be enumerated;
- partially ordered or multi-authority current state;
- intentionally time-decaying facts where age itself is a semantic dependency;
- probabilistic observations;
- C1-N's private downstream witness where current predicate identity may not be independently observable;
- atomic publication between source change and derivation publication.

Therefore C1-O should not be turned into a generic clock/TTL subsystem. EC1 instead provides the first physical stale-but-integrity-valid consumer and shows that this instance is resolved by exact current-dependency identity. If a later witness consumer lacks such an observable current identity, that absence—not elapsed time alone—is the next structural problem.

## Next research pressure

The AE/EC line has now removed three premature abstractions:

```text
raw history problem
→ not Trust; exact reduction

reducer ownership problem
→ not shared EvidenceReducer; exact computation identity

freshness problem
→ not TTL/generation; exact dependency applicability
```

The next higher-order Security consumer should return to autonomous multi-Agent behavior rather than continue inventing evidence infrastructure. A strong next pressure is autonomous communication and coordination/collusion under the already-established claim/truth/UNKNOWN/effect boundaries. Only repeated strategic interactions should force new social state such as Trust, Reputation, coalition, or organization.
