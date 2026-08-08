---
schema_version: 1
id: security.multiple-successors-c1f
title: Multiple Successors and Recovery Lineage C1-F
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - evaluator
  - agent
updated: 2026-08-08
summary: Physical proof that two successor candidates over the same dead-owner S6 generation are mutually excluded by the existing recovery gate, that the losing successor can later re-observe and adopt the winner's newer world generation without replaying the effect, and that repeated succession requires durable predecessor-claim lineage rather than one overwrite-only current claim.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.successor-ownership-c1e
  - security.fresh-controller-continuation-c1d
  - security.law-profiles-c0
---
# Multiple Successors and Recovery Lineage C1-F

## Question

C1-E proved that one successor continuation controller and one orphan reconciler cannot safely mutate the same dead-owner world concurrently. The accepted single-host mechanism made them share one exact per-Run recovery gate.

C1-F asks the next narrower question:

> If two successor candidates observe the same exact dead-owner generation, can exactly one act, can the loser later inherit the winner's newer world without replaying the old effect, and what durable provenance becomes unavoidable after more than one succession?

The experiment deliberately does not add fairness, election priority, a generation counter, a wall-clock lease, distributed consensus, or a generic workflow.

## Physical setup

The old controller is killed at the already accepted root-veth partial-materialization point:

```text
topologyPhase = peer-a-removed
QEMU / swtpm / capture = alive
peer-B namespace       = present
q/w veths              = Host-root veths
peer B                 = not yet materialized
```

Two independent successor processes, A and B, both read the same exact ledger generation and are then released to claim recovery authority.

## Initial competition: exclusion already works

In the accepted fixed run both candidates observed:

```text
initial ledger digest
= sha256:af27ac84d9f52f953ca7c9114086020e15ea50fe88014140f7f67a571253749f
```

Successor B acquired the recovery gate and exact-generation claim:

```text
claimId = recovery-claim:55d73a44c2622606e159a539
```

Successor A returned `lost-authority`.

Independent Host truth before and after the competition was identical. The loser did not move a veth, change a namespace, terminate a process, or otherwise mutate the Range.

This means C1-E's single-host arbitration did not require an additional election protocol merely because a second successor appeared:

```text
same generation
+ two contenders
+ one per-Run recovery gate
→ exactly one physical recovery mutator
```

The experiment does **not** claim fairness. Which contender wins is not currently part of the law.

## The winner advances the world generation

Successor B then continued the exact missing suffix and independently established peer B:

```text
topologyPhase      = peer-b-present
currentPeerAddress = 10.253.70.4
```

The durable ledger changed from the initial digest to:

```text
sha256:11cb6ae67e46496a42244787b5222c84f39f15a320e6c735ba215274a2866e71
```

The semantic effect identity remained the same. The changed digest represents a newer physical/durable world generation, not a new requested effect.

## The winner dies; the loser must not replay the past

Successor B is then killed with `SIGKILL` while it still owns recovery authority. The kernel releases the gate automatically.

Successor A does **not** retry using its old initial digest. It re-reads the current durable world, obtains the new digest above, and claims against that exact generation.

A then observes the already materialized peer-B topology:

```text
QEMU       alive
swtpm      alive
capture    alive
fabric ns  present
peer-B ns  present
q/w        placed inside their target namespaces
bridge     TAP + peer-B fabric veth
peer addr  10.253.70.4/24
root q/w   absent
```

By the time A observes it, the one-shot peer-B challenge server may already have exited because the Windows Guest consumed it. That does not undo the persistent consequence.

C1-F therefore distinguishes:

```text
persistent consequence topology
!=
transient challenge-service liveness
```

A returns:

```text
status                    = adopted-existing-effect
wholeEffectReplayAttempted = false
physicalMutationAttempted  = false
```

This is the important succession result:

> **A losing successor can later inherit a newer world by re-observing current truth and current generation, rather than replaying the action it originally wanted to perform.**

## Baseline falsifier: overwrite-only claim metadata loses succession history

Before the lineage fix, the physical exclusion and retry behavior already worked.

Baseline revision:

```text
git:c9d98a1ca6bffb7058b2fbfe53b5aa57aace5d0a
```

Its receipt had 13 of 14 substantive gates true. The only false gate was:

```text
firstSuccessorClaimLineagePreserved = false
```

Why?

C1-E had one current claim file:

```text
recovery-claims/<run>.json
```

When successor A later acquired authority, it overwrote successor B's stale claim. The physical mutex remained correct, but the durable recovery substrate could no longer answer:

```text
Who held recovery authority immediately before A?
Which exact claim did A inherit from?
```

The original owner identity was still preserved, but the **successor-to-successor history** had disappeared.

That is the C1-F falsifier:

> **Original-owner provenance is not sufficient once recovery authority itself can pass through multiple successor generations.**

## Minimal lineage mechanism

The accepted fix is revision:

```text
git:511f08fc74ba4590941683b6d0e62fc7c45815c7
```

It does not change the kernel mutex.

Before a new successor replaces the current claim while holding the same recovery gate, Security now archives the exact previous claim as one immutable record:

```text
recovery-claims/history/<run>/<claim-id>.json
```

The new current claim records only one backward edge:

```text
predecessorClaimId
predecessorClaimDigest
```

Thus repeated succession can form:

```text
current C
  │ predecessorClaimId
  ▼
archived B
  │ predecessorClaimId
  ▼
archived A
```

without copying the entire history into every new claim.

The current claim remains the live durable declaration. Archived claims are provenance only. Neither grants physical mutation authority; the per-Run kernel gate still does that.

## Fixed physical acceptance

In the final run:

```text
winner B claim
= recovery-claim:55d73a44c2622606e159a539

retry A claim
= recovery-claim:e9646d7b13b85c16e0e19e04
```

A's claim points directly to B:

```text
predecessorClaimId
= recovery-claim:55d73a44c2622606e159a539

predecessorClaimDigest
= sha256:8c0b7bb69f234b1c9bdb7dcbc87545f5d0601b5c549ad515ef4f6767d7e2e64d
```

The archived record for B exists with the exact matching claim identity and digest.

After A is also killed, the final reconciler obtains the recovery gate and records both:

```text
successorClaimObserved
= current A claim

successorClaimHistoryObserved
= [archived B claim]
```

Only after clean world closure does it remove the current claim and archived history metadata.

Final independent truth:

```text
QEMU       absent
swtpm      absent
peer       absent
capture    absent
namespaces []
root links []
ledger     absent
claim      absent
history    absent
```

No experiment cleanup action was needed.

## What C1-F proves

For this exact single-host S6 world and fault path, C1-F proves:

- two successor candidates may start from the same exact dead-owner generation without both gaining physical mutation authority;
- the loser can fail to acquire authority without mutating the world;
- no priority or fairness policy is required merely to guarantee exclusivity;
- a successful successor can advance the durable world to a new ledger generation while retaining the same semantic effect identity;
- after the winner dies, the loser can re-read the newer generation and acquire recovery authority against that generation;
- a successor may recognize that the consequence already exists and adopt it without replaying the whole effect or performing another physical mutation;
- persistent consequence state must not be conflated with transient helper/service liveness;
- an overwrite-only current successor claim is insufficient after multiple succession events because it erases successor-to-successor provenance;
- one-hop `predecessorClaimId`/digest plus append-only exact archived claim records is sufficient for the tested succession chain;
- final reconciliation can preserve the entire tested recovery lineage in its closure receipt and then clear recovery metadata;
- the existing per-Run `flock` remains sufficient for physical exclusion in the tested single-host universe;
- no generic election service, priority policy, wall-clock lease, consensus protocol, transaction log, or causal DAG was forced.

A useful relation is now:

```text
semantic effect identity
+
current world truth
+
current ledger generation
+
exclusive recovery authority
+
recovery-claim lineage
→ successor can inherit consequence without rewriting history
```

## What C1-F does not prove

C1-F does not prove:

- fairness between competing successors;
- deterministic winner selection;
- three or more physical successor generations, although the stored lineage shape can represent them;
- safe successor handoff while the current successor remains alive;
- recovery if a successor dies **midway through its own continuation suffix**;
- arbitrary partial states beyond the tested root-veth start and stable peer-B adoption;
- multi-host ownership, fencing, quorum, or partition recovery;
- generic exactly-once execution;
- generic shared-resource concurrency;
- a universal claim-history schema for all Ordivon domains;
- generic `RangeEvent.causalParents` enforcement;
- external or uncontrolled target authority.

## Resulting pressure

The strongest next experiment is not a third stable successor merely to lengthen the chain.

It is:

> **Kill the winning successor during its own continuation, after it has changed the world but before it publishes the stable target generation; then require another successor to reconstruct the new partial world and continue from there.**

That experiment would combine C1-C/D's world-state-as-progress result with C1-E/F's successor authority and lineage across **multiple recovery generations**.

Do not add durable substep state first. Let a successor-to-successor mid-effect crash reveal whether world truth + exact resource identity + claim lineage still suffice.
