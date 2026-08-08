---
schema_version: 1
id: security.mid-successor-recovery-c1g
title: Mid-Successor Recovery C1-G
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
summary: Physical proof that one successor may change the world and die before publishing a new durable ledger generation, so the same ledger digest can refer to different physical progress; a later successor can inherit the same durable generation, re-observe current world truth, preserve recovery lineage, and complete only the missing suffix without durable substep state or whole-effect replay.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.multiple-successors-c1f
  - security.successor-ownership-c1e
  - security.fresh-controller-continuation-c1d
  - security.partial-materialization-c1c
  - security.law-profiles-c0
---
# Mid-Successor Recovery C1-G

## Question

C1-F proved that two successor candidates can share one dead-owner observation, that exactly one gains recovery authority, and that a losing successor can later adopt a newer stable world after the winner dies.

C1-G asks the harder case:

> What if the winning successor dies **during its own continuation**, after it has changed the physical world but before it publishes a new stable durable generation?

The experiment deliberately does not add a durable substep state machine, transaction log, generation counter, causal DAG, or whole-effect replay protocol first.

## Two crashes before completion

The original controller first dies at the accepted C1-C root-veth partial state:

```text
ledger topologyPhase = peer-a-removed
q/w veths            = Host root
peer-B namespace     = present
QEMU / swtpm / sensor = alive
```

A first successor acquires recovery authority against ledger digest:

```text
sha256:c1e7f1b948e7082b1bbdd8f2bcd2cdd1560c2f75966b8fa2071713bf612e653c
```

It then physically executes only part of the continuation:

```text
q → peer-B namespace
w → fabric namespace
w → fabric bridge
```

Before interface-up, address configuration, peer service start, or `peer-b-present` publication, that successor is killed with SIGKILL.

Independent Host observation at the kill point sees:

```text
ledger topologyPhase = peer-a-removed
currentPeerAddress    = null
q root link           = absent
w root link           = absent
q in peer-B namespace = present
w in fabric namespace = present
bridge ports          = Windows TAP + w
peer-B address        = absent
peer-B service        = absent
QEMU / swtpm / sensor = alive
```

## The key falsifier: durable generation did not move

The ledger digest before the first successor mutated the world was:

```text
sha256:c1e7f1b948e7082b1bbdd8f2bcd2cdd1560c2f75966b8fa2071713bf612e653c
```

After the successor had moved both veths, attached the fabric side to the bridge, and died, the ledger digest was still exactly the same.

Therefore:

```text
same durable ledger digest
!=
same physical world progress
```

This corrects an over-strong interpretation of the C1-E/F claim CAS.

The ledger digest is an **exact durable publication fence**. It is not a physical-world version oracle.

## Second successor: same durable generation, different world

After the first successor dies, the kernel releases the recovery gate. A second successor reads the still-unchanged ledger and acquires a new claim against the same digest.

Its claim preserves the previous successor:

```text
first claim
= recovery-claim:55cb73ea51bf5798ad2540e5

second claim
= recovery-claim:36650bca6db73b6c9a523488

second.predecessorClaimId
= recovery-claim:55cb73ea51bf5798ad2540e5
```

The archived first claim remains exact recovery provenance.

Crucially, the second successor does **not** reuse the first successor's old root-veth preflight merely because the durable digest matches. It independently observes the current Host world and classifies the new midpoint.

That observation, not the unchanged ledger, determines the missing suffix.

## World state remains the progress state

From the observed midpoint, the second successor performs only the operations still missing:

```text
raise fabric-side veth
raise peer loopback
raise peer-side veth
assign 10.253.70.4/24
verify no peer default route
verify isolated bridge truth
start peer-B service
verify target topology
publish peer-B process identity
publish peer-b-present
```

It does **not** move q/w again and does not replay the original effect.

The durable ledger then finally advances to:

```text
sha256:76a4ce16c60179ff5c5915bf5095c9667c0eed484f4cc0492a52f56fd5d55f1b
```

with:

```text
topologyPhase      = peer-b-present
currentPeerAddress = 10.253.70.4
```

Thus the stable durable generation moves only when the successor publishes the verified target state; physical progress may legitimately precede that publication.

## Same Guest across two controller deaths

The maintained Windows Guest itself had already consumed peer A before the original controller died.

It remained alive through:

```text
original controller SIGKILL
first successor SIGKILL mid-continuation
second successor recovery
```

and then successfully consumed peer B.

The Guest result retained:

```text
peerAConnected     = true
peerABannerMatched = true
peerBConnected     = true
peerBBannerMatched = true
completed          = true
externalNetworkRequested = false
```

One surviving packet capture observed both A and B flows:

```text
packetLineCount = 16
pcapDigest = sha256:dc85839e393e266ad75e50ff580fbf071ce010de58883e26f0155602585f1f66
```

This is the strongest continuity result in the C1 line so far: the same external consumer crossed two controller deaths while successor lineage and physical consequence remained coherent.

## Final closure

The second successor is then SIGKILLed after publishing the stable target generation. The kernel releases recovery authority.

Final reconciliation records:

```text
successorClaimObserved
= second successor claim

successorClaimHistoryObserved
= [first successor claim]
```

and closes the world with:

```text
QEMU       absent
swtpm      absent
peer       absent
capture    absent
namespaces []
root links []
ledger     absent
```

The experiment cleanup probe finds no residual work.

## What C1-G proves

For this exact single-host S6 fault path, C1-G proves:

- a successor can physically advance a consequence and die before any new stable durable ledger publication;
- the exact same ledger digest can therefore coexist with materially different physical world states at different times;
- claim CAS over `ledgerDigest` fences durable identity/publication state, not physical progress;
- obtaining recovery authority does not make a prior world observation current;
- a successor must re-observe world truth after obtaining authority before selecting a recovery mutation;
- the next successor can acquire against the same durable digest, preserve predecessor claim lineage, classify the changed physical midpoint, and execute only the missing suffix;
- recovery lineage remains valid even when two consecutive successor claims bind the same durable ledger digest;
- world state remains sufficient progress state for this tested midpoint without durable substep state;
- the same Guest can survive two controller deaths and complete the same admitted consequence;
- no whole-effect replay, generic transaction log, generation counter, or causal DAG was forced.

A more precise relation is now:

```text
exact durable identity fence
+
exclusive recovery authority
+
post-acquisition world observation
+
resource identity
+
recovery lineage
→ select recovery action from current reality
```

not:

```text
ledger digest
→ infer physical progress
```

## What C1-G does not prove

C1-G does not prove:

- that every physical partial state is directly observable;
- recovery from effects whose important progress is ephemeral or externally consumed rather than persistently materialized;
- safe recovery if the second successor also dies midway through its suffix;
- generic idempotency across arbitrary effects;
- complete post-hoc reconstruction of every physical handoff solely from production claim metadata after the world has been destroyed;
- multi-host fencing, partitions, quorum, or distributed leases;
- generic shared-resource concurrency;
- generic exactly-once semantics;
- generic `RangeEvent.causalParents` enforcement;
- external or uncontrolled target authority.

The acceptance receipt records the midpoint observation as experimental evidence, but C1-G does not promote that full snapshot into a universal durable recovery record.

## Resulting pressure

The next useful experiment should attack the remaining assumption behind world-state-as-progress: that the relevant consequence remains persistently observable.

A stronger fault point is after peer B has been fully materialized and its one-shot service has been consumed, but **before** `peer-b-present` is durably published. A successor would then see durable state still at `peer-a-removed`, persistent topology already complete, transient service liveness possibly gone, and possibly Guest completion evidence already present.

That experiment should ask whether persistent topology + independent consequence evidence is enough to reconstruct an unpublished completion without replay. Only if it is ambiguous should Security add a durable completion/substep receipt.
