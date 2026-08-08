---
schema_version: 1
id: security.successor-ownership-c1e
title: Successor Ownership and Recovery Arbitration C1-E
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
summary: Physical proof that a dead-owner S6 world needs mutually exclusive recovery authority between continuation and reconciliation; an exact ledger-generation successor claim plus a per-Run kernel flock prevents concurrent mutation while preserving predecessor provenance and automatically releases physical authority when the successor dies.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.fresh-controller-continuation-c1d
  - security.partial-materialization-c1c
  - security.persistent-range-recovery-s6r
  - security.law-profiles-c0
---
# Successor Ownership and Recovery Arbitration C1-E

## Question

C1-D proved that a fresh controller can continue an admitted partial S6 consequence from durable effect/resource identity plus current Host placement without restoring the old Python Range object or event stream.

It also exposed a contradiction: the durable ledger still identifies the dead predecessor as `ownerPid/ownerStartTime`, while the successor is actively mutating the world. The existing reconciler treats that same dead-owner ledger as orphaned and therefore eligible for closure.

C1-E asks:

> What is the minimum mechanism that prevents a successor and the orphan reconciler from concurrently mutating the same exact world, while still allowing recovery if the successor also dies?

The experiment deliberately does not introduce a global recovery service, distributed transaction, workflow engine, wall-clock lease protocol, human approval gate, or generic ownership ontology.

## Baseline: the ownership race is real

The baseline revision is:

```text
git:351140fb9d8c2611b3e4c7b09908ca52fdd3bd04
```

The old controller is killed at the accepted C1-C root-veth partial-materialization point. A successor independently verifies that the world is continuable:

```text
topologyPhase = peer-a-removed
QEMU / swtpm / sensor = alive
fabric namespace      = present
peer-B namespace      = present
q/w root veths        = present and type=veth
bridge ports          = Windows TAP only
```

The successor then pauses immediately before physical continuation. The existing reconciler and successor are released against the same dead-owner ledger.

Both act.

The successor begins moving the deterministic q/w pair. At the same time, the reconciler admits orphan closure, terminates QEMU/swtpm/sensor, removes namespaces and the remaining Host link, and deletes the Run/ledger.

The successor fails while trying to raise the peer-B link:

```text
ip -n s6q... link set q... up
→ exit 255
```

The reconciler receipt is especially informative: it requests only the remaining root `w...` link. That means the successor had already moved the other veth end before reconciliation deleted the namespace that contained it.

This is physical interleaving, not a hypothetical TOCTOU argument.

The baseline establishes:

> **Dead predecessor identity made two incompatible recovery authorities simultaneously admissible.**

The successor's valid observation was not atomic with its authority to act.

## The law forced by the falsifier

The experiment does not justify replacing predecessor identity with successor identity. Those are different facts.

The durable model must preserve:

```text
Predecessor provenance
≠
Current recovery authority
```

The narrower law is:

> **For one exact recoverable world generation, at most one recovery mutator may hold authority at a time.**

A recovery mutator may be a successor continuation controller or the reconciler. The law does not decide which strategy is preferable; it prevents both from physically acting concurrently.

## Minimal single-host mechanism

The accepted implementation revision is:

```text
git:d82241b2f49994ee819dfb5d32a990bf97ea2830
```

For the current single-host S5/S6 substrate, the mechanism has two separate parts.

### 1. Durable successor claim: provenance and exact generation

A successor may create a claim only after acquiring the per-Run recovery gate. Claim acquisition re-reads the exact ledger while holding that gate and requires its digest to equal the successor's expected digest.

Therefore claim acquisition is a CAS over one exact ledger generation:

```text
expected ledger digest
==
current ledger digest
```

It also refuses acquisition while the original exact owner is still alive.

The claim records:

```text
claimId
runToken
rangeSessionId
rangeId
purpose
ledgerDigest
claimantPid
claimantStartTime
predecessorOwnerPid
predecessorOwnerStartTime
effectId
acquiredAtNs
state
```

The predecessor fields are retained rather than overwritten.

### 2. Per-Run kernel flock: the mutex

The durable claim is **not** trusted as the mutex.

The actual single-host arbitration is an exclusive non-blocking `flock` on one exact per-Run lock file. The successor holds it while it owns continuation. The reconciler must acquire the same gate before mutating an orphaned Range.

If the gate is held, reconciliation returns:

```text
decision = skipped-successor-active
```

and performs no cleanup mutation.

Because the lock is held by a process file descriptor with `CLOEXEC`, a successor `SIGKILL` causes the kernel to release the recovery gate automatically. A peer-B child process does not inherit ownership.

This is why C1-E does not require a wall-clock TTL for the accepted single-host case.

## Physical acceptance

The accepted run starts from the same root-veth partial world.

The successor acquires:

```text
claimId = recovery-claim:70f3f1ae24ed3f34be2359e0
ledgerDigest = sha256:0c49489e6424784c7d5a5c02dd233f2f9f13da1338bfc8eef654613730d71522
```

The claim preserves distinct process identities:

```text
predecessor owner = 130284 / 756874
successor claimant = 133359 / 770748
```

The first reconciler runs while the successor holds the gate:

```text
reconciled             = 0
skippedSuccessorActive = 1
attentionRequired      = 0
```

Independent Host observation confirms no physical change: QEMU, swtpm, packet sensor, both namespaces, and both root veths remain exactly as before.

The successor is then released and continues to:

```text
topologyPhase      = peer-b-present
currentPeerAddress = 10.253.70.4
peerNamespace      = s6q4aecfee6
peerPid            = 133399
peerStartTime      = 770824
```

while the claim remains `state=held` and QEMU remains alive.

## Successor death does not create an immortal lock

The experiment then kills the successor itself with `SIGKILL` while it still holds the claim.

Two things deliberately diverge:

```text
Durable metadata:
claim.state = held

Physical arbitration:
kernel flock = released automatically
```

The stale durable claim therefore remains useful provenance, but it no longer grants mutation authority.

A second reconciler immediately acquires the gate and closes the world. Its receipt preserves the exact stale claim it observed, including the same `claimId`, then removes the claim metadata after clean closure.

Final independent truth is:

```text
QEMU       = absent
swtpm      = absent
peer       = absent
sensor     = absent
namespaces = []
root links = []
ledger     = absent
claim JSON = absent
```

The experiment cleanup probe finds no residual work.

## What C1-E proves

For the current single-host S5/S6 recovery consumer, C1-E proves:

- the successor-versus-reconciler race is physically real;
- a valid successor preflight does not itself grant exclusive recovery authority;
- rewriting `ownerPid` to the successor would conflate provenance with current recovery ownership;
- one exact per-Run recovery gate can make continuation and reconciliation mutually exclusive;
- successor claim acquisition can be bound to one exact ledger generation rather than a broad mutable world name;
- the reconciler can defer without declaring failure while a live successor owns recovery;
- the successor can continue the already accepted partial world while holding that authority;
- successor `SIGKILL` automatically releases the single-host kernel gate;
- durable claim metadata can survive the crash as provenance while no longer functioning as authority;
- the reconciler can then acquire authority, observe the stale claim, close the continued world, and remove the claim metadata;
- no wall-clock lease, heartbeat daemon, generic transaction framework, or causal DAG was required by this exact experiment.

The accepted relation is:

```text
historical predecessor identity
+
exact ledger generation
+
durable successor claim
+
process-scoped recovery gate
→ one recovery mutator at a time
```

## What C1-E does not prove

C1-E does not prove:

- multi-host or distributed ownership arbitration;
- recovery through network partitions;
- a universal `flock`-based law outside this single Linux Host;
- fairness between multiple competing successors;
- priority policy between continuation and closure;
- successor-to-successor handoff without an intervening crash;
- arbitrary concurrent effects over shared resources;
- generic exactly-once semantics;
- that wall-clock leases are unnecessary in a future multi-node substrate;
- generic causal-DAG enforcement;
- external or uncontrolled target authority.

The constitutional result is exclusivity of recovery authority for one exact world generation. `flock` is merely the smallest mechanism that satisfies it in this currently tested universe.

## Resulting pressure

C1-F has now run the multiple-successor experiment physically. Two candidates over the same exact generation produced exactly one recovery-authority winner and one non-mutating loser. After the winner advanced the world and died, the loser re-read the new ledger generation, acquired authority against that generation, and adopted the existing peer-B consequence without replay. See [`MULTIPLE-SUCCESSORS-C1F.md`](MULTIPLE-SUCCESSORS-C1F.md).

C1-F also exposed a provenance boundary C1-E could not see with only one successor: replacing one current claim with another erased successor-to-successor history. The accepted correction archives the exact predecessor claim and links the new current claim by `predecessorClaimId` and digest. The per-Run kernel gate remains the mutex.

The next pressure is therefore successor death during its own partially completed continuation, not distributed consensus or a third stable succession merely to lengthen the chain.
