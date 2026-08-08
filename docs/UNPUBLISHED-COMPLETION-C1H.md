---
schema_version: 1
id: security.unpublished-completion-c1h
title: Unpublished Completion C1-H
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
summary: Physical proof that the peer-B consequence may be fully materialized and consumed before stable durable publication, and that a later successor can recover completed-but-unpublished state from persistent Host topology plus independent Guest and read-only sensor evidence, repair only durable publication, and avoid replay or transient-service restart.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.mid-successor-recovery-c1g
  - security.multiple-successors-c1f
  - security.successor-ownership-c1e
  - security.law-profiles-c0
---
# Unpublished Completion C1-H

## Question

C1-G proved that one successor may change the physical world and die before stable ledger publication. A later successor could re-observe the partial topology and execute only the missing suffix.

C1-H attacks the remaining easy assumption:

> What if the consequence is already fully materialized and consumed, the transient executor has disappeared, and the successor dies **before durable completion publication**?

The experiment deliberately does not add a durable completion receipt, substep state machine, transaction log, exactly-once layer, or generic causal DAG first.

## Fault construction

The original controller first dies at the accepted root-veth partial point. A first successor then acquires recovery authority and completes the physical peer-B topology without publishing it:

```text
q -> peer-B namespace
w -> fabric namespace
w -> bridge
links up
10.253.70.4/24 assigned
no default route
isolated bridge verified
peer-B one-shot service started
```

The same Windows Guest consumes peer B. The one-shot service exits zero. The Guest completes and QEMU exits.

Only then is the first successor killed with SIGKILL, before it writes:

```text
topologyPhase      = peer-b-present
currentPeerAddress = 10.253.70.4
peerPid / peerStartTime
```

The exact durable ledger digest remains:

```text
sha256:edd0825bc32daf6fd7717680101eb8fb03d612aa37e2f98df41b394d04b9d7f6
```

while persistent Host topology already contains peer B.

This is a stronger form of the C1-G result:

```text
consequence completion
can precede
durable completion publication
```

## What the second successor is allowed to know

The second successor is not handed the first successor's local Python state or an experimental completion verdict.

After obtaining recovery authority it independently obtains three evidence classes.

### 1. Persistent Host topology

It observes:

```text
peer-B namespace present
q in peer-B namespace
w in fabric namespace
w attached to bridge
10.253.70.4/24 present
no default route
root q/w absent
```

At the same time the durable ledger still says:

```text
topologyPhase      = peer-a-removed
currentPeerAddress = null
```

### 2. Guest consequence evidence

Only after the first successor has died, the second successor extracts the completed Guest result from the closed run disk.

The Guest independently reports:

```text
peerAConnected      = true
peerABannerMatched  = true
peerBConnected      = true
peerBBannerMatched  = true
completed           = true
externalNetworkRequested = false
```

Fixture result digest:

```text
sha256:9f82b3b3660f5fb7e189ec7fef9a329261c040d1f30216f96e62664541cb517e
```

### 3. Read-only packet-sensor evidence

The packet capture still belongs to the live Range recovery substrate when the second successor inspects it.

The corrected C1-H runner takes a point-in-time read-only pcap snapshot and parses that snapshot without stopping or signalling the capture process:

```text
captureAliveBefore       = true
captureAliveAfter        = true
captureMutationAttempted = false
peerATrafficObserved     = true
peerBTrafficObserved     = true
```

Corrected pcap snapshot:

```text
byteLength = 1228
packetLineCount = 16
sha256:5e6d9fe4b3700cc8198cb3e2a5e6c7e228a8338bed266c9803be58a385768497
```

Therefore observation does not silently consume the sensor resource.

## Methodology falsifier: observation that mutates the sensor

The first successful physical candidate at revision `1161ff80ce0fbae35b39f9dc1124a9b677c4578f` reached the same domain result, but its second successor reused `_sensor_truth()`, which terminates tcpdump before reading the pcap.

That made the candidate methodologically too strong to call “no physical mutation”: the recovery actor had not replayed the peer effect, but its observation had changed a managed sensor resource.

The candidate is therefore not the canonical acceptance.

The correction at:

```text
git:6fce713dd44578293bec97f9e4ac14b229ae7612
```

uses read-only sensor observation and requires capture liveness to remain unchanged across the read.

This reinforces an existing Security truth discipline:

```text
Observation
!=
Intervention
```

An observation API that silently changes the observed substrate must declare that effect or be rejected for evidence-preserving recovery.

## Recovery classification

The second successor now has:

```text
persistent peer-B topology complete
+
Guest says B was actually consumed
+
independent packet sensor saw B traffic
+
durable ledger still peer-a-removed
```

It classifies:

```text
completed-but-unpublished
```

The transient peer-B service is not restarted.

The original replacement effect is not replayed.

No Range-world mutation is performed by the second successor. The only recovery write is to repair durable publication:

```text
topologyPhase      = peer-b-present
currentPeerAddress = 10.253.70.4
peerPid            = 0
peerStartTime      = null
```

The `physicalMutationAttempted=false` field in the experiment receipt is scoped to consequence/Range-world mutation; durable ledger publication and evidence extraction are intentionally still writes/reads in the recovery substrate.

The repaired ledger advances to:

```text
sha256:6395bc6bca7b7a39fa4bf564a4096eb4dae1229cfa66e8bc37d15c93b5a192c3
```

## Recovery lineage

The first successor claim is:

```text
recovery-claim:7f5d3f2da6c0176418123901
```

The second successor claim is:

```text
recovery-claim:412f83032f30b02752cda57c
```

and records:

```text
predecessorClaimId
= recovery-claim:7f5d3f2da6c0176418123901

predecessorClaimDigest
= sha256:6fe747507f562f1b2b2cf9c7dec5db8796542c600f647e7dadd2a1b1eefff3b4
```

Both claims bind the same unpublished durable ledger digest. Recovery lineage therefore continues to describe authority succession independently of durable world-state advancement.

## Final closure

The second successor is SIGKILLed after repairing publication. The final reconciler acquires recovery authority, observes the current claim plus archived predecessor claim, and closes the remaining substrate.

Final truth:

```text
QEMU       absent
swtpm      absent
peer       absent
capture    absent
namespaces []
root links []
ledger     absent
```

The experiment cleanup probe requests no work.

## What C1-H proves

For this exact isolated S6 effect and fault path, C1-H proves:

- the physical peer-B consequence may become complete and be consumed before stable durable completion publication;
- transient peer-service liveness is not required to recover completion after that service has already been consumed;
- persistent topology alone shows materialization, while independent Guest and sensor evidence can establish that the intended one-shot interaction actually occurred;
- a successor can distinguish `completed-but-unpublished` from the tested partial states without replaying the original effect;
- after that classification, recovery can repair only durable publication and leave the already-completed Range world untouched;
- successor claim lineage remains coherent even when multiple successor claims bind the same unchanged unpublished ledger digest;
- read-only evidence observation can preserve the packet sensor for the later reconciler;
- no durable completion receipt, substep state machine, generation counter, transaction log, exactly-once framework, or causal DAG was forced by this observable consequence.

The useful relation is now:

```text
persistent world consequence
+
independent completion evidence
+
exclusive recovery authority
+
recovery lineage
-> repair lost publication without replay
```

and:

```text
completion fact
!=
completion publication
!=
transient executor liveness
```

## What C1-H does not prove

C1-H does not prove:

- that persistent topology alone establishes every domain-specific completion condition;
- that Guest claims or sensors are infallible;
- how to recover if independent completion evidence is absent, contradictory, or corrupted;
- recovery of a one-shot consequence whose delivered and undelivered worlds converge to the same observable state;
- arbitrary non-idempotent effects;
- generic exactly-once delivery;
- multi-host fencing, partitions, quorum, or distributed leases;
- generic shared-resource concurrency;
- generic `RangeEvent.causalParents` enforcement;
- external or uncontrolled target authority.

The first physical setup attempt also missed the initial Guest challenge window before any C1-H successor logic ran. Its orphaned S6 resources were closed by the existing reconciler with zero residuals. That operational cold-boot timeout is not part of the C1-H semantic result.

## Resulting pressure

The C1 line has now recovered both partial and completed-but-unpublished effects **when enough consequence truth remains observable**.

A stronger next experiment should remove that advantage rather than add more topology cases.

Create an isolated one-shot, non-idempotent consequence whose final observable world can be identical in two histories:

```text
History A: delivery happened, publication was lost
History B: delivery never happened

current physical world after crash
= observationally indistinguishable
```

Then kill the controller between physical delivery and durable acknowledgement.

The successor must not guess or blindly resend. The experiment should determine whether the minimum unavoidable structure is downstream idempotency, a durable effect/completion receipt, an acknowledgement identity, or simply an explicit `UNKNOWN` outcome when information has been destroyed.

Only that information-loss experiment should decide whether an exactly-once-style primitive is genuinely necessary.
