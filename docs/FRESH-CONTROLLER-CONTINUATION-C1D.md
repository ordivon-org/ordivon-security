---
schema_version: 1
id: security.fresh-controller-continuation-c1d
title: Fresh Controller Continuation C1-D
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
summary: Physical proof that a replacement controller can continue one admitted S6 peer-B materialization from durable effect/resource identity plus independent Host observation without restoring the old Python Range object, event stream, or a durable substep transaction log.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.partial-materialization-c1c
  - security.interrupted-consequence-c1b
  - security.persistent-range-recovery-s6r
  - security.law-profiles-c0
---
# Fresh Controller Continuation C1-D

## Question

C1-C proved that an interrupted peer-B materialization can be truthfully closed to zero once transient resource ownership is complete.

C1-D asks the stronger question:

> Can a fresh controller inherit the same admitted effect and partial physical world, finish the missing suffix, and let the already-running Windows Guest continue without first destroying the Range?

The experiment deliberately does not restore the old `_FabricRun`, the old `RangeSession`, or the old event stream. It also does not add a durable substep state machine, transaction log, compensation engine, or generic exactly-once protocol.

## Starting world

The owner process runs the same actor-authorized S6 effect and is killed at the accepted C1-C fault point:

```text
Guest connects peer A
→ peer A exits successfully
→ old controller publishes peer-a-removed
→ peer-B namespace is created
→ q<session> ↔ w<session> veth pair is created in Host root namespace
→ old controller receives SIGKILL
```

The Windows Guest, QEMU, swtpm, packet sensor, isolated fabric, admitted effect identity, and partial peer-B resources all remain alive after the controller disappears.

The inherited durable ledger says:

```text
topologyPhase      = peer-a-removed
currentPeerAddress = null
```

Independent Host observation additionally sees:

```text
fabric namespace = present
peer-B namespace = present
q/w root veths   = present and type=veth
bridge ports     = Windows TAP only
QEMU             = alive
swtpm            = alive
packet sensor    = alive
old owner         = dead
```

The fresh controller does not consume a durable substep label telling it what to do next.

## Continuation rule

For this exact accepted fault point, continuation is derived from the combination of:

```text
exact admitted effect identity
+
exact deterministic S6 resource identities
+
independent current Host placement
```

The fresh controller validates the inherited ledger with the existing S6 recovery identity rules, confirms the q/w candidates are the exact session-derived veths, confirms the peer-B and fabric namespaces exist, and confirms neither veth has already been moved into its target namespace.

Only then does it execute the missing suffix:

```text
move q into peer-B namespace
move w into fabric namespace
attach w to bridge
raise w / q / loopback
assign 10.253.70.4/24 to q
verify no peer default route
verify fabric bridge still has no L3 route/address
start the maintained peer-B service
observe TAP + w as the exact bridge ports
```

After independent Host observation establishes the target topology, the fresh controller updates only the durable facts needed by later recovery:

```text
peerNamespace
peerPid
peerStartTime
topologyPhase = peer-b-present
currentPeerAddress = 10.253.70.4
```

The original Actor effect binding remains byte-for-byte semantically identical and the original backend receipt remains:

```text
status = accepted-pending-execution
worldEffectVerified = false
```

The continuation therefore does not promote a backend receipt into world truth.

## Physical acceptance

The accepted implementation revision is:

```text
git:691145f8466bc2a0633882ebd6540d0e480f0f82
```

The owner died at the exact partial-materialization gate. The fresh controller inherited the effect:

```text
effectId        = range-effect:8b73398929693d0d49d593c5
requestDigest   = sha256:8b73398929693d0d49d593c5517fdf84a8a4fe28f4366a26f2a73a22f3b6ff04
admissionDigest = sha256:44f3d99a51666ad72ae5b0713193f47f6966a63113d4eec3484db04b833f31bb
```

The durable ledger moved from:

```text
peer-a-removed
currentPeerAddress = null
```

to:

```text
peer-b-present
currentPeerAddress = 10.253.70.4
peerNamespace      = s6q4e833afd
peerPid            = 117307
peerStartTime      = 637036
```

No old Python Range object or event stream was reconstructed.

## The same Guest crossed controller death

This run intentionally differs from the earlier partial-materialization acceptance: peer A was not consumed by a Host-side probe. The maintained Windows Guest itself connected peer A before the old controller died.

After the fresh controller materialized peer B, the same Guest continued and connected peer B successfully.

The recovered Guest result reports:

```text
peerAConnected      = true
peerABannerMatched  = true
peerBConnected      = true
peerBBannerMatched  = true
completed           = true
externalNetworkRequested = false
```

The independent packet sensor recorded both flows in one surviving capture:

```text
packetLineCount = 16
peer A traffic  = observed
peer B traffic  = observed
```

QMP also observed exactly one Windows Ethernet device before and after controller replacement.

This is the strongest result of C1-D:

> **The Agent/controller process disappeared, but the world and its in-progress consequence did not need to restart.**

## Closure after continuation

After the Guest completed, the existing S5/S6 reconciler consumed the updated durable peer identity and closed the continued world.

Final reconciliation reported:

```text
status             = passed
reconciled         = 1
residualNamespaces = []
residualHostLinks  = []
```

Independent closure observation found no QEMU, swtpm, peer, packet-sensor, namespace, or candidate root-link residuals.

## What C1-D proves

For this exact S6 effect and fault point, C1-D proves:

- a replacement controller can continue a consequential physical effect without restoring the old Python controller object graph;
- the old Range event stream is not required to complete this exact physical suffix;
- the same Windows Guest can remain alive across controller death and continue its challenge after the successor materializes peer B;
- exact durable semantic effect identity plus exact resource identity plus current Host placement is sufficient to select the missing suffix at this fault point;
- no durable substep state was consumed;
- no whole-Range reset was required before continuation;
- after Host verifies the target topology, publishing the new peer process identity and stable topology phase is sufficient for the existing reconciler to later close the continued world;
- the non-truth backend receipt can remain unchanged while independent world observation establishes the physical consequence;
- this consumer still does not force a generic causal DAG or exactly-once transaction framework.

The practical relation is:

```text
semantic effect identity
+
resource identity
+
current world placement
→ infer missing suffix
→ execute suffix
→ independently verify target world
→ publish new durable resource identity
```

For this experiment, **world state acts as progress state**.

## What C1-D does not prove

C1-D does not prove:

- that every partial placement can be continued safely;
- that the continuation suffix itself survives another controller crash;
- generic idempotency across arbitrary physical effects;
- concurrent successors or multiple recovery contenders;
- exactly-once execution;
- repair or compensation for conflicting partial worlds;
- durable restoration of the old Range event stream;
- generic `RangeEvent.causalParents` enforcement;
- external or uncontrolled target authority.

The acceptance runner is a research consumer, not a declaration of a universal recovery API.

## New pressure: successor ownership

C1-E has now run this race physically. Without arbitration, a preflight-valid successor moved one side of the partial veth pair while the existing dead-owner reconciler simultaneously closed QEMU/namespaces and removed the same world; the successor then failed because its namespace disappeared. See [`SUCCESSOR-OWNERSHIP-C1E.md`](SUCCESSOR-OWNERSHIP-C1E.md).

The accepted correction does not rewrite the dead predecessor as the successor. It separates historical provenance from current recovery authority: the successor CAS-binds a durable claim to the exact ledger digest, while one per-Run kernel gate makes successor continuation and reconciliation mutually exclusive. Successor SIGKILL releases the physical gate automatically, so a later reconciler can recover while retaining the stale claim as evidence.

The next pressure is therefore multiple successor candidates over the same exact generation, not a generic distributed lease protocol.
