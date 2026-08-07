---
schema_version: 1
id: security.range-session-s0
title: Range Session S0
type: architecture
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - builder
  - evaluator
  - agent
updated: 2026-08-07
summary: Minimal continuous Range lifecycle contracts that remove tick and action-menu assumptions without changing the accepted synchronous Contest or Evaluation paths.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.architecture
  - security.research-agenda
  - security.authority
---
# Range Session S0

## Purpose

Range Session S0 introduces the smallest Security core that can represent a persistent contested world without requiring one proposal per Actor, an allowed-action catalog, or a global simultaneous-resolution barrier.

It is deliberately parallel to the accepted `ContestRunner`. S0 does not change Micro Range, CAGE, existing Trial identity, Contest evidence, Evaluation, or Windows KVM execution authority.

## Active contracts

`RangeSessionSpec` binds one Range, the participating Actor identities, optional Range authorities, and metadata. It has no tick limit and no action catalog.

`RangeAuthority` grants an Actor capabilities inside named zones and separately declares the external-effect boundary. It authorizes an action space rather than individual commands.

`ActorPresence` records whether an Actor is `unknown`, `active`, `unreachable`, `stopped`, or `compromised`. An Actor becoming unreachable does not invalidate the Range Session or stop peer/world progress.

`RangeEvent` records an ordered observation of a changing world. Event sequence and logical time are distinct: multiple independent events may share the same logical time. Events explicitly identify the `management` or `contested` plane and may carry causal-parent references for later evidence integration.

`RangeCheckpoint` binds a Security checkpoint identity to a backend-owned checkpoint reference without pretending Security owns hypervisor mechanics.

`RangeSessionBackend` owns physical or simulated Range lifecycle operations: create, inspect, event retrieval, checkpoint, terminate, and destroy. It does not expose `observe → admit → resolve` as a universal execution law.

## Lifecycle

```text
RangeSessionSpec
      ↓
RangeSession.start
      ↓
RangeSessionBackend.create
      ↓
continuous backend/world events
      ↓
RangeSession.poll_backend
      ↓
management + contested RangeEvent stream
      ↓
checkpoint / terminate / destroy
```

Environment events may occur without an Actor proposal. Actor failure is represented as Actor presence and management evidence rather than automatic world rollback.

## Acceptance

S0 unit acceptance proves:

- an Actor can exist without an action menu;
- Actor failure does not invalidate the world or freeze a peer;
- the environment can change without an Actor proposal;
- logical time is not a synchronization barrier;
- authority is expressed as zone plus capability rather than commands;
- management-plane and contested-plane events remain distinct;
- checkpoint identity remains separate from backend checkpoint ownership;
- terminate and destroy are separate lifecycle transitions.

The full existing unit suite must remain green. S0 is not accepted as a physical adversarial Range until a backend can survive Guest compromise while preserving external containment and management truth.

## Explicit non-goals

S0 does not implement scheduling, Agent cognition, ControlState, Campaign, organizations, VM networking, Guest compromise, causal evidence schema v2, scoring, or a new KVM Provider. Those require separate evidence and acceptance.
