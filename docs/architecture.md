---
schema_version: 1
id: security.architecture
title: Architecture
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
updated: 2026-08-04
summary: Canonical architecture for fail-closed multi-Actor Contest execution, complete execution identity, semantic and operational evidence, CAGE Ranges, and staged model integration.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.research-boundary
  - security.migration.round2
  - security.migration.round3-p0
  - security.authority
---
# Architecture

## System boundary

Ordivon Security is the adversarial domain layer. It defines who is contesting what, what each actor may know and attempt, how concurrent actions are admitted and resolved, which source owns world truth, and how evidence and outcomes are reconstructed.

It composes rather than replaces Host, Harness, Runtime, external ranges, model Providers, and classical security tools.

## Active `0.3` flow

```text
ScenarioManifest
  ├─ Range binding and exact revision
  ├─ ordered Actor bindings
  ├─ backend implementation and configuration digests
  ├─ objectives and Action grants
  ├─ limits
  └─ metadata
        ↓
ContestRunner
  1. create authoritative Range instance
  2. start one backend session per Actor
  3. collect actor-specific observations
  4. collect one proposal per Actor
  5. admit every proposal against Range and Actor grants
  6. invalidate the tick without world mutation if any Actor fails or proposal is rejected
  7. otherwise resolve all admitted proposals simultaneously
  8. return Actor results
  9. record sensor telemetry and hidden truth independently
 10. repeat until Range terminal or tick limit
 11. seal semantic and operational evidence independently
```

The ordered Actor list is part of the Scenario identity. Trial identity additionally binds the Security implementation, evidence schema revision, Range adapter and substrate, and each Actor implementation identity. Actor invocation is sequential in the current process, but all proposals are collected before any world mutation; therefore the semantic tick is simultaneous.

## Core contracts

### `ScenarioManifest`

Binds Scenario revision, Range identity, ordered Actors, backend identities and configuration digests, objectives, allowed actions, tick limit, and experiment metadata. Its canonical digest participates in Trial identity.

### `ActorBackend`

Starts an Actor session, receives only that Actor's observation, returns an `ActionProposal`, receives the resolved result, and produces a stop receipt.

Active implementation:

- scripted sequence baseline.

Planned implementations:

- Native Ordivon Harness Actor using model APIs such as DeepSeek;
- delegated Codex/Hermes Harness backend;
- PettingZoo/RL policy adapter.

### `RangeBackend`

Creates and destroys an authorized world, emits actor-specific observations, admits proposals, resolves simultaneous actions, exposes independent truth, exports raw metrics, and declares terminal state.

Active Ranges:

- `MicroContestRange` — local deterministic semantic contract fixture;
- `Cage4RangeBackend` — pinned CAGE Challenge 4 Enterprise simulation.

Planned fidelity levels:

- S0: deterministic local and CAGE/CybORG simulations;
- E1: containerlab/Docker isolated emulation;
- E2: Proxmox/KVM VM range when required.

### Action path

```text
ActionProposal
  → ActionAdmission
  → Range-specific intent or Runtime Job
  → ActorActionResult / EffectReceipt
  → independent world verification
```

A model-generated command is never automatically authoritative. Structured actions and open tools share this path. If one Actor fails to propose or any proposal is rejected, no side is resolved for that tick; peers receive `not-executed` and the Trial ends with an explicit failure reason.

## CAGE 4 Range

The active adapter binds:

```text
repository: cage-challenge/cage-challenge-4
revision: 8c3c50ca54b176c2de199847944e8dcc035497e3
```

A CAGE Contest has two Security Actors:

```text
actor:red  → red_agent_0
actor:blue → blue_agent_0 ... blue_agent_4
```

Each Security Actor currently chooses one team plan per tick:

```text
cage.team.native-policy
cage.team.sleep
```

The Range expands the plan into concrete CAGE actions and supplies every Red and Blue action explicitly to `parallel_step(actions=...)`. Green agents remain CAGE-controlled environmental actors. Missing Red/Blue plans are rejected rather than silently delegated to CAGE defaults.

The native plan is a transitional bridge: it proves that Security controls scheduling, admission, information, evidence, and comparison while reusing mature CAGE policies. It does not yet expose arbitrary parameterized CAGE actions to a model.

CAGE source integrity is enforced by:

- exact Git revision;
- clean checkout;
- import provenance from the configured checkout;
- semantic config digest excluding machine-local source path;
- explicit external action counts;
- raw native action names and world-truth summaries.

Pinned CAGE terminates at `step_count >= steps - 1`; the adapter adds one internal episode step so Security's `max_ticks` remains the exact number of executable Contest ticks.

## Evidence authority

Every active Trial produces four hash-chained streams:

| Channel | Owns |
|---|---|
| Actor | observations, proposals, returned action results |
| Range management | lifecycle, admissions, resolutions, backend receipts |
| Sensor | fallible and potentially manipulable telemetry |
| World truth | management-plane state unavailable to evaluated actors |

The semantic bundle additionally contains the exact Scenario manifest, Trial execution identity, raw metrics, result summary, per-channel file digests, and chain heads. Wall-clock timestamps remain absent from the deterministic core; logical time is authoritative. A separately chained operational stream records durations and operating facts and binds back to the semantic evidence digest without changing it.

For CAGE, actor events contain each side's admitted observations and team plan. Management events contain the concrete CAGE actions submitted. Sensor events contain reward, mission phase, foothold, and action-count telemetry. Truth events independently summarize native CAGE state.

## Current Micro Range

The synthetic Red/Blue Range remains a fast contract fixture. It proves simultaneous conflict rules, hidden truth separation, and evidence tamper rejection without an external dependency.

Its deletion condition is not merely the existence of CAGE: it can be removed only when another fixture covers the same deterministic unit tests with lower maintenance cost.

## Cross-project composition

| Responsibility | Owner |
|---|---|
| Goal, durable Task, commitment, final outcome | Host |
| Native Agent loop, Provider turns, Tool recovery, external Harness drivers | Harness |
| Workspace, Job, Attempt, process, artifact, physical recovery | Runtime |
| external provider/private operator adapters when needed | World |
| Scenario, Contest, Campaign, organization, Range semantics, scoring | Security |
| promoted cross-domain protocols | Computing |

Security may request a Harness or Runtime change but must not copy their state machines.

## Next integration sequence

1. define the Security-owned CAGE team-plan catalog using the implemented Harness `DomainToolCatalog`;
2. implement the Security `DomainToolBridge` and Native Harness Actor failure mapping;
3. run DeepSeek Flash-backed Native Harness Red and Blue Actors;
4. expand from team-plan control to parameterized CAGE Action Proposals where experiments require it;
5. add Campaign and organization state only when multi-Actor experiments consume it;
6. introduce containerlab, an independent management plane, and Zeek telemetry;
7. add CALDERA as a TTP execution adapter, not as Campaign authority;
8. connect Codex and Hermes as delegated Harness baselines in planner-only, Tool-proxy, and black-box modes.

## Explicit non-goals

The repository will not implement its own hypervisor, container runtime, topology engine, C2 framework, exploit database, scanner, EDR/SIEM, generic model router, generic Job system, policy language, RL trainer, or signing infrastructure unless a measured domain gap survives mature alternatives.
