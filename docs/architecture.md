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
summary: Canonical architecture for multi-Actor Contest execution, Range authority, native and delegated actors, evidence channels, and staged cyber-range integration.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.research-boundary
  - security.authority
---
# Architecture

## System boundary

Ordivon Security is the adversarial domain layer. It defines who is contesting what, what each actor may know and attempt, how concurrent actions are admitted and resolved, which source owns world truth, and how evidence and outcomes are reconstructed.

It composes rather than replaces Host, Harness, Runtime, external ranges, model Providers, and classical security tools.

## Active `0.1` flow

```text
ScenarioManifest
  ├─ Range binding
  ├─ ordered Actor bindings
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
  6. resolve admitted proposals simultaneously
  7. return Actor results
  8. record sensor telemetry and hidden truth independently
  9. repeat until Range terminal or tick limit
 10. seal raw metrics and evidence
```

The ordered Actor list is part of the Scenario identity. Actor invocation is sequential in the current process, but all proposals are collected before any world mutation; therefore the semantic tick is simultaneous.

## Core contracts

### `ScenarioManifest`

Binds Scenario revision, Range identity, ordered Actors, backend identities, objectives, allowed actions, tick limit, and experiment metadata. Its canonical digest participates in Trial identity.

### `ActorBackend`

Starts an Actor session, receives only that Actor's observation, returns an `ActionProposal`, receives the resolved result, and produces a stop receipt.

Planned implementations:

- scripted baseline;
- Native Ordivon Harness Actor using model APIs such as DeepSeek;
- delegated Codex/Hermes Harness backend;
- PettingZoo/RL policy adapter.

### `RangeBackend`

Creates and destroys an authorized world, emits actor-specific observations, admits proposals, resolves simultaneous actions, exposes independent truth, exports raw metrics, and declares terminal state.

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

A model-generated command is never automatically authoritative. Structured actions and open tools share this path.

## Evidence authority

Every active Trial produces four hash-chained streams:

| Channel | Owns |
|---|---|
| Actor | observations, proposals, returned action results |
| Range management | lifecycle, admissions, resolutions, backend receipts |
| Sensor | fallible and potentially manipulable telemetry |
| World truth | management-plane state unavailable to evaluated actors |

The bundle additionally contains the exact Scenario manifest, raw metrics, result summary, per-channel file digests, and chain heads. Wall-clock timestamps are intentionally absent from the deterministic `0.1` core; logical time is authoritative.

## Current Micro Range

The synthetic Red/Blue Range is not a security simulator product. It proves that:

- Red and Blue are independently controlled;
- Blue cannot read Red foothold truth directly;
- monitoring can create fallible alerts;
- simultaneous isolation blocks a pivot;
- a passive defender permits exfiltration;
- identical inputs reproduce identical evidence digests;
- modified event files fail verification.

Its deletion condition is a mature external Range adapter that covers the same contract tests more cheaply and deterministically.

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

1. strengthen contracts and failure evidence in the deterministic core;
2. implement a first-class CAGE 4 Range adapter controlled by Ordivon Actors;
3. add a generic Harness domain Tool Bridge without making Harness depend on Security;
4. run DeepSeek-backed Native Harness Red and Blue Actors;
5. add Campaign and organization state only when multi-Actor experiments consume it;
6. introduce containerlab, an independent management plane, and Zeek telemetry;
7. add CALDERA as a TTP execution adapter, not as Campaign authority;
8. connect Codex and Hermes as delegated Harness baselines in planner-only, Tool-proxy, and black-box modes.

## Explicit non-goals

The repository will not implement its own hypervisor, container runtime, topology engine, C2 framework, exploit database, scanner, EDR/SIEM, generic model router, generic Job system, policy language, RL trainer, or signing infrastructure unless a measured domain gap survives mature alternatives.
