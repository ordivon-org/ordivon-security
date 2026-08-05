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
updated: 2026-08-05
summary: Canonical architecture for fail-closed Contest execution and authorized software Evaluation Trials with exact identity, separated authorities, residual closure, and sealed evidence.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.research-boundary
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.case-snapshot-p0
  - security.windows-kvm-p0
  - security.agent-experiment-p0
  - security.migration.round2
  - security.migration.round3-p0
  - security.authority
---
# Architecture

## System boundary

Ordivon Security is the adversarial domain layer. It defines who is contesting what, what each actor may know and attempt, how concurrent actions are admitted and resolved, which source owns world truth, and how evidence and outcomes are reconstructed.

It composes rather than replaces Host, Harness, Runtime, external ranges, model Providers, and classical security tools.

## Active `0.8` flows

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

EvaluationSpec
  1. validate Sample, Authority, Environment, Guardian, Observation plan, and actions
  2. verify Sample bytes from the local content-addressed Vault
  3. create one exact backend instance
  4. stage the Sample without exposing bytes to evidence
  5. collect Observer records, Guardian decisions, facts, metrics, and Artifact identities
  6. destroy the instance and require residual closure
  7. derive evidence-bound Findings and a conservative disposition
  8. seal semantic and operational evidence independently

Case root
  1. audit permission, link, executable, and special-file drift without mutation
  2. declare static, external-uncontrolled, or controlled execution status
  3. hash every regular file and bind every relative path and mode
  4. fail closed if the tree changes during capture
  5. write a private atomic Case Snapshot outside the Case root
```

The ordered Actor list is part of the Scenario identity. Trial identity additionally binds the Security implementation, evidence schema revision, Range adapter and substrate, and each Actor implementation identity. Actor invocation is sequential in the current process, but all proposals are collected before any world mutation; therefore the semantic tick is simultaneous.

## Core contracts

### `ScenarioManifest`

Binds Scenario revision, Range identity, ordered Actors, backend identities and configuration digests, objectives, allowed actions, tick limit, and experiment metadata. Its canonical digest participates in Trial identity.

### `ActorBackend`

Starts an Actor session, receives only that Actor's observation, returns an `ActionProposal`, receives the resolved result, and produces a stop receipt.

Active implementations:

- scripted sequence baseline;
- `NativeHarnessActorBackend`, using DeepSeek Flash through the bounded Harness domain loop.

The first model-backed variant is P0-A: Provider and Harness are consumed, while exact Host and Runtime revisions plus explicit non-consumption modes remain in Actor identity. P0-B and P0-C add Host and Runtime one layer at a time. See [`AGENT-EXPERIMENT-P0.md`](AGENT-EXPERIMENT-P0.md).

Planned implementations:

- Host-assigned Native Harness Actor;
- Runtime-executed Native Harness Actor;
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

## Evaluation Trial P0

Evaluation Trial is a separate Security execution path for authorized software assessment. It does not reuse the Contest state machine and does not model a software Sample as an Actor.

The active local contracts are `SampleIdentity`, `SampleVault`, `AuthorityManifest`, `GuardianPolicy`, `ObservationPlan`, `EnvironmentIdentity`, `EvaluationSpec`, `EvaluationRangeBackend`, `Finding`, `EvaluationDisposition`, and `EvaluationResult`.

The `FixtureEvaluationBackend` verifies staged bytes and emits configured records but declares `sampleExecution: false` and never invokes Sample code. It proves admission, identity, failure handling, destruction, residual closure, and evidence before a disposable-machine provider is admitted.

The `LocalStaticEvaluationBackend` invokes admitted classical analyzers without loading or invoking Sample code. SampleVault revision 2 streams large imports through private staging and supports quotas and recovery. Native analyzer reports are staged before backend destruction and sealed as verified Artifacts in Evaluation Evidence schema revision 2. Current analyzers cover file identity, 7-Zip inventory, ClamAV, and imported native reports; they remain Observers rather than truth or Guardian authorities.

Observer and Guardian are separate authorities. Observer records may support a Finding but cannot alter the environment. Guardian decisions represent hard boundary enforcement and may terminate a Run without inventing a Finding. A Run is invalid when Sample verification, backend execution, or residual closure is incomplete.

Current Runtime `contained_local` remains outside dynamic Sample execution because it does not provide hostile-code isolation, management-plane egress control, or disposable-machine semantics. Static Evaluation runs locally but permits only declared non-executing analyzers. The candidate Windows KVM backend is an external QEMU/KVM integration behind `EvaluationRangeBackend`; it is restricted to the Ordivon benign fixture until real acceptance succeeds. See [`EVALUATION-TRIAL-P0.md`](EVALUATION-TRIAL-P0.md), [`STATIC-EVALUATION-P0.md`](STATIC-EVALUATION-P0.md), and [`WINDOWS-KVM-P0.md`](WINDOWS-KVM-P0.md).

## Case Snapshot P0

Case Snapshot is a separate metadata path for analysis directories that evolve after a sealed Evaluation. It does not reuse Evaluation truth, Findings, Guardian authority, or residual closure. A read-only quarantine audit records permission and executable drift. A snapshot binds relative paths, modes, byte lengths, complete file digests, execution status, limitations, linked Evaluation Run identities, and exact Security source identity.

A local Wine fuzz run of one retained component occurred outside an admitted disposable-machine backend. Its stdout and stderr remain historical material under `external-uncontrolled-execution`; they do not prove the stronger behavioral conclusions later written into a human report. See [`CASE-SNAPSHOT-P0.md`](CASE-SNAPSHOT-P0.md).

## Windows KVM Provider P0

The candidate Provider uses QEMU/KVM from WSL because the actual Windows 11 Home host lacks Windows Sandbox and the complete Hyper-V VM management stack while exposing a functional `/dev/kvm`. The base builder seals an exact Windows 11 Enterprise Evaluation image. Each Run creates a qcow2 overlay, UEFI variables copy, TPM state, FAT Run disk, and QMP socket, then removes the complete Run directory after execution.

No network device is configured. QMP `query-pci` is the management-plane authority and terminates the Run if a network-class PCI device appears. The Guest report remains an Observer. P0 binds the exact compiled benign Sample digest and compilation-attestation digest into Provider execution identity; relabelling another PE is insufficient. Unknown Samples remain prohibited until a later explicit gate. See [`WINDOWS-KVM-P0.md`](WINDOWS-KVM-P0.md).

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
| disposable Windows machine lifecycle and no-network topology | candidate QEMU/KVM Provider integrated by Security; hypervisor mechanics remain QEMU/KVM |
| Scenario, Contest, Campaign, organization, Range semantics, scoring | Security |
| promoted cross-domain protocols | Computing |

Security may request a Harness or Runtime change but must not copy their state machines.

## Next integration sequence

1. retain the implemented Security CAGE team-plan catalog, Domain Tool Bridge, Native Harness Actor, and fail-closed Provider mapping;
2. complete the first retained DeepSeek Flash Red/Blue P0-A Contest;
3. add the Host-assigned P0-B variant without changing the Security workload;
4. add the Runtime-executed P0-C variant and compare recovery/cancellation effects;
5. expand from team-plan control to parameterized CAGE Action Proposals where experiments require it;
6. add Campaign and organization state only when multi-Actor experiments consume it;
7. introduce containerlab, an independent management plane, and Zeek telemetry;
8. add CALDERA as a TTP execution adapter, not as Campaign authority;
9. connect Codex and Hermes as delegated Harness baselines in planner-only, Tool-proxy, and black-box modes.

Evaluation integration proceeds independently:

1. retain P0 local contracts, streaming Vault, static backend, report Artifacts, quarantine audits, and Case Snapshots;
2. preserve external uncontrolled executions as limited historical Case material rather than Evaluation truth;
3. build and seal the exact Windows KVM base image from a clean Security revision;
4. admit the candidate only after the maintained benign fixture proves management-plane no-network topology, bounded execution, evidence export, destruction, and residual closure;
5. add Guest and network Observers without giving them Guardian authority;
6. require a separate explicit gate before any unknown Sample;
7. add mature static analyzers only when an observed evidence gap justifies the adapter;
8. connect Harness only to structured evidence summaries, never raw Sample bytes.

## Explicit non-goals

The repository will not implement its own hypervisor, container runtime, topology engine, C2 framework, exploit database, scanner, EDR/SIEM, generic model router, generic Job system, policy language, RL trainer, or signing infrastructure unless a measured domain gap survives mature alternatives.
