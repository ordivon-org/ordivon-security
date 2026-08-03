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
updated: 2026-08-03
summary: Canonical architecture separating strategic adversarial research, experiment-local records, bounded evaluations, mature external Worlds, cross-project ownership, and archived Campaign infrastructure.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.experiment-layer
  - security.research-boundary
  - security.authority
---
# Architecture

## Purpose

Separate Security's strategic research object from its smallest current executable experiment and evaluation substrates, while preventing historical Campaign infrastructure or mature external systems from becoming shadow authorities.

## Boundaries

Security owns adversarial relationship hypotheses, experiment identity, actor-specific observation, hidden evaluation records, independent scoring, strategic outcome dimensions, and adversarial evaluation scenarios. Host, Harness, Runtime, World, Game, and external cyber ranges retain their own state and execution authority.

## Components

The active repository consists of `ordivon_security_experiments`, `ordivon_security_evaluations`, local and external World adapters, scripted and model-backed Actor baselines, immutable Trial evidence, independent Scorers, analysis, and sanitized repository evidence. The former Campaign lifecycle substrate is archived and absent from active code.

## Data flow

An ExperimentSpec binds Actor, World, evaluator, seed, opponent policy, resources, and limits; the World emits actor-specific Observation; the Actor returns a bounded Decision; the World applies the Effect and retains hidden truth; a separately identified Scorer evaluates the sealed record; Security stores immutable Trace and per-dimension outcomes for comparison and diagnosis.

## Failure modes

The architecture fails when Actor context leaks hidden truth, Trial identity omits a changing condition, World execution certifies its own result without contestable evidence, aggregate scores erase dimensions, traces can be overwritten, external adapters copy authoritative state, model failures escape evidence, or archived infrastructure is treated as current behavior.

## Verification

Verification combines deterministic unit tests, local dynamic-opponent acceptance, sealed Trial artifacts, offline rescoring, exact source and implementation identity, optional pinned CAGE runs, bounded model diagnostics, and explicit null or deletion judgments. [`experiment-layer.md`](experiment-layer.md) defines the executable protocol, [`research-boundary.md`](research-boundary.md) defines authorization, and [`authority.md`](authority.md) records document authority. Current claims must link to retained evidence rather than document recency.

This document separates the **research architecture** from the repository's
currently implemented experimental-support substrate.

## Research architecture

```text
Strategic adversarial plane
  ├─ conflicting objectives and victory conditions
  ├─ opponent models and belief states
  ├─ initiative, tempo, escalation, withdrawal
  ├─ deception, counter-deception, deterrence, signalling
  └─ strategic resource and information allocation
                │
                ▼
Operational Campaign plane
  ├─ Campaign synthesis and revision
  ├─ intelligence requirements and collection
  ├─ phases, missions, branches, reserves, and contingencies
  ├─ adaptation history and counter-adaptation
  └─ multi-Agent command and organization
                │
                ▼
Tactical Agent plane
  ├─ reconnaissance, analysis, exploitation, detection
  ├─ repair, restoration, containment, and response
  ├─ tool selection and construction
  └─ action execution and feedback interpretation
                │
                ▼
Mature classical capability plane
  ATT&CK / D3FEND / Engage · scanners · fuzzers · sandboxes · IAM
  network controls · EDR/SIEM · forensics · patching · cyber ranges
                │
                ▼
Contested world plane
  hosts · services · code · identities · networks · data · tools · Agents
```

Ordivon Security's candidate ownership begins at the Operational Campaign plane
and becomes strongest at the Strategic Adversarial plane. The Tactical plane is
shared with Host and domain tools. Classical mechanisms and world execution are
reused from mature projects and the rest of Ordivon.

## Candidate research objects

The following are hypotheses, not frozen implementation contracts:

| Object | Research purpose |
|---|---|
| Actor | represent a goal-bearing participant's knowledge, beliefs, resources, capabilities, and organizational relations |
| Contest | represent the conflict structure across actors, world, rules, information, resources, and outcomes |
| Campaign | represent one actor's or coalition's long-horizon organized effort to change the Contest |
| Opponent model | represent hypotheses about another actor's objectives, beliefs, capabilities, policy, and adaptation |
| Information position | represent what each actor can observe, infer, hide, signal, or manipulate |
| Strategic outcome | evaluate objective progress, initiative, resources, information advantage, capability exposure, and future options |

No separate database, protocol, or universal schema should be created merely to
make this vocabulary look complete. The first requirement is a comparative model
and experiments showing where existing game, evaluation, cyber-range, and Agent
frameworks are insufficient.

## Cross-project responsibility

| Responsibility | Natural owner |
|---|---|
| Goal and Task continuity, commitment, uncertainty, verification, outcome | Host |
| Assignment, Run, Provider and Tool execution semantics | Harness |
| Workspace, Job, Attempt, Artifact, process and physical recovery | Runtime |
| external provider adapters and private operator tools | World |
| authoritative world mechanics, simulation, replay and domain rules | Game or domain system |
| promoted contracts and cross-project synthesis | Computing |
| adversarial relationship, opponent model, strategic outcome and evaluation research | Security |

Security consumes component-native identities and evidence. It must not create a shadow Host, Harness, Runtime, World provider, Game engine, scanner, cyber range, or external control plane.

## Current implemented substrate

The active code implements two deliberately bounded surfaces:

```text
ordivon_security_experiments
  ExperimentSpec / Actor / WorldAdapter / Observation / Decision / Trial
  hidden evaluation record / independent Scorer / immutable Trace / sealed evidence
  local dynamic-opponent fixture / model-backed actors / pinned CAGE adapter

ordivon_security_evaluations
  exact adversarial control-boundary scenarios
  paired baselines / evidence accounting / evaluator disagreement / dispositions
```

This substrate currently proves exact Trial identity, actor-specific observation, hidden World truth, independent scoring, immutable evidence, multi-dimensional outcomes, optional external-World adaptation, and bounded evaluation of provenance, reconciliation, evidence omission, and evaluator manipulation.

It does not prove real-world offensive or defensive capability, universal Contest or Campaign schemas, autonomous Campaign synthesis, robust opponent modelling, transfer across broad domains, production authorization, or safe uncontrolled external action.

The former Campaign Manifest, lifecycle ledger, coordinator, evidence bundle, process ports, and Link/Edge/Runtime composition are removed from active code. Their exact historical revision and reproduction command remain in the archive.

## Substrate freeze rule

The implemented substrate remains maintained and tested, but its vocabulary and
scope are frozen by default. Expansion requires all of the following:

1. a concrete adversarial experiment exposes an unrepresentable fact;
2. mature external frameworks cannot carry that fact without semantic loss;
3. the fact crosses component boundaries and cannot live naturally in Host,
   Runtime, Link, Edge, or Game;
4. a simpler experiment record or adapter is insufficient;
5. the new abstraction changes diagnosis, comparison, adaptation, or research
   validity in a measurable way.

## Research and experiment planes

A future experiment may use four operational planes without making them the
project's conceptual center:

- **world-management plane** — creates and destroys the owned range;
- **actor plane** — contains evaluated offensive, defensive, neutral, service,
  user, and observer actors;
- **observation plane** — preserves world truth and actor-specific observations;
- **evaluation plane** — computes multiple outcome dimensions and tests evaluator
  integrity.

The evaluated actors may study and attack one another. They must not receive
undeclared authority over the external world-management plane. This is a legal
and experimental-validity boundary, not a reason to weaken internal adversarial
capability.
