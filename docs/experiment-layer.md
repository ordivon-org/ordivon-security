---
schema_version: 1
id: security.experiment-layer
title: Experimental adversarial research layer
type: protocol
profile: research
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
summary: Canonical protocol for identity-bound adversarial Trials, actor-specific observations, hidden World records, independent scoring, immutable evidence, reproduction, promotion, and deletion.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security-experiments
related:
  - security.architecture
  - security.research-agenda
  - security.evidence
  - security.authority
---
# Experimental adversarial research layer

## Question

What is the smallest executable layer that can test adaptive opposition while preserving exact experimental identity, epistemic separation, independently contestable evaluation, and immutable evidence?

## Method

Bind every Trial to Actor, World, evaluator, seed, opponent, resources, and limits; expose only actor-authorized Observation and actions; let the World retain hidden truth; score a sealed hidden record through a separately identified Scorer; preserve complete Trace and independent outcome dimensions; compare scripted, structured, organizational, model-backed, local, and mature external baselines.

## Inputs

Inputs are an ExperimentSpec, Actor implementation, WorldAdapter, Scorer identity, seeds, opponent policies, resource and turn limits, optional provider configuration, and exact external-source identity for mature Worlds.

## Procedure

Reset Actor and World, obtain the actor-specific Observation, admit one bounded Decision, apply it through the World, record Effect and truth digest, repeat to terminal or bounded limit, emit the hidden evaluation record, independently score it, seal immutable Trial files, and aggregate only through references to individual Trials.

## Evidence

Each Trial retains a manifest, Trace, hidden evaluation record, result, and byte-level seal. Repository evidence contains sanitized summaries, exact digests, authority boundaries, limitations, null results, and retain, reduce, or delete decisions.

## Failure conditions

Reject a Trial or claim when identity is incomplete, hidden truth leaks to the Actor, a Decision is outside the allowed action set, World and Scorer identity are conflated, files are overwritten or unsealed, aggregate output loses Trial references, provider failure is omitted, or an external adapter changes native semantics without disclosure.

Status: implemented research substrate; not Protocol and not a production control plane

## Purpose

`ordivon_security_experiments` is the smallest executable layer needed to test
claims about adaptive opposition after removing the former Campaign lifecycle and
evidence machinery from active architecture.

It answers six practical questions:

1. can one experiment bind exact Actor, World, opponent, judge, resource, and
   seed identity;
2. can authoritative World truth remain separate from Actor observations;
3. can scripted, structured, organizational, and model-backed actors use one
   narrow decision interface;
4. can every decision be linked to its observation, effect, and World-truth
   digest;
5. can tactical, operational, strategic, information, organization, evaluator,
   validity, and cost outcomes remain separate;
6. can mature external worlds be adapted without copying their state or
   dependencies into Security.

## Deliberate non-architecture

The layer does **not** define a universal `Actor`, `Contest`, `Campaign`, belief,
organization, or strategic-outcome ontology. Its records are experiment-local
Python dataclasses and JSON files. Promotion requires evidence from more than one
world and a deletion comparison against existing Host, Game, evaluation, and
workflow structures.

## Core records

```text
ExperimentSpec
├─ ActorIdentity
├─ WorldIdentity
├─ EvaluationIdentity
├─ seeds
├─ opponent policies
└─ resource and turn limits

Trial
├─ Observation
├─ Decision
├─ Effect
├─ authoritative World-truth digest
└─ TrialOutcome
```

`TrialOutcome` reports independently:

```text
validity
 tactical
 operational
 strategic
 information
 organization
 evaluator_integrity
 cost
```

No aggregate deletes the individual Trial records.

## Interfaces

The runner depends on two narrow protocols:

```text
Actor
  reset → decide → update → usage

WorldAdapter
  reset → observe → step → truth → evaluation_record

Scorer
  versioned identity → score sealed hidden record
```

A World controls action semantics and authoritative state. An Actor receives only
its declared observation and allowed action list. The World emits a hidden
evaluation record after execution; an independently identified Scorer computes
the outcome. Security records the relation without making the executing World
the sole authority over its own score.

## Local dynamic-opponent fixture

`MicroContestWorld` is a deterministic, two-route research fixture with:

- hidden decoy and guarded routes;
- actor-specific observations;
- scan, verify, exploit, wait, and withdraw actions;
- energy, stealth, exposure, and turn budgets;
- defense-phase rotation;
- an adaptive opponent that can shape the route first examined;
- stale evidence after policy change;
- tactical success that can be strategically harmful.

It exists to expose experiment and modelling errors quickly. It is not a cyber
range, game engine, or evidence that a policy transfers to real cyber operations.

## Actor baselines

- `GreedyActor` — trusts the first attractive route;
- `OpponentAwareActor` — maintains three explicit competing hypotheses and
  evidence-triggered revision;
- `CommitteeActor` — compares a commander-plus-specialists organization under
  compromise and compartmentalization;
- `CommandDecisionActor` — invokes a bounded command provider and accepts one
  JSON decision from an allowed action set.

Hermes and Codex are adapters behind `CommandDecisionActor`. Future Ordivon Harness integration should replace repeated stateless CLI startup; Security should not own a second model-session implementation.

## Mature external World

The CAGE Challenge 4 adapter pins:

```text
repository: https://github.com/cage-challenge/cage-challenge-4.git
revision:   8c3c50ca54b176c2de199847944e8dcc035497e3
```

The bootstrap installs only the simulation slice required for baseline runs. It
does not install Ray, Torch, graph-learning, training, or GUI stacks. The source
remains an external checkout and is never vendored into this repository.

The adapter preserves CAGE-native facts, including its native time type, mission
phase, actions, rewards, sessions, and foothold state. It does not coerce them
into Security lifecycle semantics.

## Evidence artifacts

Every family writes `experiment-spec.json`, `trial-index.json`, and
`summary.json`. Every Trial is an immutable atomic evidence unit:

```text
trials/<identity-bound-trial>/
├── trial-manifest.json
├── trace.jsonl
├── hidden-evaluation-record.json
├── result.json
└── seal.json
```

The Trial key binds the complete ExperimentSpec, Actor, World, Scorer, seed,
opponent policy, and turn limit. Files are written in a private staging
directory, sealed by exact byte length and SHA-256, synchronized, and atomically
renamed. An existing Trial directory cannot be overwritten. The hidden record
is excluded from Actor Context but retained for offline rescoring.

The repository ignores raw artifacts and stores only sanitized evidence summaries
and their source digests under [`../evidence/experiments/`](../evidence/experiments/).

## Reproduction

Deterministic local acceptance:

```bash
./scripts/run_round1_acceptance.sh
```

Pinned CAGE 4 baseline:

```bash
./scripts/bootstrap_cage4.sh
PYTHONPATH="$PWD/.cache/cage4" \
  .venv-cage4/bin/python scripts/run_cage4_baseline.py \
  --source "$PWD/.cache/cage4" \
  --output artifacts/round1/cage4 \
  --seeds 1,2,3,4,5 \
  --steps 60
```

Optional model-backed diagnostic Trials:

```bash
python3 scripts/run_adversarial_experiment.py \
  --actor hermes-strategic \
  --seeds 101 \
  --opponents adaptive-counter \
  --max-turns 6 \
  --output artifacts/round1/hermes-strategic

python3 scripts/run_adversarial_experiment.py \
  --actor codex-strategic \
  --seeds 101 \
  --opponents adaptive-counter \
  --max-turns 6 \
  --output artifacts/round1/codex-strategic
```

Model Trials depend on locally configured providers, are not CI gates, and must
not be interpreted as provider benchmarks from one seed.

See [`P0-CORE-A-CONSTRAINT-AUDIT.md`](P0-CORE-A-CONSTRAINT-AUDIT.md) for the A-series ownership and constraint review.

## Promotion and deletion rules

Retain an experiment record only when it supports more than one World or actor
family. Promote nothing to Protocol until it is required by another Ordivon
project and survives a simpler baseline. Delete the local fixture if a mature
external environment can produce the same diagnostic signal at comparable cost.
