# Experimental adversarial research layer

Status: implemented research substrate; not Protocol and not a production control plane

## Purpose

`ordivon_security_experiments` is the smallest executable layer needed to test
claims about adaptive opposition without expanding the frozen Campaign
lifecycle/evidence substrate.

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
  reset → observe → step → truth → judge
```

A World controls action semantics and authoritative state. An Actor receives only
its declared observation and allowed action list. Security records the relation;
it does not reinterpret component-native truth.

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

Hermes and Codex are adapters behind `CommandDecisionActor`. Future Ordivon Host
integration should replace repeated stateless CLI startup; Security should not
own a second model-session implementation.

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

## Evidence

Every Trial writes:

```text
experiment-spec.json
trials/<trial>/trace.jsonl
trials/<trial>/result.json
trial-index.json
summary.json
```

JSONL traces are append-only within one run and receive a deterministic SHA-256
digest. The repository ignores raw artifacts and stores only sanitized evidence
summaries and their source digests under [`../evidence/experiments/`](../evidence/experiments/).

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

## Promotion and deletion rules

Retain an experiment record only when it supports more than one World or actor
family. Promote nothing to Protocol until it is required by another Ordivon
project and survives a simpler baseline. Delete the local fixture if a mature
external environment can produce the same diagnostic signal at comparable cost.
