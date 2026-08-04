---
schema_version: 1
id: security.migration.round2
title: Security migration round 2
type: closeout
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - maintainer
  - builder
  - researcher
  - evaluator
  - agent
updated: 2026-08-04
summary: Scope, implementation, and acceptance for promoting pinned CAGE Challenge 4 from a baseline wrapper to a first-class Ordivon Range.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.migration.round1
  - security.architecture
  - security.evidence
---
# Security migration round 2

## Chosen stage

Round 2 promotes CAGE Challenge 4 from an external baseline measurement into an authoritative `RangeBackend` controlled by the active multi-Actor Contest core.

This stage precedes model-backed actors. Without a real external Range contract, adding DeepSeek would only produce model text around the synthetic fixture or recreate the removed command-backed provider path.

## Pinned substrate

```text
repository: https://github.com/cage-challenge/cage-challenge-4.git
revision: 8c3c50ca54b176c2de199847944e8dcc035497e3
scenario: EnterpriseScenarioGenerator
```

CAGE remains external source and is installed through the optional `cage` dependency group. Security does not vendor or fork the simulator.

The pinned source still imports the unmaintained `gym` package and emits its upstream warning. Round 2 locks `gym==0.26.2` and `numpy==1.26.4` for reproduction rather than silently rewriting CAGE imports. A future source revision migration must be evaluated as substrate drift.

## New active surface

```text
Cage4RangeConfig
Cage4RangeBackend
ordivon-security-cage4
scripts/bootstrap_cage4.sh
```

The Range validates exact source revision, requires a clean checkout, verifies import provenance, and binds policy configuration into Scenario identity. Machine-local checkout paths are deliberately excluded from the semantic digest.

## Team-plan bridge

The Enterprise Scenario creates one Red agent, five Blue agents, and the Green population. Security exposes two actors:

```text
actor:red
actor:blue
```

Each side currently proposes one of:

```text
cage.team.native-policy
cage.team.sleep
```

The native plan asks the pinned CAGE policy for the concrete action. The sleep plan constructs `Sleep`. Security then passes every Red and Blue action explicitly in the joint action dictionary. Green remains CAGE-controlled.

This is materially different from the archived Round 1 wrapper, which called `parallel_step()` without externally controlling Red or Blue.

## Proved in this round

- CAGE is an active `RangeBackend`, not a side report generator;
- Security Red and Blue Actors receive different CAGE observations;
- Action Proposals pass normal Contest admission;
- every CAGE Red and Blue agent receives an explicit Ordivon-submitted action each tick;
- CAGE default Red/Blue action usage is zero;
- Green agents continue to provide native background dynamics;
- concrete CAGE actions appear in effects and raw metrics;
- source revision, policy configuration, action counts, rewards, mission phases, and footholds enter evidence;
- identical source, Scenario, plans, and seed reproduce Trial identity, metrics, and evidence digest;
- local checkout paths do not change experiment identity;
- the CAGE `steps - 1` termination convention is normalized to Security tick semantics.

A three-tick native Red/native Blue smoke run produced concrete actions including discovery, monitoring, decoy deployment, removal, restoration, and sleep while submitting all eighteen Red/Blue actions explicitly.

## Not proved

- model-backed autonomous strategy;
- arbitrary parameterized CAGE action construction;
- policy quality or a general Red/Blue capability ranking;
- durable Harness pause, resume, or Provider replacement;
- Campaign or organizational adaptation;
- transfer from simulation to container or VM ranges;
- real network effects.

The native CAGE policy is a transitional action executor. Security owns the side-level choice and evidence boundary, but the native policy still chooses the concrete action under `cage.team.native-policy`.

## Acceptance

```bash
scripts/bootstrap_cage4.sh

ORDIVON_CAGE4_SOURCE=.cache/cage4 \
  uv run --extra cage python -m unittest discover -s tests -v

uv run --extra cage ordivon-security-cage4 \
  --source .cache/cage4 \
  --output .artifacts/cage-native-sleep \
  --steps 3 \
  --seed 1 \
  --red native \
  --blue sleep

uv run --extra cage ordivon-security-cage4 \
  --source .cache/cage4 \
  --output .artifacts/cage-native-native \
  --steps 3 \
  --seed 1 \
  --red native \
  --blue native
```

## Next round

Round 3 should add a dependency-inverted Domain Tool Bridge to Ordivon Harness, then attach Native Harness Actors using DeepSeek Flash. Security should expose non-secret Tool and model identities; credential selection, leasing, retry, and Provider invocation belong to Harness. Initial model experiments can select CAGE team plans before the action surface expands to parameterized native actions.
