---
schema_version: 1
id: security.start
title: Ordivon Security
type: start
profile: organization
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
summary: Canonical entry to the authorized multi-Actor adversarial Contest laboratory, deterministic core, and pinned CAGE 4 Range.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.architecture
  - security.research-agenda
  - security.research-boundary
  - security.evidence
  - security.authority
---
# Ordivon Security

Ordivon Security is an **authorized adversarial-Agent laboratory** for studying autonomous Red, Blue, neutral, observer, and evaluator actors in contested digital worlds.

Its central executable object is a **Contest**: multiple goal-bearing actors receive different observations, propose actions concurrently, act through an authoritative Range, and leave independently verifiable evidence. Cyber is the first domain. Campaigns, organizations, deception, adaptation, and coevolution are later research layers—not substitutes for a working Contest.

## Current capability

The active `0.3` core provides:

- a multi-Actor `ScenarioManifest`;
- actor-specific observations separated from hidden world truth;
- simultaneous Action Proposals followed by explicit admission and deterministic resolution;
- an authoritative `RangeBackend` contract;
- raw metrics before derived scores;
- four independent deterministic hash-chained evidence channels: Actor, Range management, sensor, and world truth;
- a separate operational evidence chain for wall-clock duration, Provider, retry, and lifecycle facts;
- fail-closed tick semantics for Actor failure and rejected proposals;
- Trial identity binding the Security implementation, evidence schema, Range adapter/substrate, and Actor implementations;
- deterministic replay and evidence verification;
- a small synthetic Red/Blue Range proving the core loop;
- a first-class, revision-pinned CAGE Challenge 4 Enterprise Range.

In the CAGE adapter, one Security Red Actor controls the CAGE Red team and one Security Blue Actor controls five CAGE Blue agents. Every Red and Blue CAGE action is explicitly supplied by Ordivon to the joint step; Green agents remain CAGE-controlled environmental actors. The current action surface is intentionally narrow: each side selects either the pinned native team policy or Sleep. Parameter-level model control is a later integration.

It does **not yet** provide model-backed actors, containerlab, CALDERA, Zeek, Campaign execution, or production cyber operations.

## Run the deterministic Contest

Python 3.12 is the supported interpreter.

```bash
uv sync --locked
uv run ordivon-security-micro --output .artifacts/reactive --blue reactive
uv run ordivon-security-micro --output .artifacts/sleepy --blue sleepy
```

The reactive Blue baseline detects the web foothold and isolates the vault before Red pivots. The sleepy Blue baseline allows Red to establish two footholds and exfiltrate protected data.

## Run the pinned CAGE 4 Range

```bash
scripts/bootstrap_cage4.sh

uv run --extra cage ordivon-security-cage4 \
  --source .cache/cage4 \
  --output .artifacts/cage-native-native \
  --steps 3 \
  --seed 1 \
  --red native \
  --blue native
```

The bootstrap command checks out exactly:

```text
cage-challenge/cage-challenge-4
8c3c50ca54b176c2de199847944e8dcc035497e3
```

The adapter rejects revision drift, a dirty CAGE source tree, and imports from an unexpected checkout. Local source paths are operator configuration and do not alter Trial identity.

Every run writes a sealed evidence bundle:

```text
manifest.json
trial-identity.json
raw-metrics.json
result.json
bundle-manifest.json
operational-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
  operational.jsonl
```

The deterministic bundle and non-deterministic operational bundle verify independently. CAGE metrics additionally bind the source revision, explicit external action count, Red/Blue agent counts, native actions executed, mission phases, rewards, and Red footholds.

## Active architecture

```text
ScenarioManifest
  → ContestRunner
  → ActorBackend[]
  → ActionProposal[]
  → Range admission
  → simultaneous resolution
  → Actor result + sensor telemetry + hidden truth
  → raw metrics + sealed evidence
```

Security owns the adversarial domain semantics: Scenario, Contest, Campaign and organization hypotheses, actor information boundaries, domain action admission, Range truth, scoring, and adversarial evaluation.

Security does not rebuild model Providers, general Agent Harnesses, process runtimes, hypervisors, container engines, C2 frameworks, scanners, SIEMs, or generic workflow systems. Host, Harness, Runtime, World, external ranges, and mature security tools retain those responsibilities.

## Native and delegated actors

The planned actor surfaces remain distinct:

- **Native Harness Actor** — Ordivon Harness owns the Agent loop and calls a model API such as DeepSeek.
- **Delegated Harness Actor** — Codex App Server, Hermes ACP, or another complete Harness owns its internal loop and is attached through a driver.
- **Scripted/RL Actor** — deterministic baselines and learned policies use the same Contest boundary.

DeepSeek is a model Provider. Codex and Hermes are complete external Harnesses; they are not equivalent Provider adapters.

## Historical Round 1

The former single-Actor experiment/evaluation framework is frozen at Git revision `92c0f9497741c3cde542c347318d2372fb884e30`. Its reports, fixture, and retained evidence remain under [`docs/archive/round1/`](docs/archive/round1/) and [`evidence/`](evidence/). They remain valid historical evidence but no longer define active APIs.

## Read next

- [`CHARTER.md`](CHARTER.md) — project purpose and ownership;
- [`docs/architecture.md`](docs/architecture.md) — active contracts and integrations;
- [`docs/MIGRATION-ROUND-1.md`](docs/MIGRATION-ROUND-1.md) — Contest Core replacement;
- [`docs/MIGRATION-ROUND-2.md`](docs/MIGRATION-ROUND-2.md) — first-class CAGE 4 Range;
- [`docs/MIGRATION-ROUND-3-P0.md`](docs/MIGRATION-ROUND-3-P0.md) — fail-closed model prerequisites, execution identity, and evidence separation;
- [`docs/research-agenda.md`](docs/research-agenda.md) — research sequence and falsifiers;
- [`docs/research-boundary.md`](docs/research-boundary.md) — authorization and external-effect limits;
- [`evidence/README.md`](evidence/README.md) — active and historical evidence contracts.
