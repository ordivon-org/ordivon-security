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
summary: Canonical entry to the authorized multi-Actor adversarial Contest laboratory and its first deterministic executable core.
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

Its central executable object is a **Contest**: multiple goal-bearing actors receive different observations, propose actions concurrently, act through an authoritative Range, and leave independently verifiable evidence. Cyber is the first domain. Campaigns, organizations, deception, adaptation, and coevolution are the next research layers—not substitutes for a working Contest.

## Current capability

The active `0.1` core now provides:

- a multi-Actor `ScenarioManifest`;
- actor-specific observations separated from hidden world truth;
- simultaneous Action Proposals followed by explicit admission and deterministic resolution;
- an authoritative `RangeBackend` contract;
- raw metrics before derived scores;
- four independent hash-chained evidence channels: Actor, Range management, sensor, and world truth;
- deterministic replay and evidence verification;
- a small Red/Blue synthetic Range proving the complete loop.

It does **not yet** provide CAGE control, model-backed actors, containerlab, CALDERA, Zeek, Campaign execution, or production cyber operations. Those are staged integrations after the Contest semantics are stable.

## Run the first Contest

Python 3.12 is the supported interpreter.

```bash
uv sync --locked
uv run ordivon-security-micro --output .artifacts/reactive --blue reactive
uv run ordivon-security-micro --output .artifacts/sleepy --blue sleepy
```

The reactive Blue baseline detects the web foothold and isolates the vault before Red pivots. The sleepy Blue baseline allows Red to establish two footholds and exfiltrate protected data. Each run writes a sealed evidence bundle containing:

```text
manifest.json
raw-metrics.json
result.json
bundle-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
```

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

Security does not rebuild model providers, general Agent harnesses, process runtimes, hypervisors, container engines, C2 frameworks, scanners, SIEMs, or generic workflow systems. Host, Harness, Runtime, World, external ranges, and mature security tools retain those responsibilities.

## Native and delegated actors

The planned actor surfaces are deliberately distinct:

- **Native Harness Actor** — Ordivon Harness owns the Agent loop and calls a model API such as DeepSeek.
- **Delegated Harness Actor** — Codex App Server, Hermes ACP, or another complete Harness owns its internal loop and is attached through a driver.
- **Scripted/RL Actor** — deterministic baselines and learned policies use the same Contest boundary.

DeepSeek is a model Provider. Codex and Hermes are complete external Harnesses; they are not classified as equivalent providers.

## Historical Round 1

The former single-Actor experiment/evaluation framework is frozen at Git revision `92c0f9497741c3cde542c347318d2372fb884e30`. Its reports, fixture, and retained evidence remain under [`docs/archive/round1/`](docs/archive/round1/) and [`evidence/`](evidence/). They remain valid historical evidence but no longer define active APIs.

## Read next

- [`CHARTER.md`](CHARTER.md) — project purpose and ownership;
- [`docs/architecture.md`](docs/architecture.md) — active contracts and staged integrations;
- [`docs/MIGRATION-ROUND-1.md`](docs/MIGRATION-ROUND-1.md) — first migration scope and acceptance;
- [`docs/research-agenda.md`](docs/research-agenda.md) — research sequence and falsifiers;
- [`docs/research-boundary.md`](docs/research-boundary.md) — authorization and external-effect limits;
- [`evidence/README.md`](evidence/README.md) — active and historical evidence contracts.
