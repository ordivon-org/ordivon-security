---
schema_version: 1
id: security.migration.round1
title: Security migration round 1
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
  - agent
updated: 2026-08-04
summary: Scope, decisions, implementation, and acceptance criteria for replacing the Round 1 single-Actor framework with the first multi-Actor Contest core.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
---
# Security migration round 1

## Chosen stage

The first migration round combines three inseparable steps:

1. freeze the previous research runtime as historical evidence;
2. establish a locked Python 3.12 `src/` project;
3. implement a complete deterministic multi-Actor Contest loop.

CAGE, model Providers, Harness, containerlab, CALDERA, and Campaign state are intentionally deferred. Adding them before proving the Contest boundary would force external capabilities into the obsolete single-Actor `WorldAdapter.step()` shape.

## Removed active machinery

The following Round 1 packages and scripts no longer define current behavior:

- `ordivon_security_experiments`;
- `ordivon_security_evaluations`;
- their single-Actor Trial runner, command-backed actors, CAGE baseline wrapper, old Trace/evidence format, reports tests, and shell entry points.

The code remains recoverable from Git revision `92c0f9497741c3cde542c347318d2372fb884e30`. Reports, fixture, and retained evidence remain in the repository archive.

## New active contracts

- `ScenarioManifest` — exact Range, ordered Actor, backend, objective, Action grant, limit, and metadata identity;
- `ActorBackend` — session start, proposal, result observation, and stop receipt;
- `RangeBackend` — create, observe, admit, resolve, truth, metrics, terminal, destroy;
- `ActionProposal` / `ActionAdmission` / `ActorActionResult`;
- `ContestRunner` — proposal barrier and deterministic simultaneous resolution;
- `EvidenceRecorder` — Actor, management, sensor, and truth hash chains;
- `ContestResult` — raw metrics plus evidence identity.

## Proved in this round

- Red and Blue are separately controlled actors;
- both submit proposals before the Range mutates;
- actor observation is distinct from hidden truth;
- Range admission rejects identity, tick, grant, or action drift;
- a simultaneous Blue isolation prevents a Red pivot;
- a passive Blue permits Red exfiltration;
- same Scenario and seed reproduce the same Trial and evidence digest;
- modified event bytes fail evidence verification;
- raw metrics preserve facts and units instead of forcing a fixed normalized score vector.

## Not proved

- fidelity to real cyber operations;
- model-backed autonomy;
- durable Harness recovery;
- asynchronous or long-running effects;
- multi-member organizations;
- Campaign revision;
- external sensor evasion;
- CAGE, container, or VM transfer.

## Acceptance commands

```bash
uv sync --locked
uv run python -m unittest discover -s tests -v
uv run ordivon-security-micro --output .artifacts/reactive --blue reactive
uv run ordivon-security-micro --output .artifacts/sleepy --blue sleepy
uv build
```

The next round begins with a full CAGE 4 Range adapter. Harness changes are deferred until Security can expose a stable domain Tool catalog rather than tunnelling actions through opaque shell execution.
