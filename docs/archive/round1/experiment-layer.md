---
schema_version: 1
id: security.archive.round1.experiment-layer
title: Round 1 experimental adversarial research layer
type: archive
profile: research
lifecycle: historical
source_role: supporting
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - builder
  - evaluator
  - agent
updated: 2026-08-04
summary: Historical protocol for the removed single-Actor ExperimentSpec, WorldAdapter, Decision, hidden record, scoring, and evidence framework.
evidence_status: verified
readiness: ARCHIVED
applies_to:
  - ordivon-security-round1
related:
  - security.archive.round1.system
---
# Round 1 experimental adversarial research layer

This document describes the framework frozen at Git revision `92c0f9497741c3cde542c347318d2372fb884e30`. It does not define active APIs.

## Historical question

What is the smallest executable layer that can test adaptive opposition while preserving exact experimental identity, epistemic separation, independently contestable evaluation, and immutable evidence?

## Historical protocol

Each Trial bound an `ExperimentSpec`, one evaluated Actor, a `WorldAdapter`, a Scorer, seeds, opponent policy, resource limits, and optional Provider or external-source identity. The World emitted an actor-specific Observation, the Actor returned one bounded Decision, the World applied the Effect while retaining hidden truth, and a separately identified Scorer evaluated a sealed record.

The framework preserved:

- exact Trial identity;
- actor-specific Observation separated from hidden World state;
- immutable Trace and evidence sealing;
- independent scoring and per-dimension outcomes;
- local scripted/model-backed baselines;
- a pinned CAGE 4 baseline wrapper;
- bounded evaluator and control-boundary attacks.

## Historical limitation

The execution shape was fundamentally single-Actor:

```text
one Actor → observe → decide → World.step → score
```

It could model a scripted opponent inside the World, but could not independently schedule Red and Blue actors, collect simultaneous proposals, represent explicit organizations, or attach durable Harness sessions cleanly. Its CAGE integration measured native policies rather than making Ordivon Actors first-class participants.

The active replacement is documented in [`../../MIGRATION-ROUND-1.md`](../../MIGRATION-ROUND-1.md) and [`../../architecture.md`](../../architecture.md). Exact historical tests and evidence digests are recorded in [`system.md`](system.md).
