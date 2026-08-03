---
schema_version: 1
id: security.research-boundary
title: Research boundary
type: decision
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - operator
  - builder
  - evaluator
  - agent
updated: 2026-08-03
summary: Canonical decision for high-intensity authorized adversarial experiments, external-effect prohibition, mature-substrate reuse, Agent-native ownership, and retained compositional control boundaries.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.architecture
  - security.experiment-layer
  - security.authority
---
# Research boundary

## Context

Useful adversarial research may require broad autonomy, writable systems, adaptive offense and defense, deception, persistence, and long execution. Without a precise boundary, the project either becomes an inert compliance exercise or creates invalid undeclared effects on systems it does not own.

## Decision

Permit high experimental intensity only inside owned or explicitly authorized Worlds with independent management and destroy capability. Outside that World, reachability is not authority, unrelated third-party systems are not targets, real personal or production credentials are absent, and undeclared external effects invalidate the experiment.

## Consequences

Security can study realistic adaptive opposition without owning a guardrail product, generic containment layer, or external control plane. Mature ranges, hypervisors, networks, scanners, identity, forensics, and recovery are reused. Security code must point to a concrete Agent-native experiment and remain separable from Host, Harness, Runtime, World, Game, and domain authority.

## Status

Accepted and active. [`architecture.md`](architecture.md) defines ownership, [`experiment-layer.md`](experiment-layer.md) defines current execution, and [`authority.md`](authority.md) records content authority. The retained R-A conclusion is compositional: provenance, UNKNOWN reconciliation, verification, evidence completeness, and replacement continuity remain with their natural owners; Security owns the adversarial scenario and evaluation evidence.

Ordivon Security is a high-intensity adversarial research project, not an
enterprise protection or compliance system.

## Internal experimental intensity

Inside an owned or explicitly authorized range, experiments may grant:

- broad Agent autonomy;
- writable systems and real services;
- range-local Tool creation and modification;
- persistent range-local state;
- multi-node and multi-Agent coordination;
- adaptive offensive and defensive actors;
- deception, counter-deception, hidden objectives, and asymmetric information;
- long execution, interruption, replacement, and recovery;
- realistic resource scarcity and changing mission value.

The purpose of the boundary is to permit stronger experiments with valid
world truth, not to make the evaluated actors passive.

## External authority boundary

Outside the declared world:

- reachability is not authority;
- unrelated public or third-party systems are not targets;
- real personal and production credentials are absent;
- world-management authority remains independent from evaluated actors;
- undeclared external effects invalidate the experiment;
- the range can be frozen and destroyed out of band.

These are authorization and experimental-validity requirements. They are not the
project's intellectual center and must not cause the repository to drift toward
guardrails, policy engines, or generic containment products.

## Classical substrate reuse

Ordivon Security composes mature:

- hypervisors, containers, sandboxes, and operating systems;
- network emulators and cyber ranges;
- scanners, fuzzers, analysis tools, and patch systems;
- identity, secret, logging, forensic, and recovery systems;
- Agent evaluation and multi-Agent simulation frameworks.

It does not claim novelty for these mechanisms.

## Agent-native research boundary

The project owns research only where intelligent opposition creates a structural
problem that existing mechanisms do not adequately express or evaluate:

- strategic Campaign formation and revision;
- opponent modelling and belief state;
- deception and information position;
- initiative, tempo, escalation, and strategic resource allocation;
- multi-Agent adversarial organization;
- coevolution and transfer;
- evaluation under actors that model or manipulate the evaluator.

Any new code must point to a concrete experiment demonstrating this gap.

## R-A control-boundary closeout

The Game-to-Security R-A experiment showed that Security does not need a new
control platform. Model-only instructions and global risk/approval thresholds
failed low-risk evidence corruption and UNKNOWN recovery, while a fixed threshold
also blocked valid work when the monitor was unavailable. Direct native state
was materially stronger but still missed stale provenance, evidence omission,
provider-replacement continuity, evidence laundering, and reconcile-first
recovery.

The retained boundary is compositional:

- Host Context and source adapters bind provenance and current revision;
- Host/provider operation state reconciles UNKNOWN before redispatch;
- Host completion authority requires accepted independent verification;
- completion proposals bind the required evidence set, including unfavorable
  evidence;
- provider or Harness replacement emits an explicit continuity/reconstruction
  receipt rather than claiming hidden memory;
- observer failure changes evidence quality but is not a default veto;
- Security owns the adversarial scenario and evaluation evidence only.

No Campaign schema, lifecycle state, generic Hook layer, trust score, approval
plane, or duplicate component state was added.
