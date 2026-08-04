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
updated: 2026-08-04
summary: Canonical boundary for high-intensity experiments inside owned or explicitly authorized ranges, with independent management truth and no undeclared third-party effects.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.architecture
  - security.migration.round1
  - security.authority
---
# Research boundary

## Decision

Ordivon Security may run high-intensity autonomous offensive, defensive, deceptive, persistent, multi-node, and multi-Agent experiments only inside worlds that Ordivon owns or has explicit authority to test.

The declared Range must have an independent management plane capable of creating, freezing, observing, resetting, and destroying the world without relying on the evaluated actors. Outside that Range, reachability is not authority and undeclared effects invalidate the Trial.

## Permitted internal intensity

Inside a declared authorized Range, an experiment may grant:

- broad Agent autonomy and long execution;
- writable systems and realistic services;
- range-local Tool creation and modification;
- persistence, credentials, footholds, and multi-node action;
- adaptive Red, Blue, neutral, service, observer, and evaluator actors;
- deception, counter-deception, hidden objectives, compromised teammates, and collusion;
- interruption, replacement, recovery, withdrawal, escalation, and reorganization;
- realistic resource scarcity and changing mission value.

The boundary exists to make stronger experiments valid, not to turn evaluated actors into passive demonstrations.

## Prohibited external effects

Outside the declared Range:

- unrelated public or third-party systems are not targets;
- personal and production credentials are absent;
- Provider/API connectivity does not grant target authority;
- actor-generated target expansion is not admitted;
- real-world persistence, scanning, exploitation, denial, credential collection, or lateral movement is prohibited;
- undeclared external effects invalidate the Trial and must be investigated as a containment failure.

## Plane separation

A valid high-fidelity Range separates:

1. **management plane** — deploy, reset, truth, freeze, destroy;
2. **actor plane** — evaluated Red/Blue/neutral workspaces and services;
3. **Provider plane** — model/Harness connectivity outside the contested network;
4. **sensor plane** — fallible telemetry available to defenders or evaluators;
5. **truth plane** — out-of-band state inaccessible to evaluated actors.

An actor may attack or manipulate admitted sensor and service surfaces when the experiment requires it. It may not receive management-plane credentials or silently redefine the Range boundary.

## Reuse boundary

Security composes mature hypervisors, containers, operating systems, network emulators, cyber ranges, scanners, fuzzers, analysis tools, C2/TTP libraries, identity systems, telemetry, forensics, and recovery mechanisms. It does not claim novelty or authority over those implementations.

Security's own code is justified where intelligent opposition creates a domain distinction: Contest structure, asymmetric observation, Action admission, Campaign revision, opponent models, deception, organization, strategic outcomes, or adversarial evaluation.

## Evidence requirements

Every Range-backed Trial must bind:

- authorization and Range identity;
- management-plane implementation and revision;
- Actor/Harness/Provider identity;
- target topology and image revisions;
- network egress policy;
- Action grants and budgets;
- sensor sources and known blind spots;
- independent truth collection;
- reset and destroy receipts;
- all detected boundary violations.

## Historical control-boundary result

The archived R-A evaluation remains useful: model-only instructions and global risk thresholds did not preserve provenance, UNKNOWN reconciliation, evidence completeness, or replacement continuity. Those generic facts remain owned by Host, Harness, and Runtime. Security owns the adversarial Scenario, Range boundary, domain admissions, and evaluation evidence rather than rebuilding a generic control platform.

Current execution is defined by [`architecture.md`](architecture.md) and [`MIGRATION-ROUND-1.md`](MIGRATION-ROUND-1.md). Historical Round 1 protocols remain under [`archive/round1/`](archive/round1/).
