---
schema_version: 1
id: security.authority
title: Security Content Authority
type: decision
profile: organization
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - evaluator
  - agent
updated: 2026-08-03
summary: Decision separating Security's charter, current architecture, experiment protocol, research agenda, authorization boundary, evidence contract, reports, evaluations, and archived Campaign substrate.
evidence_status: not_applicable
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.start
  - security.charter
  - security.architecture
  - security.experiment-layer
  - security.research-agenda
  - security.research-boundary
  - security.evidence
---
# Security Content Authority

## Context

Security contains a strategic charter, research architecture, active experiment and evaluation code, research agenda, control-boundary studies, Round 1 reports, capability-gap notes, evidence summaries, and an archived Campaign substrate. Several documents accurately describe earlier states but cannot define current active machinery.

## Decision

[`../README.md`](../README.md) is the repository entry. [`../CHARTER.md`](../CHARTER.md) owns the research object and governing principles. [`architecture.md`](architecture.md) owns current architecture and cross-project responsibility. [`experiment-layer.md`](experiment-layer.md) owns the executable Trial protocol. [`research-agenda.md`](research-agenda.md) owns open research tracks and falsifiers. [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits. [`../evidence/README.md`](../evidence/README.md) owns repository evidence admission.

Source code, deterministic tests, exact ExperimentSpec and Trial artifacts, sealed hidden records, Scorer identity, pinned external-source revisions, evaluation reports, and reproduced results remain stronger owners for fields, behavior, metrics, and empirical claims. Round 1 reports, R-A evaluations, capability maps, constraint audits, and closeouts support or constrain the current boundary. [`archive/campaign-v0.md`](archive/campaign-v0.md) is historical reproduction authority only and cannot restore removed Campaign machinery to current architecture.

## Consequences

Only the current authority set enters strict content management in this adoption step. Existing phase, audit, report, result, and archive documents remain available without bulk conversion. Later human-centered reconstruction may publish clearer concepts, experiment walkthroughs, and comparative reports, but it must retain exact evidence and explicit supersession rather than treating narrative synthesis as machine truth.

## Status

Accepted and active. Reopen when active executable surfaces change, an external World or Host/Harness integration changes ownership, a research concept is promoted, or two managed sources claim the same current responsibility.
