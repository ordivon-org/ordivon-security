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
updated: 2026-08-04
summary: Authority map for the active Contest core, migration record, research program, authorization boundary, evidence, and frozen Round 1 materials.
evidence_status: not_applicable
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.start
  - security.charter
  - security.architecture
  - security.research-agenda
  - security.research-boundary
  - security.evidence
---
# Security Content Authority

## Current authority

- [`../README.md`](../README.md) owns the public entry and current runnable capability.
- [`../CHARTER.md`](../CHARTER.md) owns mission, principles, and repository responsibility.
- [`architecture.md`](architecture.md) owns active contracts, data flow, and cross-project composition.
- [`MIGRATION-ROUND-1.md`](MIGRATION-ROUND-1.md) owns the first replacement scope and acceptance record.
- [`research-agenda.md`](research-agenda.md) owns the ordered research program and falsifiers.
- [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits.
- [`../evidence/README.md`](../evidence/README.md) owns active and historical evidence admission.

For implemented behavior, source code and deterministic tests outrank prose. For an individual Trial, its Scenario manifest, event streams, raw metrics, bundle manifest, and verified digests outrank summaries.

## Historical authority

The former single-Actor experiment/evaluation framework is frozen at `92c0f9497741c3cde542c347318d2372fb884e30`. [`archive/round1/system.md`](archive/round1/system.md) binds its test baseline and retained evidence digests. Other files under [`archive/round1/`](archive/round1/) explain historical results and constraints but cannot define active APIs.

[`archive/campaign-v0.md`](archive/campaign-v0.md) remains historical reproduction authority for the earlier Campaign infrastructure only.

## Reopen conditions

Revisit this map when a CAGE, Harness, container Range, Campaign, organization, or delegated Harness integration becomes active; when a public API is stabilized; or when two sources claim the same current fact.
