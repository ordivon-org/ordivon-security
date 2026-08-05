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
updated: 2026-08-05
summary: Authority map for the active Contest core, CAGE Range, software Evaluation and Static P0, research program, authorization boundary, evidence, and frozen Round 1 materials.
evidence_status: not_applicable
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.start
  - security.charter
  - security.architecture
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.research-agenda
  - security.research-boundary
  - security.evidence
---
# Security Content Authority

## Current authority

- [`../README.md`](../README.md) owns the public entry and current runnable capability.
- [`../CHARTER.md`](../CHARTER.md) owns mission, principles, and repository responsibility.
- [`architecture.md`](architecture.md) owns active contracts, data flow, CAGE composition, and cross-project ownership.
- [`MIGRATION-ROUND-1.md`](MIGRATION-ROUND-1.md) owns the Contest Core replacement record.
- [`MIGRATION-ROUND-2.md`](MIGRATION-ROUND-2.md) owns the first-class CAGE 4 Range migration and acceptance record.
- [`MIGRATION-ROUND-3-P0.md`](MIGRATION-ROUND-3-P0.md) owns fail-closed tick semantics, Trial execution identity, semantic/operational evidence separation, and the Harness Domain Tool Bridge prerequisite.
- [`EVALUATION-TRIAL-P0.md`](EVALUATION-TRIAL-P0.md) owns the general local software Evaluation contracts, SampleVault boundary, Observer/Guardian distinction, residual closure, evidence, and next-backend admission gate.
- [`STATIC-EVALUATION-P0.md`](STATIC-EVALUATION-P0.md) owns SampleVault revision 2, static analyzer admission, native-report Artifact evidence, quarantine hardening, historical report limitations, and the no-execution static profile.
- [`research-agenda.md`](research-agenda.md) owns the ordered research program and falsifiers.
- [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits.
- [`../evidence/README.md`](../evidence/README.md) owns active and historical evidence admission.

For implemented behavior, source code and deterministic/integration tests outrank prose. A static analyzer owns only its native report and declared tool result; it does not own runtime behavior, intent, or independent world truth. An imported historical report is authoritative only for the bytes and statements retained under its bound digest. For an individual Contest Trial, its Scenario manifest, Trial identity, semantic and operational event streams, raw metrics, bundle manifests, and verified digests outrank summaries. For an individual Evaluation Run, its Evaluation Spec, execution identity, Sample identity, separated event streams, residual-closure receipt, Findings, result, bundle manifests, and verified digests outrank summaries. For CAGE substrate behavior, the exact pinned source revision is authoritative; Security owns the adapter mapping and evidence claims.

## Historical authority

The former single-Actor experiment/evaluation framework is frozen at `92c0f9497741c3cde542c347318d2372fb884e30`. [`archive/round1/system.md`](archive/round1/system.md) binds its test baseline and retained evidence digests. Other files under [`archive/round1/`](archive/round1/) explain historical results and constraints but cannot define active APIs.

[`archive/campaign-v0.md`](archive/campaign-v0.md) remains historical reproduction authority for the earlier Campaign infrastructure only.

## Reopen conditions

Revisit this map when a Harness, model-backed Actor, container Range, external Evaluation backend, Campaign, organization, or delegated Harness integration becomes active; when the CAGE action surface expands; when a public API is stabilized; or when two sources claim the same current fact.
