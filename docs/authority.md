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
updated: 2026-08-06
summary: Authority map for the active Contest core, CAGE Range, software Evaluation, Static P0, Case Snapshot P0, P0-admitted Windows KVM Provider, research program, authorization boundary, evidence, and frozen Round 1 materials.
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
  - security.case-snapshot-p0
  - security.windows-kvm-p0
  - security.agent-experiment-p0
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
- [`CASE-SNAPSHOT-P0.md`](CASE-SNAPSHOT-P0.md) owns read-only quarantine drift, evolving Case identity, external uncontrolled execution status, snapshot verification, and the boundary between Case material and Evaluation evidence.
- [`WINDOWS-KVM-P0.md`](WINDOWS-KVM-P0.md) owns the P0-admitted disposable Windows Provider, sealed image identity, management-plane no-network authority, exact benign fixture admission, and residual-closure gate.
- [`WINDOWS-KVM-RECOVERY-P0.1.md`](WINDOWS-KVM-RECOVERY-P0.1.md) owns root-owned Run-ledger identity, owner/process recovery rules, orphan reconciliation, and its candidate hard-failure acceptance gates without changing Sample admission.
- [`WINDOWS-KVM-INSTALLER-P1.md`](WINDOWS-KVM-INSTALLER-P1.md) owns the separate large-Sample installer profile, exact Case/archive binding, read-only NTFS input-media preparation, and the prohibition on execution before a later gate.
- [`AGENT-EXPERIMENT-P0.md`](AGENT-EXPERIMENT-P0.md) owns the Provider/Harness/Host/Runtime experiment variants, credential-scope identity, and model-Actor admission boundary.
- [`research-agenda.md`](research-agenda.md) owns the ordered research program and falsifiers.
- [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits.
- [`../evidence/README.md`](../evidence/README.md) owns active and historical evidence admission.

For implemented behavior, source code and deterministic/integration tests outrank prose. A static analyzer owns only its native report and declared tool result; it does not own runtime behavior, intent, or independent world truth. An imported historical report is authoritative only for the bytes and statements retained under its bound digest. A Case Snapshot owns exact directory metadata and file digests, not runtime behavior. External uncontrolled stdout, stderr, scripts, and human reports cannot establish Guardian enforcement, world truth, or residual closure. For Windows KVM, QMP and the host process lifecycle own network-device and machine-lifecycle facts; Guest PowerShell and fixture JSON are Observers only. P0.1 root-owned ledgers own recoverable Run/process identity after owner loss, while the reconciler owns only the decisions and receipts it actually produces. A prepared P1 NTFS disk proves exact staged bytes and read-only QEMU topology, not execution safety or installer behavior. Retained benign acceptance authorizes only the exact maintained fixture; it does not authorize unknown Sample execution or third-party installers. For an individual Contest Trial, its Scenario manifest, Trial identity, semantic and operational event streams, raw metrics, bundle manifests, and verified digests outrank summaries. For an individual Evaluation Run, its Evaluation Spec, execution identity, Sample identity, separated event streams, residual-closure receipt, Findings, result, bundle manifests, and verified digests outrank summaries. For CAGE substrate behavior, the exact pinned source revision is authoritative; Security owns the adapter mapping and evidence claims.

## Historical authority

The former single-Actor experiment/evaluation framework is frozen at `92c0f9497741c3cde542c347318d2372fb884e30`. [`archive/round1/system.md`](archive/round1/system.md) binds its test baseline and retained evidence digests. Other files under [`archive/round1/`](archive/round1/) explain historical results and constraints but cannot define active APIs.

[`archive/campaign-v0.md`](archive/campaign-v0.md) remains historical reproduction authority for the earlier Campaign infrastructure only.

## Reopen conditions

Revisit this map when a Harness, model-backed Actor, container Range, external Evaluation backend, Campaign, organization, or delegated Harness integration becomes active; when the CAGE action surface expands; when a public API is stabilized; or when two sources claim the same current fact.
