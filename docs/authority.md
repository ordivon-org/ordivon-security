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
updated: 2026-08-07
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
- [`LAW-PROFILES-C0.md`](LAW-PROFILES-C0.md) owns the interpretation boundary between constitutional law, authority/resource grants, experiment profiles/fixtures, and evaluator judgments. Local profile restrictions cannot silently become universal Security doctrine.
- [`architecture.md`](architecture.md) owns active contracts, data flow, CAGE composition, and cross-project ownership.
- [`RANGE-SESSION-S0.md`](RANGE-SESSION-S0.md) owns the experimental persistent Range Session contracts, capability-envelope authority, asynchronous event semantics, and S0 acceptance boundary.
- [`EXECUTABLE-AUTHORITY-C1.md`](EXECUTABLE-AUTHORITY-C1.md) owns the first executable zone/capability `RangeAuthority` path, one Actor-requested S6 physical effect, its negative authority cases, receipt-versus-world-truth boundary, and exact physical acceptance limitations.
- [`SYNCHRONOUS-CONTEST-S1.md`](SYNCHRONOUS-CONTEST-S1.md) owns the S1 compatibility boundary between persistent Range Sessions and accepted synchronous Contest execution.
- [`WINDOWS-KVM-SUBSTRATE-S2.md`](WINDOWS-KVM-SUBSTRATE-S2.md) owns the S2 machine-level Provider boundary, external topology/process truth, reusable lifecycle substrate, and separation from Evaluation admission.
- [`SACRIFICIAL-NODE-S3.md`](SACRIFICIAL-NODE-S3.md) owns the S3 single-node challenge, management-plane acceptance gates, Guest-claim boundary, and the transition to out-of-band truth research.
- [`OUT-OF-BAND-TRUTH-S4.md`](OUT-OF-BAND-TRUTH-S4.md) owns the first physical Range `world-truth` plane, read-only offline NTFS authority, selected post-run disk facts, S4 limitations, and the transition to contested networking.
- [`ISOLATED-FABRIC-S5.md`](ISOLATED-FABRIC-S5.md) owns the first accepted physical contested fabric, heterogeneous Windows/lightweight materialization, management/world-truth/sensor/contested authority separation, S5 falsifiers, and its exact physical acceptance boundary.
- [`TOPOLOGY-CHURN-S6.md`](TOPOLOGY-CHURN-S6.md) owns the accepted live peer-replacement challenge, current-versus-historical topology truth, asynchronous backend evolution boundary, S6 falsifiers, and exact physical acceptance.
- [`PERSISTENT-RANGE-RECOVERY-S6R.md`](PERSISTENT-RANGE-RECOVERY-S6R.md) owns the post-S6 read/effect correction, durable S5/S6 Range resource identity, exact Range reconciliation policy, owner-loss physical acceptance, and final normal-path regression.
- [`MIGRATION-ROUND-1.md`](MIGRATION-ROUND-1.md) owns the Contest Core replacement record.
- [`MIGRATION-ROUND-2.md`](MIGRATION-ROUND-2.md) owns the first-class CAGE 4 Range migration and acceptance record.
- [`MIGRATION-ROUND-3-P0.md`](MIGRATION-ROUND-3-P0.md) owns fail-closed tick semantics, Trial execution identity, semantic/operational evidence separation, and the Harness Domain Tool Bridge prerequisite.
- [`EVALUATION-TRIAL-P0.md`](EVALUATION-TRIAL-P0.md) owns the general local software Evaluation contracts, SampleVault boundary, Observer/Guardian distinction, residual closure, evidence, and next-backend admission gate.
- [`STATIC-EVALUATION-P0.md`](STATIC-EVALUATION-P0.md) owns SampleVault revision 2, static analyzer admission, native-report Artifact evidence, quarantine hardening, historical report limitations, and the no-execution static profile.
- [`CASE-SNAPSHOT-P0.md`](CASE-SNAPSHOT-P0.md) owns read-only quarantine drift, evolving Case identity, external uncontrolled execution status, snapshot verification, and the boundary between Case material and Evaluation evidence.
- [`WINDOWS-KVM-P0.md`](WINDOWS-KVM-P0.md) owns the P0-admitted disposable Windows Provider, sealed image identity, management-plane no-network authority, exact benign fixture admission, and residual-closure gate.
- [`WINDOWS-KVM-RECOVERY-P0.1.md`](WINDOWS-KVM-RECOVERY-P0.1.md) owns root-owned Evaluation Run-ledger identity, Evaluation owner/process recovery rules, orphan reconciliation, and its candidate hard-failure acceptance gates without changing Sample admission.
- [`WINDOWS-KVM-INSTALLER-P1.md`](WINDOWS-KVM-INSTALLER-P1.md) owns the large-Sample research profile, deployment/evaluation/host authority split, Case A/B/C topology, transformation-manifest requirements, main-Windows Free control, read-only media gates, and pending execution/write gates.
- [`AGENT-EXPERIMENT-P0.md`](AGENT-EXPERIMENT-P0.md) owns the Provider/Harness/Host/Runtime experiment variants, credential-scope identity, and model-Actor admission boundary.
- [`research-agenda.md`](research-agenda.md) owns the ordered research program and falsifiers.
- [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits.
- [`../evidence/README.md`](../evidence/README.md) owns active and historical evidence admission.

For implemented behavior, source code and deterministic/integration tests outrank prose. A static analyzer owns only its native report and declared tool result; it does not own runtime behavior, intent, or independent world truth. An imported historical report is authoritative only for the bytes and statements retained under its bound digest. A Case Snapshot owns exact directory metadata and file digests, not runtime behavior. External uncontrolled stdout, stderr, scripts, and human reports cannot establish Guardian enforcement, world truth, or residual closure. For Windows KVM, QMP and the host process lifecycle own network-device and machine-lifecycle facts; Guest PowerShell and fixture JSON are Observers only. For S5 contested networking, Host Linux netlink/bridge state owns the declared fabric topology and route facts, Host tcpdump is a fallible `sensor` observation rather than world truth, and Guest connectivity JSON remains contested evidence. For S6 topology churn, management replacement events own controller intent/completion only; successive Host netlink/bridge observations own the physical transition, historical topology events retain the past, and the latest `fabricTruth` owns the current observed topology. `WindowsKvmMachineProvider` ledgers and process helpers own reusable machine recovery facts, but reconciliation policy remains consumer-specific: P0.1 owns Evaluation reconciliation, while S6-R owns the exact S5/S6 Range reconciliation policy and its physical owner-loss receipt. Each reconciler owns only the decisions and receipts it actually produces. A prepared P1 NTFS disk proves exact staged bytes and declared read-only QEMU topology, not execution safety or installer behavior. A transformation manifest owns the declared source-to-Case difference but not runtime behavior. The main-Windows Free baseline receipt owns only signed file identities and read-only collection; the user declaration owns the Free-edition label until feature behavior is measured. Retained benign acceptance authorizes only the exact maintained fixture; it does not authorize unknown Sample execution or third-party installers. For an individual Contest Trial, its Scenario manifest, Trial identity, semantic and operational event streams, raw metrics, bundle manifests, and verified digests outrank summaries. For an individual Evaluation Run, its Evaluation Spec, execution identity, Sample identity, separated event streams, residual-closure receipt, Findings, result, bundle manifests, and verified digests outrank summaries. For CAGE substrate behavior, the exact pinned source revision is authoritative; Security owns the adapter mapping and evidence claims.

## Historical authority

The former single-Actor experiment/evaluation framework is frozen at `92c0f9497741c3cde542c347318d2372fb884e30`. [`archive/round1/system.md`](archive/round1/system.md) binds its test baseline and retained evidence digests. Other files under [`archive/round1/`](archive/round1/) explain historical results and constraints but cannot define active APIs.

[`archive/campaign-v0.md`](archive/campaign-v0.md) remains historical reproduction authority for the earlier Campaign infrastructure only.

## Reopen conditions

Revisit this map when a Harness, model-backed Actor, container Range, external Evaluation backend, Campaign, organization, or delegated Harness integration becomes active; when the CAGE action surface expands; when a public API is stabilized; or when two sources claim the same current fact.
