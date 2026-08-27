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
updated: 2026-08-27
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
- [`AUTONOMOUS-INTENT-C1A.md`](AUTONOMOUS-INTENT-C1A.md) owns the model/Harness choice-over-capability experiment, the intent-Tool boundary, immutable Range-inspection requirement, first evidence-aliasing falsifier, corrected physical acceptance, and resulting interrupted-effect pressure.
- [`INTERRUPTED-CONSEQUENCE-C1B.md`](INTERRUPTED-CONSEQUENCE-C1B.md) owns the admitted-effect owner-loss experiment, physical-versus-semantic recovery falsifier, minimal durable effect-binding mechanism, intermediate and response-lost kill gates, causal-graph result, and final S6 regression.
- [`PARTIAL-MATERIALIZATION-C1C.md`](PARTIAL-MATERIALIZATION-C1C.md) owns the partial peer-B materialization experiment, false-clean falsifier, exact transient Host-link ownership rule, veth type-validation boundary, corrected zero-residual physical acceptance, and resulting continuation pressure.
- [`FRESH-CONTROLLER-CONTINUATION-C1D.md`](FRESH-CONTROLLER-CONTINUATION-C1D.md) owns the first physical successor-continuation experiment, world-state-as-progress result, same-Guest continuity proof, and non-restoration of the old Range object/event stream.
- [`SUCCESSOR-OWNERSHIP-C1E.md`](SUCCESSOR-OWNERSHIP-C1E.md) owns the physical successor-versus-reconciler race falsifier, predecessor-provenance/current-recovery-authority separation, exact-generation successor claim, per-Run kernel arbitration mechanism, and successor-SIGKILL release proof.
- [`MULTIPLE-SUCCESSORS-C1F.md`](MULTIPLE-SUCCESSORS-C1F.md) owns the two-successor competition, non-mutating loser proof, current-generation retry/adoption result, persistent-consequence versus transient-service distinction, overwrite-lineage falsifier, and archived predecessor-claim mechanism.
- [`MID-SUCCESSOR-RECOVERY-C1G.md`](MID-SUCCESSOR-RECOVERY-C1G.md) owns the successor-mid-continuation SIGKILL experiment, same-ledger/different-world falsifier, post-acquisition world re-observation rule, and same-Guest two-controller-death continuity proof.
- [`UNPUBLISHED-COMPLETION-C1H.md`](UNPUBLISHED-COMPLETION-C1H.md) owns the completed-but-unpublished consequence experiment, completion/publication/executor separation, read-only sensor methodology correction, and publication-only successor repair.
- [`INFORMATION-LOSS-C1I.md`](INFORMATION-LOSS-C1I.md) owns the delivered-versus-undelivered indistinguishability experiment, `UNKNOWN` epistemic boundary, blind-retry falsifier, restricted-principal recipient-state separation, and recipient-side exact-effect deduplication result.
- [`RECIPIENT-COMMIT-GAP-C1J.md`](RECIPIENT-COMMIT-GAP-C1J.md) owns the recipient consequence/dedup dual-order fault injection, duplicate-versus-loss result, and durable `reserved` inbox ambiguity proof.
- [`INTRINSIC-IDEMPOTENCY-C1K.md`](INTRINSIC-IDEMPOTENCY-C1K.md) owns the exact ensure-state consequence experiment, repeated-invocation/single-semantic-consequence result, preexisting-invariant semantics, and fail-closed resource identity boundary.
- [`COMPENSATION-C1L.md`](COMPENSATION-C1L.md) owns the non-idempotent duplicate/compensation experiment, blind-compensation-retry falsifier, original-versus-compensation identity separation, and repair-invariant re-observation rule.
- [`COMPENSATION-INFORMATION-LOSS-C1M.md`](COMPENSATION-INFORMATION-LOSS-C1M.md) owns the caller-visible compensation indistinguishability proof, downstream-private authority boundary, naive-replay falsifier, distinct idempotent compensation protocol result, and physical no-sidecar inventory.
- [`DOWNSTREAM-TRUTH-FAILURE-C1N.md`](DOWNSTREAM-TRUTH-FAILURE-C1N.md) owns the missing/corrupt/forked downstream predicate-truth experiment, zero-mutation fail-closed law, distinct sealed state-witness recovery identity, tampered-witness rejection, and resulting witness-freshness pressure.
- [`WORLD-ENTITY-MIGRATION-RECOVERY.md`](WORLD-ENTITY-MIGRATION-RECOVERY.md) owns the World Entity KVM recovery boundary: predecessor ownership remains provenance; independently re-observed completion may repair publication without body replay; provably body-free staged or TPM-only abandonment may be compensated to zero residuals and released as `NOT_COMMITTED`; ambiguous QEMU launch evidence remains `UNKNOWN`; and the tested single-host consumer still does not justify a generic durable Entity successor or transaction primitive.
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
- [`AGENT-FIRST-STRUCTURE-AF1.md`](AGENT-FIRST-STRUCTURE-AF1.md) owns the AF1 structural classification separating reusable Security constitution, scoped profiles, cross-repository integrations, and research apparatus without promoting a new universal framework.
- [`AGENT-FIRST-INTENT-AF2.md`](AGENT-FIRST-INTENT-AF2.md) owns the AF2 minimal reusable Range-intent surface and its boundary against Contest ticks, action menus, exactly-one-action rules, or Security ownership of the cognition loop.
- [`AGENT-FIRST-DECEPTION-AF3.md`](AGENT-FIRST-DECEPTION-AF3.md) owns the AF3 higher-order deception consumer, its same-claim/different-world consequence result, and the non-admission of Trust, Reputation, Organization, or a generic policy primitive.
- [`ADVERSARIAL-EPISTEMICS-AE0.md`](ADVERSARIAL-EPISTEMICS-AE0.md) owns the AE0 autonomous-deception/partial-truth experiment and its bounded information-acquisition result without promoting adversarial claims to truth.
- [`ADVERSARIAL-EPISTEMICS-AE1.md`](ADVERSARIAL-EPISTEMICS-AE1.md) owns the AE1 delayed-truth/costly-waiting experiment and its scoped UNKNOWN-under-risk result without forcing Trust, Reputation, freshness machinery, or reversible containment.
- [`ADVERSARIAL-EPISTEMICS-AE2.md`](ADVERSARIAL-EPISTEMICS-AE2.md) owns the AE2 conflicting-independent-observation experiment, explicit-adjudication result, and boundary against promoting either sensor to world truth or durable Trust/Reputation state.
- [`ADVERSARIAL-EPISTEMICS-AE3.md`](ADVERSARIAL-EPISTEMICS-AE3.md) owns the AE3 no-adjudication experiment, its bounded consequence-under-UNKNOWN result, and the falsifier against claiming one counterfactually optimal risk action from the supplied evidence.
- [`ADVERSARIAL-EPISTEMICS-AE3B.md`](ADVERSARIAL-EPISTEMICS-AE3B.md) owns the falsified AE3-B raw-history treatment showing that verified episodes in ordinary Agent context are insufficient for stable evidence aggregation or reproducible effect strategy.
- [`ADVERSARIAL-EPISTEMICS-AE3C.md`](ADVERSARIAL-EPISTEMICS-AE3C.md) owns the accepted AE3-C reconstructable evidence-reduction treatment and its boundary against turning derived projection into current truth, policy, Trust, or Reputation.
- [`EVIDENCE-COMPUTATION-EC0.md`](EVIDENCE-COMPUTATION-EC0.md) owns the EC0 cross-domain evidence-computation ownership experiment and the rejection of a Security-owned reducer primitive or new shared reducer library.
- [`EVIDENCE-FRESHNESS-EC1.md`](EVIDENCE-FRESHNESS-EC1.md) owns the EC1 source-evolution experiment separating derivation integrity from current applicability and the non-admission of TTL/clock/generation freshness or a new freshness service.
- [`AUTONOMOUS-COMMUNICATION-AC0.md`](AUTONOMOUS-COMMUNICATION-AC0.md) owns the falsified AC0 one-shot cheap-talk coordination treatment and the result that message projection alone does not establish strategic credibility.
- [`INCENTIVE-COMMUNICATION-AC1.md`](INCENTIVE-COMMUNICATION-AC1.md) owns the falsified AC1 aligned-incentive treatment, including the first B-to-A reply evidence and the rejection of common aligned incentives as sufficient credibility.
- [`VERIFIABLE-DISCLOSURE-AC2.md`](VERIFIABLE-DISCLOSURE-AC2.md) owns the falsified AC2 selective-disclosure experiment showing epistemic resolution without reliable Tool-intent/reasoning convergence.
- [`INTENT-CONVERGENCE-IF0-IF2.md`](INTENT-CONVERGENCE-IF0-IF2.md) owns the IF0/IF1 finalization/readback falsifiers and the accepted IF2 deliberation-before-authority treatment on the scoped AC2 consumer.
- [`INTENT-CEREMONY-ABLATION-IF3.md`](INTENT-CEREMONY-ABLATION-IF3.md) owns the IF3 ablation showing that ordinary AF2 revision semantics remain sufficient after prior deliberation without IF1 readback/finalization Tools in the tested consumer.
- [`POST-CA-O1-CARRIER-OBSERVABILITY.md`](POST-CA-O1-CARRIER-OBSERVABILITY.md) owns the accepted scoped same-effect carrier-observability result and its boundary against universal stealth/loudness ranking or a new semantic capability domain.
- [`POST-CA-P1-PHYSICAL-ADAPTATION.md`](POST-CA-P1-PHYSICAL-ADAPTATION.md) owns the accepted physical adaptive-composition consumer and its scoped comparison among fixed, thin-adaptive, and Harness/model treatments.
- [`RESEARCH-CORPUS-K1-CURRENTNESS.md`](RESEARCH-CORPUS-K1-CURRENTNESS.md) owns the accepted on-demand provider-currentness experiment, exact candidate-vs-head comparison result, and rejection of automatic polling/mirroring/global freshness labels.
- [`ORDINARY-SECURITY-CONSUMPTION-R1.md`](ORDINARY-SECURITY-CONSUMPTION-R1.md) owns the accepted ordinary-consumption round, thin ordinary task-view result, ResearchCorpus pre-analysis role, bounded Blue response path, and its rejected over-expansions.
- [`research-boundary.md`](research-boundary.md) owns authorization and external-effect limits.
- [`CLASSICAL-CAPABILITY-BASIS-CA0.md`](CLASSICAL-CAPABILITY-BASIS-CA0.md) owns the CA0 first-principles classical capability decomposition, competing-model falsifiers, orthogonal capability-contract candidate, Red/Blue relation-symmetry candidate, current Security capability-gap map, and the boundary against prematurely promoting a tool tree, ATT&CK clone, universal mechanism vocabulary, or `RangeActionGateway`.
- [`CLASSICAL-EXECUTION-CARRIERS-CA1.md`](CLASSICAL-EXECUTION-CARRIERS-CA1.md) owns the CA1 same-effect execution-carrier experiment, carrier-versus-semantic-effect boundary, provider-policy-versus-RangeAuthority separation, Windows hosted-process/installer-lifecycle evidence, retained QMP/identity/MSI-sequencing/build-identity falsifiers, Office-provider non-admission, and the rule that carrier becomes Agent-visible only through decision-relevant operational properties.
- [`VULNERABILITY-EVIDENCE-CA2.md`](VULNERABILITY-EVIDENCE-CA2.md) owns the CA2 owned-target vulnerability evidence ladder, static-finding versus exploitability falsifier, libFuzzer/ASan discovery and independent replay boundary, exact target-revision applicability result, and the decision to stop at bounded sanitizer process consequence rather than weaponization.
- [`POST-COMPROMISE-STATE-CA3.md`](POST-COMPROMISE-STATE-CA3.md) owns the CA3 bounded post-compromise state experiment, persistence-versus-usable-control boundary, synthetic credential generation/revocation semantics, verified foothold consequence, controller-directed versus delegated continuation result, eradication/stale-belief negative controls, and the decision not to build credential-stealing or worm infrastructure.
- [`DEFENSIVE-OBSERVATION-RESPONSE-CA4.md`](DEFENSIVE-OBSERVATION-RESPONSE-CA4.md) owns the CA4 provider-first Blue-plane experiment, raw-observation/detection/adjudication/response/truth separation, ClamAV/EICAR classification boundary, stale-detection and provider-unavailable controls, case-local quarantine verification, and the decision not to build a SIEM/EDR/IDS stack.
- [`PROVIDER-ASSIMILATION-CA5.md`](PROVIDER-ASSIMILATION-CA5.md) owns the CA5 cross-consumer provider-binding audit and the evidence-backed decision that no shared `RangeActionGateway` or new Security provider-binding layer is currently earned; provider-specific adapters plus existing Runtime/Harness/Range/evidence owners remain authoritative.
- [`TACTICAL-ADAPTATION-CA6.md`](TACTICAL-ADAPTATION-CA6.md) owns the CA6 static-versus-adaptive-versus-DeepSeek/Harness tactical comparison, current-evidence capability selection/replanning result, active Blue counterplay treatment, information-acquisition cost, model/Harness instability evidence, and the conclusion that no tactical-state/Campaign/Gateway abstraction is forced by this consumer.
- [`CAMPAIGN-ORGANIZATION-GATE-CA7.md`](CAMPAIGN-ORGANIZATION-GATE-CA7.md) owns the CA7 negative strategic-admission decision: current CA-series evidence does not admit Campaign, Organization, persistent OpponentModel, coevolution, or a cross-fidelity strategic law; it also owns the exact reopen conditions for any future strategic-state work.
- [`CLIENT-AUTHORITY-ENTITLEMENT-CA-LIC.md`](CLIENT-AUTHORITY-ENTITLEMENT-CA-LIC.md) owns the independent CA-LIC authority-topology family: ToyDesigner V0-V8 evidence, credential-versus-enforcement separation, protected-asset placement, remote-entitlement-versus-remote-capability contrast, external-result authority, publication boundary, and the decision to keep third-party bypass mechanics out of reusable/ordinary Security surfaces.
- [`CLIENT-AUTHORITY-ENTITLEMENT-CA-LIC-R1.md`](CLIENT-AUTHORITY-ENTITLEMENT-CA-LIC-R1.md) owns the CA-LIC revocation/economics follow-up: V5 recipient/key churn, prospective revocation, V6 offline-lease versus stale-authority coupling, V8 outage/input/authority-rotation cost, the vendor-documented cross-system observation matrix, and the decision to leave these mechanics as research rather than a generic licensing subsystem.
- [`AUTHORITY-LIFECYCLE-ENGINEERING.md`](AUTHORITY-LIFECYCLE-ENGINEERING.md) owns the engineering application of CA-LIC to Security: exact frozen grant snapshots, digest-bound admission history, prospective authority change, delivered-information irreversibility, external-authority identity continuity, evidence-path verifier hardening, and explicit non-promotion of a generic lease/revocation subsystem.
- [`RESEARCH-CORPUS-P0.md`](RESEARCH-CORPUS-P0.md) owns the post-CA vulnerability/Sample research-corpus boundary: revisioned exact identities, provider/evidence claim truth roles, explicit provider snapshot provenance, private SampleVault materialization, denied-by-default Sample execution, seed-set acceptance, and the decision not to build a malware downloader, public sample zoo, provider database mirror, family ontology, or automatic synchronization layer in P0.
- [`../research/w5b/README.md`](../research/w5b/README.md) owns the recovered W5-B research standing and its historical/currentness distinction; [`../research/w5b/evidence/b1-second-active-destination.json`](../research/w5b/evidence/b1-second-active-destination.json) preserves the exact bounded 2026-08-09 acceptance, while current source code owns only today's substrate behavior. The W5-B rebind is not a fresh physical replay and grants no production Embodiment/Presence authority.
- [`../evidence/README.md`](../evidence/README.md) owns active and historical evidence admission.

For implemented behavior, source code and deterministic/integration tests outrank prose. A static analyzer owns only its native report and declared tool result; it does not own runtime behavior, intent, or independent world truth. An imported historical report is authoritative only for the bytes and statements retained under its bound digest. A Case Snapshot owns exact directory metadata and file digests, not runtime behavior. External uncontrolled stdout, stderr, scripts, and human reports cannot establish Guardian enforcement, world truth, or residual closure. For Windows KVM, QMP and the host process lifecycle own network-device and machine-lifecycle facts; Guest PowerShell and fixture JSON are Observers only. For S5 contested networking, Host Linux netlink/bridge state owns the declared fabric topology and route facts, Host tcpdump is a fallible `sensor` observation rather than world truth, and Guest connectivity JSON remains contested evidence. For S6 topology churn, management replacement events own controller intent/completion only; successive Host netlink/bridge observations own the physical transition, historical topology events retain the past, and the latest `fabricTruth` owns the current observed topology. `WindowsKvmMachineProvider` ledgers and process helpers own reusable machine recovery facts, but reconciliation policy remains consumer-specific: P0.1 owns Evaluation reconciliation, while S6-R owns the exact S5/S6 Range reconciliation policy and its physical owner-loss receipt. Each reconciler owns only the decisions and receipts it actually produces. A prepared P1 NTFS disk proves exact staged bytes and declared read-only QEMU topology, not execution safety or installer behavior. A transformation manifest owns the declared source-to-Case difference but not runtime behavior. The main-Windows Free baseline receipt owns only signed file identities and read-only collection; the user declaration owns the Free-edition label until feature behavior is measured. Retained benign acceptance authorizes only the exact maintained fixture; it does not authorize unknown Sample execution or third-party installers. For an individual Contest Trial, its Scenario manifest, Trial identity, semantic and operational event streams, raw metrics, bundle manifests, and verified digests outrank summaries. For an individual Evaluation Run, its Evaluation Spec, execution identity, Sample identity, separated event streams, residual-closure receipt, Findings, result, bundle manifests, and verified digests outrank summaries. For CAGE substrate behavior, the exact pinned source revision is authoritative; Security owns the adapter mapping and evidence claims.

## Historical authority

The former single-Actor experiment/evaluation framework is frozen at `92c0f9497741c3cde542c347318d2372fb884e30`. [`archive/round1/system.md`](archive/round1/system.md) binds its test baseline and retained evidence digests. Other files under [`archive/round1/`](archive/round1/) explain historical results and constraints but cannot define active APIs.

[`archive/campaign-v0.md`](archive/campaign-v0.md) remains historical reproduction authority for the earlier Campaign infrastructure only.

## Reopen conditions

Revisit this map when a Harness, model-backed Actor, container Range, external Evaluation backend, Campaign, organization, or delegated Harness integration becomes active; when the CAGE action surface expands; when a public API is stabilized; or when two sources claim the same current fact.
