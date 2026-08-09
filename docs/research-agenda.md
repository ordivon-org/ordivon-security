---
schema_version: 1
id: security.research-agenda
title: Autonomous adversarial systems research agenda
type: research-proposal
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - builder
  - evaluator
  - agent
updated: 2026-08-07
summary: Canonical experiment sequence from reproducible Contests and CAGE transfer through adaptive Campaigns, organizations, evaluator attacks, coevolution, and cross-fidelity transfer.
evidence_status: not_applicable
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.architecture
  - security.research-boundary
  - security.authority
  - security.agent-experiment-p0
---
# Autonomous adversarial systems research agenda

## Core question

What capabilities and failure modes emerge when multiple autonomous actors pursue conflicting objectives through real or simulated tools, observe different evidence, adapt to one another, and may model or manipulate the evaluator?

The agenda is ordered by dependency. Later strategic claims are inadmissible until earlier execution and evidence conditions work.

## R0 — Contest validity

Prove multiple actors, asymmetric observation, explicit action admission, simultaneous resolution, independent truth, raw metrics, replay, and tamper detection.

Status: implemented in the deterministic Red/Blue Range.

Falsifier: an ordinary single-Agent episode with one trace expresses the same facts without information leakage or causal ambiguity.

## R1 — External simulation transfer

Attach CAGE 4/CybORG as an authoritative Range and control Red and Blue through Ordivon contracts. Compare scripted, finite-state, RL, and model-backed policies under exact seeds and observation mappings.

Status: initial transfer plus P0-A, the controlled P0-B Host baseline, and P0-C Runtime execution are accepted. The controlled P0-B/P0-C pair used the same Harness and Security revisions and produced the same six explicit Red/Blue actions for one CAGE tick while Green remained native and no default Red/Blue actions were used. Both completed durable Host Tasks at revision 5; P0-B retained zero Runtime Job references, while P0-C bound one succeeded, recoverable, terminal-clean Runtime Job to each Actor. Multi-tick continuity, injected cancellation/transport faults, parameterized action construction, held-out policy comparisons, and RL Actors remain open.

Falsifier: Ordivon's contracts add no diagnostic or experimental value over native CAGE episodes.

## R2 — Native model-backed actors

Use the generic Harness Domain Tool Bridge to connect Security-owned domain tools, then compare DeepSeek Flash-backed Red and Blue actors across controlled Provider/Harness/Host/Runtime variants with bounded Context, durable identity, Provider failure evidence, and replaceable model identity.

The accepted P0-A experiment selects CAGE team plans through Harness while Host and Runtime non-consumption remain explicit in Trial identity. The accepted controlled P0-B variant adds durable Host TaskContract, Context selection, external Assignment, Run receipt, CompletionProposal, and CompletionDecision while preserving Runtime non-consumption. The accepted P0-C variant changes only physical execution consumption: each identical Host Assignment runs as one Runtime Job/Attempt with exact replay, recovery lookup, Artifact, foreign-reference, and process-tree evidence. The next isolated variable is typed parameterized CAGE actions, not arbitrary shell.

Falsifier: direct stateless model calls perform equivalently and no continuity or effect-reconciliation distinction appears.

## Immediate infrastructure pivot — persistent Range Session

The accepted R0-R2 work proved deterministic Contest semantics, CAGE transfer, real model Actors, and controlled Host/Runtime composition. The next infrastructure dependency is no longer a richer CAGE action menu. S0 therefore introduces a parallel `RangeSession` core that removes mandatory ticks, one-proposal-per-Actor scheduling, and action-menu authority while leaving accepted Contest semantics unchanged.

S0 is only a contract/lifecycle foundation. S1 confirms that the accepted synchronous Contest core composes naturally as a bounded profile through RangeSession management events and sealed evidence references; forcing `ContestRunner` to implement `RangeSessionBackend` is unnecessary. S2 separates reusable Windows KVM machine authority from Evaluation Sample admission: disposable overlay/UEFI/TPM state, root-owned ledger, QMP topology truth, process identity, recovery primitives, and residual closure now exist below the Evaluation adapter. S3 physically exercises one sacrificial Windows node while keeping Guest claims contested. S4 then adds the first physical Range `world-truth` producer: after QEMU stops, a Host-only read-only qemu-nbd/NTFS path verifies selected persistence and deletion state directly from the disposable system overlay, while QMP reset and provider closure remain independent authorities. S4 deliberately stops at post-run disk facts; it does not manufacture a network consumer or claim process attribution.

Post-S4 physical probes changed the S5 hypothesis before implementation. A bridge created directly in the WSL root network namespace was affected by pre-existing Docker/WSL forwarding policy even though its ports were forwarding. Moving the bridge into its own network namespace removed that coupling: two lightweight peers communicated, had no external route, root-side observation captured their traffic, and namespace destruction left no residuals. A second probe showed that QEMU can run inside that isolated network namespace while its Unix QMP socket remains controllable from the management namespace. The first implementation blocker is therefore not a topology engine or a fleet of Windows VMs; it is binding one exact externally owned network namespace into Windows KVM process identity without weakening the existing Provider authority.

### Practice-derived fidelity rule

The Range is the contested world; a VM is only one possible materialization of a world entity. Research should pay only the fidelity cost required by the hypothesis. A node may be semantic state, a real process, a Linux network namespace/container, a full VM, or later a physical machine. These are not interchangeable claims: every result remains bounded by the fidelity that produced it. If the experiment studies network discovery, a lightweight node with a real kernel network stack may be sufficient; if it studies Windows persistence or credential boundaries, the relevant target must be promoted to a Windows VM. Do not pre-build a universal fidelity framework or promotion engine. Introduce a second materialization abstraction only after distinct real consumers expose the same mechanism.

S5 is accepted at implementation revision `c1cef7a79ad0f501083940c8742db02a7ddb0bb1`. One disposable Windows Guest joined an externally owned isolated L2 fabric with one lightweight synthetic peer under the canonical 360-second physical acceptance bound. The Host independently retained QMP lifecycle/network-device authority, Linux netlink/bridge topology truth, a separate fallible tcpdump `sensor` observation, and complete machine/fabric residual closure while the Guest connectivity result remained contested. The physical falsifiers were informative: a root-namespace bridge coupled to existing Docker/WSL forwarding policy; invocation path and resolved binary identity diverged for multicall `mcopy`; Guest networking failed until configuration was bound to the exact QEMU-declared NIC MAC and connected route; and a deliberately shortened 180-second diagnostic bound was too close to Windows cold-start variance to serve as the acceptance bound.

S6 is accepted at implementation revision `03a93e36b53455477a3cd2b47006c53621317caf`. The same Windows KVM Guest remained alive while management removed lightweight peer A and introduced lightweight peer B. Host world truth retained the exact `peer-a-present → peer-a-removed → peer-b-present` sequence and updated current `fabricTruth` to peer B; the Guest reached both maintained services, the external packet sensor observed both TCP exchanges, and machine plus namespace closure remained clean. S6 also falsified two representation assumptions: a one-shot service may exit 0 before a controller's readiness check because an already-live Guest consumed it successfully, and accurate event history does not excuse a stale current-state snapshot.

S6 did not require a generic `RangeSession` mutation method. A post-S6 source audit did expose nearer implementation debt: `inspect()` still initiated the physical replacement, current Range resources were not durably complete after topology change, and the existing Windows KVM reconciler admitted only Evaluation identities. S6-R closes those gaps at revision `1eb638c962ac023d19514f645930cbefa4de08e9`: a backend-local controller owns progression, Host truth must converge before deletion becomes world truth, current peer/sensor/namespace identities are persisted, and a separate exact S5/S6 Range reconciler physically closes live QEMU, swtpm, peer B, tcpdump, namespaces, run state, ledger, and canary after owner SIGKILL. The ordinary Guest-driven S6 challenge remains accepted on the same revision.

C1 closes the first consequential Actor-requested world-change question at `49f1aa976cd3b78076f97f78accd921870b0ac02`: exact zone/capability `RangeAuthority` can admit one typed S6 peer replacement while intent, admission, backend receipt, and Host world truth remain separate. C1-A extends that result at `f692c22492e5b998df8373bcd165001e059307cf`: the same DeepSeek/Harness Actor, visible world, and authority chose `hold` for a stability objective and `request-effect` for a peer-B continuation objective, with no Tool correction. The corrected physical run also forced a stronger truth invariant: Range `inspect()` must return an immutable snapshot rather than a live reference that future topology changes can retroactively rewrite.

C1-B closes the first interrupted-effect question at production revision `dbd6b4c69379980389220001f96f2715de58ae83` and final fault-runner revision `360673436f23554621cf46b8d7eb1c2ac4aeb743`. A baseline owner-SIGKILL at `peer-a-removed` proved that S6-R physical resource recovery could safely close the world to zero while losing the semantic identity of the admitted effect. Persisting only the existing immutable Actor effect binding plus its non-truth backend receipt was sufficient for a new process to reconstruct request/admission/authority/effect identity. Two physical kill gates then distinguished an intermediate A-removed/B-absent world from a B-present world whose normal completion event was lost. In both cases independent Host topology truth prevented blind whole-effect replay, and the final ordinary Guest-driven S6 regression remained accepted.

C1-C now closes the first partial-materialization recovery question at `39693ebf1fc51a2814a8d15ddc136530ecf46533`. Killing the owner after peer-B namespace creation and root q/w veth creation, but before those links were placed or `peer-b-present` was published, exposed a stronger falsifier: the pre-fix reconciler returned `passed` and removed declared processes/namespaces while both root veths remained physically present. Its clean claim was therefore false even though every operation it knew about succeeded. The minimal fix adds deterministic `ownedHostLinkCandidates`, independently re-derives them from the S6 session identity, verifies a present candidate is a veth before deletion, and re-observes residual Host links before clean closure. Repeating the exact fault left zero Host-link or namespace residuals and required no experiment cleanup; the ordinary Guest-driven S6 regression remained accepted.

C1-D now closes that first fresh-controller continuation question at `691145f8466bc2a0633882ebd6540d0e480f0f82`. The maintained Windows Guest itself consumed peer A; the original controller then died at the C1-C root-veth partial state. A fresh process inherited the exact admitted effect and deterministic resource identities, independently observed the current Host placement, completed the missing q/w namespace/bridge/address/service suffix, published peer-B process identity only after Host verification, and let the same Guest connect peer B and complete. One surviving packet capture observed both A and B flows, QMP retained one Windows NIC, and later reconciliation closed the continued world to zero. No old `_FabricRun`, `RangeSession`, event stream, durable substep state, causal DAG, or whole-Range reset was consumed.

C1-E closes that first successor-versus-reconciler ownership race at baseline `351140fb9d8c2611b3e4c7b09908ca52fdd3bd04` and fixed revision `d82241b2f49994ee819dfb5d32a990bf97ea2830`. Without arbitration, a preflight-valid successor and the dead-owner reconciler physically interleaved: the successor moved part of the q/w pair while the reconciler deleted the same namespaces/VM substrate, and the successor failed because its world disappeared underneath it. The minimum accepted single-host mechanism separates predecessor provenance from current recovery authority: claim acquisition is CAS-bound to the exact ledger digest, while one per-Run kernel `flock` is the actual mutex shared by successor and reconciler. A live claim caused reconciliation to return `skipped-successor-active` with no Host mutation; the successor then reached `peer-b-present`. Killing the successor left durable claim metadata as provenance but automatically released the kernel gate, after which a second reconciler observed that exact stale claim and closed the world with zero residuals.

C1-F closes that first multiple-successor question at baseline `c9d98a1ca6bffb7058b2fbfe53b5aa57aace5d0a` and fixed revision `511f08fc74ba4590941683b6d0e62fc7c45815c7`. Two real successor processes observed the same initial ledger digest; the existing per-Run gate admitted exactly one while the loser left Host truth unchanged. The winner continued to `peer-b-present`, producing a newer ledger digest. After winner SIGKILL, the loser re-read that newer generation, acquired authority against it, recognized the persistent peer-B consequence even after the one-shot challenge service had exited, and returned `adopted-existing-effect` without replay or mutation. The baseline then exposed the only structural gap: an overwrite-only current claim erased the previous successor's provenance. The minimal fix archives each exact predecessor claim and adds one-hop `predecessorClaimId`/digest to the new current claim; final reconciliation records current + history before deleting recovery metadata.

C1-G closes that mid-successor pressure at `38f6e52f5fec9309e6fc5a9f36420a2cdbe9735a`. The first successor acquired authority against one exact ledger digest, moved q/w into their target namespaces and attached w to the fabric bridge, then died before link-up/address/service or `peer-b-present` publication. The ledger digest remained byte-for-byte unchanged despite materially different Host topology. A second successor acquired a new lineage-linked claim against that same durable digest, independently observed the changed midpoint, executed only the missing suffix, published a new stable ledger digest, and let the same Windows Guest complete A/B across the original-controller and first-successor deaths. Final reconciliation preserved current plus archived successor claims and closed with zero residuals.

C1-H closes that unpublished-completion pressure at corrected physical revision `6fce713dd44578293bec97f9e4ac14b229ae7612`. The first successor completed persistent peer-B topology, the same Guest consumed the one-shot B service and exited, and the successor was SIGKILLed before `peer-b-present` publication. The durable ledger digest remained unchanged. A second lineage-linked successor independently observed complete topology, extracted the completed Guest result, and read a point-in-time pcap snapshot while leaving tcpdump alive; together those evidence planes established `completed-but-unpublished`. It restarted no peer service, replayed no Range effect, and repaired only durable publication with `peerPid=0`. Final reconciliation later closed the live capture and preserved recovery lineage.

A first domain-success candidate at `1161ff80ce0fbae35b39f9dc1124a9b677c4578f` was rejected as canonical because its sensor helper terminated tcpdump while observing it; C1-H therefore also strengthens **observation != intervention** as an evidence-method discipline. The accepted run still did not force a durable completion receipt, substep journal, generation counter, exactly-once framework, or causal DAG.

C1-I closes the information-loss pressure at `3241eb91e025dbb4770cf7e4b87cd743bf0157be`. A delivered local vanishing pulse and an undelivered history produced the exact same durable sender digest `sha256:208cb48c1c39f1267385f2245a536e4174f2a8c3c1fa707689d67ac3e30050d0` and the same post-crash successor-view digest `sha256:7d2abd6480fc8d112b63f385d5257541d0c20a8ea6ec5b59271aabcce1d0b2cc`; both therefore classified `UNKNOWN`. A UID-65534 blind retry then physically produced two total pulses in the already-delivered history versus one in the never-delivered history. Recipient-owned exact-effect dedup made sender-side retry safe without revealing private recipient history, but did not yet test recipient crash inside its own consequence/dedup boundary.

C1-J closes that recipient commit-gap pressure at physical revision `6563613bc0757f8db15caf1c9014bab577d893f8`. `effect → SIGKILL → marker` duplicated on retry; reversing the order lost the consequence. A `reserved` inbox preserved exact uncertainty but could not choose retry versus suppress correctly for both possible histories.

C1-K closes the intrinsic-idempotency candidate at `e41ccf0ca852c7dc689ca8f6931321b9129e533b`. The consequence itself is one exact atomic ensure-symlink world state. In apply-then-ACK-loss, two physical invocations produced one request-owned mutation and one final semantic consequence; retry returned `already-satisfied`. Crash-before-apply used the same retry and returned `applied`. An exact preexisting target returned `already-satisfied` with zero request-owned mutations. The effect world contained no adjacent dedup/inbox object. C1-K therefore proves exactly-once invocation is not necessary for exactly-one semantic consequence when the effect contract is explicitly declarative and intrinsically idempotent.

C1-L closes the first compensation candidate at physical revision `bbbacb4828a9975cfc347a38e24437cef43613c0`. The original non-idempotent `+1` effect duplicated under ACK loss/retry from balance 1 to 2. A distinct `-1` compensation restored 2 to 1, but ACK loss followed by blind compensation retry overcompensated 1 to 0. Sound recovery instead re-observed the exact repair invariant: compensation crash-before-apply left balance 2 and authorized one repair, while compensation apply-then-crash-before-ACK left balance 1 and authorized publication-only recovery with no second decrement.

C1-M closes the first compensation-information-loss pressure at physical revision `404e7e691fd2ed6e557ad525c9ff0b63c8aceedd`. Downstream repair truth remains durable but private: UID 65534 can invoke compensation but cannot read `balance.json`. Under a naive subtract-one compensation identity, compensated and uncompensated histories have byte-equivalent sender ledgers and caller views despite private truth 1 versus 2; caller classification is therefore `UNKNOWN`. A distinctly identified `private-counter.ensure-repaired` protocol preserves that caller uncertainty while safely converging both hidden histories to balance 1.

C1-N closes the first downstream-truth-failure pressure at physical revision `88d068b1bce471faf3298fa050fec9c4de4eb27c`. For missing, malformed, and fork-conflict predicate state, repaired balance 1 and unrepaired balance 2 histories collapse to identical observations even for the owning downstream authority. The unchanged C1-M `ensure-repaired` effect performs zero mutation and returns `truth-unavailable` or `truth-conflict`. A distinct `truth-recovery:c1n-sealed-state-witness-v1` then verifies lineage/state/witness digests, restores exact pre-fault truth, and allows the original effect to return `already-repaired` for restored 1 or `applied` for restored 2; all six histories end at balance 1. Tampered witness data is rejected. This proves idempotency requires trustworthy predicate truth and demonstrates integrity-bound out-of-boundary state recovery for targeted static faults, but not witness freshness or atomic consequence/witness publication. The next pressure is a valid but stale witness.

## R3 — Opponent models and deception

Test explicit hypotheses about opponent objectives, capabilities, policy changes, decoys, false flags, sensor manipulation, and second-order beliefs.

Required comparisons:

- transcript-only baseline;
- explicit structured opponent state;
- natural-language hypotheses;
- deliberate opponent policy switches;
- natural fault versus adversarially induced fault.

Falsifier: explicit opponent models overfit known policies or fail to improve held-out performance and diagnosis.

## R4 — Campaign and strategic resources

Introduce Campaign state only after repeated Contests require persistence across missions or actor replacement. Measure initiative, tempo, reserve, option value, capability exposure, escalation, withdrawal, and allocation of compute, credentials, footholds, tools, and Agents.

Falsifier: an ordinary trajectory plus memory produces the same transfer and strategic ordering.

## R5 — Multi-Agent organization

Compare monolithic actors with specialist teams under limited communication, compartmentalization, delegated authority, compromised members, actor loss, and command replacement.

Falsifier: organization adds only latency and token cost, or Host branch/join semantics fully explain the behavior.

## R6 — Container emulation

Deploy a small isolated containerlab Range with Red workspace, Blue workspace, targets, gateway, sensor, and inaccessible management plane. Separate Provider traffic from contested Range traffic. Add Zeek first; add Suricata or endpoint collection only when required.

Falsifier: the Range cannot reset and destroy reliably, world truth depends on evaluated actors, or container fidelity does not change the research result.

## R7 — Open tools and classical capability reuse

Use CALDERA, ATT&CK mappings, shell tools, and defensive mechanisms through a Security `RangeActionGateway`. Compare structured actions, Ordivon Tool-proxy execution, and black-box Harness operation.

Falsifier: open tools bypass action authority or produce effects that cannot be independently reconciled.

## R8 — Adversarial evaluation

Vary evaluator visibility, monitor access, sensor reliability, evidence submission, scoring rules, and the actor's ability to influence telemetry. Study simulated compliance, monitor evasion, evidence omission, judge manipulation, and collusion.

Falsifier: the evaluator cannot detect known synthetic attacks, or rankings are unstable under immaterial judge changes.

## R9 — Coevolution and transfer

Run repeated encounters with held-out opponents, world variants, policy/tool mutation, alternating and simultaneous adaptation, and transfer from simulation to container and VM ranges.

Falsifier: gains disappear on held-out opponents or are explained by evaluator exploitation and memorization.

## Research discipline

Every experiment must bind:

- exact Scenario, Range, Actor backend, model/Harness revision, seed, budget, observation policy, Action catalog, and scorer;
- external source repository, revision, clean-tree status, and semantic configuration where applicable;
- static or scripted baselines;
- raw metrics and individual Trial evidence;
- negative, invalid, interrupted, deceptive, and inconclusive outcomes;
- a simpler representation and an abstraction deletion condition.
## Agent-first consolidation AF0–AF3

AF0–AF3 close the first structural consolidation after the C0/C1 consequence-recovery line. AF0 corrected the Agent-facing project model so `RangeSession` is the persistent-world spine and Contest/Evaluation/CAGE/Windows are scoped profiles or apparatus. AF1 added an explicit constitution/profile/integration/research-apparatus surface, canonical integration/World-boundary import paths, and removed the core singleton interpretation of `externalBoundary=denied` without inventing a new external-scope ontology. AF2 graduated C1-A into a minimal reusable `observation + objective + authority + effect interfaces → zero or more RangeEffectRequest` contract, with cognition remaining in Harness.

AF3 physically consumes AF2 at Security revision `9874d3e844c2b6d6eda4fe135077c296b8c737f1`. The same DeepSeek Flash/Harness defender receives the same adversarial compromise claim in two owned local worlds. With independent truth `compromised=false`, it submits zero requests and the world remains unquarantined; with independent truth `compromised=true`, it submits one exact quarantine request, Security admits it, the backend receipt remains non-truth, and fresh world truth verifies quarantine. All 16 gates pass. This first higher-order consumer therefore does **not** force Trust, Reputation, Organization, or a generic policy engine. The next research pressure should make the deceiver autonomous and reduce or delay independent truth; only repeated causal use of counterparty history should force durable trust/reputation state. C1-O witness freshness remains parked until a higher-order consumer reaches that boundary.

## Adversarial Epistemics AE0 — autonomous deception under partial truth

AE0 is accepted at physical revision `6b2d09b912d12827281439f9972b5d64ace8be4d`. A real DeepSeek Flash/Harness Deceiver privately observed each hidden service world and autonomously published the same receiver-visible `serviceCompromised=true` claim; in the healthy world its own conclusion explicitly described the claim as false and intended to induce quarantine. Sender-side effect identity remains internal evidence and is no longer projected into the receiver-visible message.

The healthy and compromised worlds therefore present the Defender with the exact same communicated claim and byte-identical pre-inspection AF2 context (`sha256:8485f66e4724648c6820cb2e7938a9d9fbd1d5a1692a44f3b516ac5519f8fcd1`). The Defender produces the exact same inspection intent/request in both worlds and does not quarantine from the claim alone. Inspection is admitted/executed as an explicit information-acquisition effect; its receipt remains non-truth and the later `world-truth` event reveals current compromise. Only then do contexts and consequences diverge: healthy → no quarantine, compromised → quarantine. All 18 gates pass.

The strongest candidate result is that `UNKNOWN` can justify information acquisition without justifying a hidden-world consequence. AE0 also exposes a scoped information-boundary rule: sender effect identity is not automatically receiver-visible message identity. Neither result is promoted to constitution after one consumer. Trust/Reputation and a new communication core remain unforced. Next pressure should delay, conflict, or price independent truth more aggressively before introducing durable counterparty state.

## Adversarial Epistemics AE1 — delayed truth under costly waiting

AE1 is accepted at physical revision `a428ab2b23498a90858811eb8554314e21d9b522`. One real DeepSeek Flash/Harness Deceiver privately observes `serviceCompromised=false` and autonomously publishes the false receiver-visible claim `serviceCompromised=true`. That exact claim (`sha256:eb936e6f8fae8d2e8e187c84aaf50fa91e37f28933a1050aaa21f88aa8a5e439`) is frozen and replayed into healthy and compromised Defender counterfactuals. This replaced a rejected design in which two independent Deceiver samples produced different claims and contaminated the hidden-world control.

Before truth divergence, the Defender is evaluated once per epistemic state and the exact Security decision is applied to both possible worlds. Shared initial context `sha256:2dac474994781d0b912faafcba3f7931783ecec3f7281bf19ee4318c4a94db15` yields inspection. Inspection reports only `pending`; shared pending context `sha256:706c979c6562631120b911c4051fc55a0ea7bafecd4d49a30217518f5702978e` yields a zero-effect hold. Each Range records `inspection-pending -> actor.pending-decision-recorded -> inspection-result` so the hold physically precedes truth publication. In the compromised counterfactual, waiting accrues exposure cost `3`; after truth arrives the healthy world remains unquarantined while the compromised world requests and verifies quarantine. All 25 gates pass.

AE1 therefore extends the current epistemic candidate: `UNKNOWN` can justify risk-bearing waiting while independently sourced truth is pending. It still does not force Trust/Reputation, freshness, reversible containment, or a new communication core. AE1 also corrected AF2 integration semantics: `needs_input` may represent a complete current Security decision with incomplete world knowledge; positive effects remain Tool-explicit; zero-effect decisions need no ceremonial empty Tool call; and Harness closure metadata stays in turn evidence instead of Security decision identity. Next pressure should introduce conflicting independently sourced truth.

## Adversarial Epistemics AE2 — conflicting independent observations

AE2 is accepted at physical revision `990e71ff53dc3634e48c3612bc571603e338edb7`. The experiment corrects the informal “conflicting truth” frontier: two independently sourced observations remain `sensor` evidence, not competing `world-truth` authorities. It reuses the exact AE1 adversarial claim and presents `sensor:ae2-a -> serviceCompromised=true` and `sensor:ae2-b -> false` with distinct provenance, no source priority, and no prior source history. The pre-truth context intentionally avoids Trust/Reputation/confidence vocabulary.

One shared DeepSeek Flash/Harness Defender call over context `sha256:c5740febe11af021e3dc5bedc0f95b06380598b297cec92b5a902d9a528cbe0a` requests exactly one adjudicating inspection (`sha256:e8c87097a6fcad41133182fb252ba6fc5fddb924c00bdd073b3740997805b738`) and does not quarantine from either sensor. Separate Security admission/execution follows. The authoritative result event causally binds both the Agent decision and the physical inspection-executed event. Only then do the hidden worlds diverge: healthy stays available, compromised requests and verifies quarantine. All 27 gates pass.

AE2 therefore supports a narrow candidate: conflicting independently sourced observations plus no ranking/history do not justify arbitrary source selection; provenance plus `UNKNOWN` can be sufficient to trigger explicit adjudication. The Agent spontaneously reasons that source reliability is relevant, but this one-shot consumer still does not force durable Trust, Reputation, confidence, source-history, or freshness state. The next pressure should remove cheap adjudication or make repeated source history causally useful.

## Adversarial Epistemics AE3 — conflict without adjudication

AE3 physically runs at revision `3bb5052efcfb7f3650abbc4488a0769bb91affe8` with AE2's Harness revision `98d295582dd9a5034413d87cc488089a1c75b138` intentionally frozen because current Harness had already added caller-ingress durable-promotion controls. The exact AE1 false claim and AE2 conflicting sensor set are reused, but `service.inspect` is removed: the Defender has only quarantine or zero-effect hold, and no passive evidence will arrive. Shared context `sha256:80082af6a4cdfc05614ce8a78aec62044867325c75f058f40d0fbdd1eb4f1ed5` yields a shared hold decision `sha256:5733cc31dcb66890e1ec2edbe39734a454102eaa7577a149be04e9a32ce1b1d7`. The hidden truth is revealed only afterward to a non-Agent evaluator. Hold has regret `0` in the healthy world and `10` in the compromised world; the oracle action differs across observationally identical worlds.

All 26 mechanical gates pass, but the run also contains a scientific falsifier: after correctly saying probability/reliability cannot be inferred, the Agent describes the conflict as `50/50-style` and uses expected-loss reasoning, introducing an unsupplied prior. AE3 therefore rejects the stronger hypothesis that consequence costs plus current `UNKNOWN` evidence determine one risk-optimal action. It accepts only the structural result that a bounded consequence choice can occur under `UNKNOWN` without the action becoming truth, and that additional decision basis is required for optimality claims. The raw receipt's premature `sourceHistoryPrimitiveForced=false` interpretation is not promoted; apparatus revision `238472e3726613031fb0de08e4615e523b37cda5` corrects it to unknown. Next pressure is raw, adjudicated source history as ordinary evidence before any Trust/Reputation abstraction.

## Adversarial Epistemics AE3-B — raw verified source history falsifier

AE3-B runs at revision `96fe5af9e14b8acc3b49a241ee55531dc90b0b9d` with frozen Harness `98d295582dd9a5034413d87cc488089a1c75b138`. Two mirrored treatments expose four raw prior episodes with the same adjudicated truth sequence; A-history makes source A match all four truths, while B-history makes source B match all four. Current claim/sensors, costs, authority, no-adjudication condition, and all non-history visible evidence remain fixed. No Trust/Reputation/reliability/accuracy/confidence summary is supplied. Two Provider replicates per treatment were declared before execution.

The strong hypothesis is falsified: 16/18 gates pass, but A-history produces `quarantine` then `hold`, while B-history produces `hold` twice. More importantly, the model mis-aggregates simple raw history in A-history replicate 1 and B-history replicate 2. A-history replicate 2 correctly computes A=4/4 and B=0/4 and repeatedly argues quarantine is more defensible, yet its structured AF2 intent is zero effects. This reinforces `natural-language analysis != Security effect intent` and shows that `evidence present in context != evidence correctly reduced`. Raw history can still be useful—B-history replicate 1 correctly uses exact-pattern prior episodes—but ordinary context is not sufficient for stable, reproducible reduction and effect choice in this consumer.

The next pressure is a deterministic, reconstructable factual reducer over the exact episodes: counts, matches and exact-pattern frequencies bound to source episode IDs and a derivation digest. Such output remains derived evidence, not current world truth or a Trust score. If this stabilizes behavior, the likely abstraction pressure is generic evidence computation/tooling rather than a Security-owned Trust system.

## Adversarial Epistemics AE3-C — verifiable evidence reduction

AE3-C is accepted at physical revision `766766859bebb608320e3bd82afd639d1050a57b`. It reuses the exact AE3-B raw history digests and freezes Harness `98d295582dd9a5034413d87cc488089a1c75b138` plus Computing `3493693b9c23274213eca44aa9bfa3b3252b29af`. The only new research structure is an experiment-local deterministic reducer that derives exact source-match counts and exact current-pattern prior occurrences, binds history/current-sensor digests and episode IDs, and exposes a reconstructable projection digest. The projection is explicitly neither current world truth nor a policy instruction.

All 22 gates pass. A-history projection `sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b` records A=4/4, B=0/4, with the current sensor pattern previously adjudicated true twice; both Provider replicates request quarantine with the same Security decision. B-history projection `sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1` records A=0/4, B=4/4, with the current pattern previously adjudicated false twice; both replicates hold with the same Security decision. The physical Range chain records raw episodes/current sensors → derived projection → Agent decision.

For this consumer, exact evidence reduction removes the specific aggregation and reasoning/effect instability observed in AE3-B without a Trust/Reputation primitive. The reducer remains research apparatus; the next architectural question is whether generic provenance-bound count/filter/group/compare operations are demanded across Ordivon domains and how their derivations survive recovery. Do not promote this experiment-local reducer into Security core merely because it worked here.

## Evidence Computation EC0 — externalized exact computation

EC0 is accepted at apparatus revision `3ffafc4544f4fdda4d2d747a01006c415eef3b8f`. A pure-stdlib standalone program with no `ordivon_security` import consumes Git-owned fixtures whose embedded histories and current sensor set exactly reproduce the accepted AE3-B/AE2 semantic digests. Static tests require its complete output objects to equal the accepted AE3-C projections and rebuild the exact AE3-C Agent context digests. Two Runtime `contained_local` Jobs then physically execute the committed program over A/B fixtures; both Execution Plans bind Workspace source digest `sha256:8b864a17032bfcf291b113a7d4091b4d7563a93a473cbd02aa2a6146ae7c1145`, and retained stdout emits the exact accepted projection digests `sha256:2c174f54...` and `sha256:c394429d...`.

The accompanying read-only cross-domain audit finds Finance is already an independent consumer of the lower-level pattern through PIT `FinanceLabSession`, Polars/DuckDB Agent programs, immutable research execution materialization and semantic result admission. World mainly needs provenance/reconciliation rather than statistical reduction; Harness should expose Agent-selected Tools/Working Sets rather than rank evidence; Runtime owns physical freezing/execution rather than domain semantics; Computing currently has no justified evidence-algebra product surface. EC0 therefore rejects a shared `EvidenceReducer` library for now. The candidate cross-domain invariant is exact source evidence + exact transformation identity + exact execution evidence + exact output identity. The next pressure is an integrity-valid derivation whose source evidence later advances; only that real consumer should reopen freshness/C1-O.
