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
