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

The typed effect surface has therefore not yet earned generalization into a persistent action gateway. The strongest next pressure is interrupted effect recovery: kill the controller after admission/request binding or during the physical transition, then require a replacement controller to reconstruct actual world state from durable identity and observation without blind duplicate mutation. Let that experiment determine whether durable effect state, stronger `causalParents`, resumable `RangeSession`, or exactly-once semantics are unavoidable.

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
