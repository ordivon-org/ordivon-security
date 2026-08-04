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
updated: 2026-08-04
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

Status: initial transfer implemented. Ordivon now explicitly supplies all actions for one CAGE Red agent and five CAGE Blue agents while Green remains native. The current Actor surface selects native-policy or Sleep team plans. Parameterized action construction, held-out policy comparisons, and model/RL Actors remain open.

Falsifier: Ordivon's contracts add no diagnostic or experimental value over native CAGE episodes.

## R2 — Native model-backed actors

Connect Security domain tools to Ordivon Harness, then run DeepSeek Flash-backed Red and Blue actors with durable Assignment, bounded context, explicit Tool grants, pause/resume, Provider failure evidence, and replaceable model identity.

The first experiment may select CAGE team plans. A later experiment should expose parameterized CAGE actions only after their identity, admission, and observation contracts are stable.

Falsifier: direct stateless model calls perform equivalently and no continuity or effect-reconciliation distinction appears.

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
