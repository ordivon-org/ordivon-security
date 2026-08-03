---
schema_version: 1
id: security.charter
title: Ordivon Security Charter
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
summary: Canonical decision defining Security's adversarial relationship, strategic research scope, classical-substrate reuse, cross-project boundary, authorization conditions, and success criterion.
evidence_status: not_applicable
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.start
  - security.architecture
  - security.research-boundary
  - security.authority
---
# Ordivon Security Charter

## Context

Security projects commonly collapse intelligent opposition into static vulnerabilities, policy compliance, scanner output, or one-sided safety evaluation. Ordivon needs a research boundary where attacker, defender, target, observer, ally, rival, and evaluator may all be adaptive subjects.

## Decision

Make the adversarial relationship the central object. Reuse mature classical security and world substrates, preserve actor-specific information and independent evaluation, permit high-intensity work only inside owned or explicitly authorized worlds, and admit new abstractions only when experiments show an Agent-native gap.

## Consequences

Cyber is the first reproducible domain rather than the full boundary. Security does not duplicate Host, Harness, Runtime, World, Game, identity, scanner, workflow, or production-control responsibilities. Reachability never grants authority, and undeclared third-party effects invalidate an experiment.

## Status

Accepted and active. [`docs/architecture.md`](docs/architecture.md) defines current structure, [`docs/research-boundary.md`](docs/research-boundary.md) defines authorization, and [`docs/authority.md`](docs/authority.md) records content authority. The former Campaign infrastructure remains historical evidence and is not restored by this charter.

Status: strategic reorientation — research charter

## Mission

Ordivon Security is Ordivon's Agent-native strategic adversarial-systems
project. It studies and constructs intelligent actors that can pursue conflicting
objectives in long-horizon, partially observed, dynamically changing digital
environments containing adaptive opponents.

Its subject is not merely whether an Agent is safe. Its subject is what happens
when intelligence becomes attacker, defender, target, observer, ally, rival, and
judge.

## Central object

The central object is the **adversarial relationship**, not the vulnerability,
permission, alert, or individual action.

A serious research setting contains:

- multiple goal-bearing actors;
- asymmetric and potentially manipulated information;
- scarce resources and constrained action opportunities;
- a world whose state can be contested;
- active adaptation and counter-adaptation;
- strategic objectives, victory conditions, and exit conditions;
- consequences that unfold across many tasks and observations.

## Research domains

Ordivon Security investigates:

- autonomous Campaign synthesis from strategic objectives;
- opponent modelling and belief revision under partial observability;
- intelligence collection, denial, deception, and counter-deception;
- initiative, tempo, escalation, withdrawal, and resource allocation;
- adaptive offensive and defensive action;
- multi-Agent organization, command, delegation, trust, collusion, and failure;
- long-horizon continuity across model, Host, process, body, and world changes;
- attack-defense coevolution and transfer across opponents and environments;
- adversarial evaluation in which traces, monitors, scorers, and judges are
  themselves part of the threat model.

Cyber is the first experimental domain, not the complete theoretical boundary.

## Relationship to classical security

Classical security provides mature tactics, techniques, countermeasures,
scanners, fuzzers, sandboxes, identity systems, network controls, observability,
forensics, patching, and cyber-range substrates.

Ordivon Security does not rebuild them. It studies how intelligent actors:

- choose and combine them;
- infer their opponent's use of them;
- adapt after countermeasures;
- conceal or expose capability;
- allocate them across a Campaign;
- alter the information and strategic position of other actors.

## Relationship to Ordivon

- Host owns Goal and Task continuity, commitment, uncertainty, verification, and outcomes;
- Harness owns replaceable Agent Assignment, Run, Provider, Tool, and recovery semantics;
- Runtime owns Workspaces, Jobs, Attempts, Artifacts, process state, and physical recovery;
- World owns external provider adapters and private operator tools;
- Game and domain systems own authoritative world mechanics, simulation, and replay;
- Computing owns promoted shared contracts and cross-project research synthesis;
- Security owns the research problem of conflict: actors, conflicting objectives, Contest and Campaign hypotheses, opponent models, strategic outcomes, and adversarial evaluation.

Security must not copy the authoritative state of the other projects.

## Experimental substrate

Security retains only the adversarial experiment and evaluation layer. Historical Campaign lifecycle and infrastructure-composition machinery is recoverable from Git but is not active architecture.

## Governing principles

1. **Opposition is intelligent.** The opponent is a subject that observes,
   predicts, deceives, and adapts—not a static fault model.
2. **Strategy is not a workflow.** A fixed action graph cannot stand in for a
   Campaign that revises itself under counterplay.
3. **Information state is real state.** Changes in beliefs, uncertainty,
   deception, and mutual knowledge are part of the outcome.
4. **Attack and defense are symmetric research objects.** Offense is not merely
   a tool for validating defense; defense is not merely a safety wrapper.
5. **Capability is relational.** A capability claim is incomplete without the
   opponent, information, resources, environment, time, and organization under
   which it holds.
6. **The evaluator is contestable.** Public or predictable scoring and
   monitoring may be optimized against or manipulated.
7. **Reuse classical machinery.** New implementation is admitted only when an
   Agent-native distinction survives comparison with mature alternatives.
8. **Research precedes ontology.** Contest, Campaign, belief, advantage, and
   organization remain falsifiable vocabulary until experiments require stable
   contracts.
9. **Owned ranges permit high internal intensity.** Within declared authorized
   worlds, experiments may grant broad autonomy, tool creation, persistence,
   multi-node action, adaptive opponents, and long execution.
10. **No uncontrolled third-party effects.** Authorization and isolation are
    experimental boundary conditions, not the intellectual center of the
    project.

## Success condition

Ordivon Security succeeds when it can make intelligent opposition a first-class,
reproducible research object; distinguish tactical success from operational and
strategic advantage; explain how actors model and manipulate one another; and
show adaptive attack-defense behavior that cannot be reduced to scripted tools,
fixed policies, or static benchmarks.

The cross-project research charter is maintained in
`ordivon-computing/research/charters/SECURITY-CHARTER-001.md`.
