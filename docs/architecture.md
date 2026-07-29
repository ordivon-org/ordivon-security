# Architecture

This document separates the **research architecture** from the repository's
currently implemented experimental-support substrate.

## Research architecture

```text
Strategic adversarial plane
  ├─ conflicting objectives and victory conditions
  ├─ opponent models and belief states
  ├─ initiative, tempo, escalation, withdrawal
  ├─ deception, counter-deception, deterrence, signalling
  └─ strategic resource and information allocation
                │
                ▼
Operational Campaign plane
  ├─ Campaign synthesis and revision
  ├─ intelligence requirements and collection
  ├─ phases, missions, branches, reserves, and contingencies
  ├─ adaptation history and counter-adaptation
  └─ multi-Agent command and organization
                │
                ▼
Tactical Agent plane
  ├─ reconnaissance, analysis, exploitation, detection
  ├─ repair, restoration, containment, and response
  ├─ tool selection and construction
  └─ action execution and feedback interpretation
                │
                ▼
Mature classical capability plane
  ATT&CK / D3FEND / Engage · scanners · fuzzers · sandboxes · IAM
  network controls · EDR/SIEM · forensics · patching · cyber ranges
                │
                ▼
Contested world plane
  hosts · services · code · identities · networks · data · tools · Agents
```

Ordivon Security's candidate ownership begins at the Operational Campaign plane
and becomes strongest at the Strategic Adversarial plane. The Tactical plane is
shared with Host and domain tools. Classical mechanisms and world execution are
reused from mature projects and the rest of Ordivon.

## Candidate research objects

The following are hypotheses, not frozen implementation contracts:

| Object | Research purpose |
|---|---|
| Actor | represent a goal-bearing participant's knowledge, beliefs, resources, capabilities, and organizational relations |
| Contest | represent the conflict structure across actors, world, rules, information, resources, and outcomes |
| Campaign | represent one actor's or coalition's long-horizon organized effort to change the Contest |
| Opponent model | represent hypotheses about another actor's objectives, beliefs, capabilities, policy, and adaptation |
| Information position | represent what each actor can observe, infer, hide, signal, or manipulate |
| Strategic outcome | evaluate objective progress, initiative, resources, information advantage, capability exposure, and future options |

No separate database, protocol, or universal schema should be created merely to
make this vocabulary look complete. The first requirement is a comparative model
and experiments showing where existing game, evaluation, cyber-range, and Agent
frameworks are insufficient.

## Cross-project responsibility

| Responsibility | Natural owner |
|---|---|
| cognition, Goal, Task, Context, memory, model/scaffold identity | Host |
| Effect execution, Workspace, Job, Attempt, process tree, terminal evidence | Runtime |
| connectivity, path, communication policy, network evidence | Link |
| external body, provider, Sandbox generation, placement lifecycle | Edge |
| general World mechanics, simulation clock, deterministic state, replay | Game |
| adversarial relationship, Campaign research, opponent model, strategic outcome | Security |

Security consumes component-native identities and evidence. It must not create a
shadow Host, Runtime, network controller, Edge provider, Game engine, scanner,
or cyber-range implementation.

## Current implemented substrate

The existing code implements:

```text
Campaign Manifest
  → append-only authority ledger
  → component-native identity bindings
  → fixed lifecycle coordination
  → unknown-result reconciliation
  → residual-state classification
  → sealed evidence export and structural replay
```

This is useful infrastructure for reproducible experiments. It currently proves:

- exact admission identity;
- capability/consequence separation;
- component binding without state copying;
- durable lifecycle intent and reconciliation;
- evidence integrity and closure;
- one infrastructure-only Link/Edge/Runtime composition.

It does not prove:

- adaptive offense or defense;
- Campaign synthesis;
- opponent modelling;
- belief revision or deception;
- initiative or strategic resource allocation;
- multi-Agent command;
- coevolution;
- strategic outcome validity.

## Substrate freeze rule

The implemented substrate remains maintained and tested, but its vocabulary and
scope are frozen by default. Expansion requires all of the following:

1. a concrete adversarial experiment exposes an unrepresentable fact;
2. mature external frameworks cannot carry that fact without semantic loss;
3. the fact crosses component boundaries and cannot live naturally in Host,
   Runtime, Link, Edge, or Game;
4. a simpler experiment record or adapter is insufficient;
5. the new abstraction changes diagnosis, comparison, adaptation, or research
   validity in a measurable way.

## Research and experiment planes

A future experiment may use four operational planes without making them the
project's conceptual center:

- **world-management plane** — creates and destroys the owned range;
- **actor plane** — contains evaluated offensive, defensive, neutral, service,
  user, and observer actors;
- **observation plane** — preserves world truth and actor-specific observations;
- **evaluation plane** — computes multiple outcome dimensions and tests evaluator
  integrity.

The evaluated actors may study and attack one another. They must not receive
undeclared authority over the external world-management plane. This is a legal
and experimental-validity boundary, not a reason to weaken internal adversarial
capability.
