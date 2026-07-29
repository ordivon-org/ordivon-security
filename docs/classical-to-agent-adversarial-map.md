# Classical-to-Agent adversarial systems map

## Purpose

This map prevents two opposite errors:

1. rebranding mature security automation as Agent-native research;
2. reducing intelligent opposition to an ordinary safety or assurance problem.

## Comparative layers

| Layer | Mature examples | What it already solves | Remaining Agent-native question |
|---|---|---|---|
| attack knowledge | MITRE ATT&CK, threat intelligence, kill-chain models | observed tactics, techniques, procedures, and operational goals | how an actor chooses, composes, hides, revises, or abandons tactics against a specific adaptive opponent |
| defensive engineering | D3FEND, detection engineering, EDR/SIEM, incident response | countermeasure mechanisms, sensors, response, restoration | how a defender models adversary intent, allocates scarce attention, deceives, and adapts strategically |
| adversary engagement | MITRE Engage, honeypots, decoys, denial and deception | planned manipulation of adversary observations and behavior | autonomous belief manipulation, second-order reasoning, and counter-deception between adaptive Agents |
| automated cyber reasoning | DARPA CGC, AIxCC, program analysis, fuzzing, patch synthesis | machine-speed vulnerability discovery, proof, exploitation, and repair | open-ended Campaign formation, opponent modelling, multi-stage strategy, and organization beyond code-centric objectives |
| autonomous cyber simulation | CybORG/CAGE, CyberBattleSim | partially observed sequential Red/Blue interaction and learned policies in defined action spaces | open tools, strategic objectives, changing organizations, explicit beliefs, deception, and long-horizon transfer |
| Agent control evaluation | Inspect, ControlArena | testing policies and monitors against sabotage or untrusted Agents | treating multiple adversarial Agents as the normal system form rather than one untrusted policy inside a control protocol |
| game and MARL theory | POSGs, extensive-form games, opponent modelling, Melting Pot | formal multi-actor uncertainty, policies, incentives, social generalization | persistent language/tool Agents whose action, communication, organization, and world interfaces remain open-ended |
| classical execution | OS, VM, container, IAM, networks, provenance, forensics | actual authority, isolation, effects, observation, recovery | binding these mechanics to strategic Agent continuity without copying or weakening them |

## Progression of autonomy

```text
mechanical tool
  executes one operation

scripted automation
  follows a human-authored rule or workflow

adaptive policy
  selects actions from a predefined space using observations and reward

Agent operation
  interprets a task, plans, uses or creates tools, and revises local action

strategic adversarial Agent
  maintains objectives, opponent models, information state, resources,
  organization, and Campaign continuity against active counter-adaptation
```

Ordivon Security should not claim progress merely because an LLM replaces a
script. The decisive evidence is whether the system handles strategic variables
and unfamiliar adaptive opponents.

## What remains classical

The following should normally remain external or component-owned:

- exploit primitives and vulnerability databases;
- scanners, fuzzers, symbolic execution, static analysis, and patch engines;
- container/VM isolation, namespaces, cgroups, and network policy;
- identity, credentials, secret management, signing, and provenance;
- logs, traces, EDR/SIEM, packet capture, and forensics;
- cyber-range provisioning and service emulation;
- generic evaluation runners and statistical libraries;
- game engines and standard multi-Agent environment APIs.

## What may be Agent-native

Candidate gaps requiring research:

- strategic objectives that persist above individual Tasks;
- Campaign revision in response to interpreted counterplay;
- explicit competing hypotheses about opponents;
- information-state and deception semantics;
- initiative, tempo, capability exposure, reserve, and option value;
- multi-Agent command, compartmentalization, collusion, and reorganization;
- evaluation against held-out adaptive actors;
- cross-Host and cross-world strategic continuity;
- attack-defense coevolution and transfer.

## Strongest danger of project drift

The repository will regress into conservative security engineering if its main
outputs become:

- more permissions and policy checks;
- more lifecycle gates;
- more evidence schemas;
- more containment infrastructure;
- more static attack tests;
- more compliance or risk reporting.

Those can support experiments, but they are not the project's purpose.

## Admission test for new Security work

A proposal belongs in Ordivon Security only when it can answer yes to most of the
following:

1. Is there an adaptive or strategically relevant opponent?
2. Does the work concern conflict across objectives, information, resources, or
   world state?
3. Does it span more than one tactical action or isolated task?
4. Is a belief, deception, organization, adaptation, or strategic-outcome
   distinction required?
5. Can the work be tested against a simpler classical or scripted baseline?
6. Would deleting the Security-specific abstraction erase a measurable
   adversarial capability or explanation?

Otherwise it belongs in a mature external tool, another Ordivon component, or a
scenario-specific adapter.
