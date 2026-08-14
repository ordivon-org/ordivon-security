---
schema_version: 1
id: security.classical-capability-basis-ca0
title: Classical Capability Basis CA0
type: research
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
updated: 2026-08-14
summary: First-principles reconstruction of the classical cyber capability world, comparing goal trees, tool trees, pure state-transition models, and an orthogonal capability contract across classical malware, exploitation, defensive tooling, cyber-agent simulation, and Agent-specific attacks.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security
related:
  - security.research-agenda
  - security.research-boundary
  - security.provider-first-pf0
---
# Classical Capability Basis CA0

## Question

CA0 asks a deliberately more fundamental question than “which attack tools should Security add?”:

> **What is an adversarial cyber capability, at the lowest useful level that remains stable across scripts, macros, installers, malware, exploits, credentials, worms, defensive tools, simulated cyber agents, and future Agent-native attacks?**

The answer matters because a wrong basis creates a permanently distorted Agent action space. A tool tree makes Agents reason in product names. A tactic tree makes them confuse goals with mechanics. A malware-family tree makes replication architecture look like payload semantics. An overly abstract state graph removes exactly the carrier, provider, evidence, and exposure distinctions that determine whether a real action is useful.

CA0 therefore does not start from ATT&CK as an ontology authority. It starts from first principles, compares several mature external projections, attacks competing decompositions with materially different cases, and retains only distinctions whose removal collapses a real Agent decision or experimental claim.

No physical malware or exploit execution is required by CA0.

## Source families

The external systems examined in this round intentionally answer different questions:

| Source family | Primary question it answers | CA0 use |
| --- | --- | --- |
| MITRE ATT&CK Enterprise v19.1 | Why does an adversary act, and how has behavior been observed? | goal/tactic and technique evidence |
| CAPEC 3.9 | What attack mechanisms and execution patterns recur across weaknesses? | mechanism evidence |
| CWE vulnerability theory | What distinguishes attack, consequence, weakness, and vulnerability? | opportunity/consequence separation |
| Malware Behavior Catalog + capa | What can executable code do, independent of malware family name? | code-behavior evidence |
| Atomic Red Team | Can one focused behavior be physically tested against controls? | atomic action/test evidence |
| Attack Flow 3.2 | How do actions create preconditions for later actions? | composition/dependency evidence |
| CALDERA | How are abilities, agents, adversary profiles, facts, and planners operationally separated? | provider/action/policy evidence |
| CyberBattleSim | Can exploit behavior be represented as precondition + outcome without executable exploit code? | abstract state-transition evidence |
| CybORG/CAGE | Can common high-level actions span simulated and emulated worlds? | fidelity and Agent action evidence |
| DARPA CGC / AIxCC | What does automated vulnerability discovery, exploitability reasoning, and repair look like as a machine capability? | capability-generation evidence |
| MITRE D3FEND | How do defensive techniques relate to concrete digital artifacts, events, sensors, and weaknesses? | defensive applicability evidence |
| Zeek / Suricata / Sigma / YARA / Velociraptor | What separates telemetry, pattern matching, alerting, file classification, endpoint collection, and response-capable operations? | observation/detection/response evidence |
| Cohen virus theory + Morris worm analysis | What is structurally special about replication and autonomous propagation? | control-mode evidence |
| InjecAgent / AgentDojo / Morris-II | Which classical invariants survive when the attacked principal is a tool-using language Agent? | cross-carrier transfer falsifier |

These systems are not treated as interchangeable taxonomies. Their disagreement is useful because many of them describe orthogonal projections of the same event.

## First-principles model

Start with an adversarial world rather than a catalog.

Let:

- `W` be the current world state;
- `Actor_i` be one actor with objective or utility `U_i`;
- `O_i(W)` be the evidence currently visible to that actor;
- `A_i` be the authority actually granted to that actor;
- `P` be an opportunity/precondition that may make some transition possible;
- `Provider` be the component that mechanically attempts a transition.

A cyber conflict exists because actors want incompatible changes to world state or information while observing only part of that world.

The smallest useful classical capability candidate is therefore not a tool name or ATT&CK ID. It is a **conditional transition option**:

```text
Capability =
  desired relation/effect family
+ required world preconditions/opportunities
+ mechanism
+ carrier/substrate
+ exact provider realization
+ target/scope
+ required authority
+ control mode
+ expected consequence family
+ observable/evidence surface
+ cost / exposure / uncertainty
+ reversibility / cleanup / recovery
+ fidelity / applicability / currentness
```

A capability is still only an option. It does not prove that the action will work.

The operational chain is:

```text
opportunity / preconditions
        ↓
capability available
        ↓
Actor selects one bound action
        ↓
Security admits exact intent + authority
        ↓
Provider attempts mechanics
        ↓
provider execution receipt
        ↓
fallible observations / detections / claims
        ↓
independent consequence evidence
        ↓
updated world / Actor evidence
```

This chain preserves several distinctions that classical cyber systems repeatedly need and that current Security experiments already independently discovered.

## Seven separations CA0 retains

### 1. Opportunity != capability

A weakness, vulnerable revision, misconfiguration, exposed trust relationship, leaked token, reachable service, or attacker-controlled document can make a transition possible. It does not itself perform the transition.

A public CVE record is weaker still: it is information about a class of possible opportunities. Target-specific applicability and consequence remain separate.

This is why CA2 must not represent “CVE present” as “exploit capability succeeded.”

### 2. Capability != action

A capability describes what can be attempted under a set of conditions. An action binds target, parameters, provider, authority, time, and experiment identity.

The same capability can produce many actions. A failed action does not erase the capability; a capability catalog does not prove an action was admissible or executed.

### 3. Action != consequence

An invocation receipt is mechanical evidence. A scanner hit, process exit code, CALDERA link result, EDR alert, or Agent conclusion is not automatically authoritative world truth.

Security already has the correct substrate here: intent, admission, backend/provider receipt, sensor evidence, and independent world truth remain separate.

### 4. Goal/effect != mechanism

ATT&CK's tactic/technique split and CAPEC's explicit mechanism view expose the same structural pressure from different directions.

“Credential access,” “persistence,” “impact,” or “reduce defender visibility” describe why or what changed. Exploiting a parser weakness, abusing existing functionality, inducing another principal, replacing an artifact, or using valid credentials describes how that change was attempted.

A single mechanism can serve several goals, and one goal can be achieved through many mechanisms.

### 5. Mechanism != carrier

PowerShell, a document macro, an MSI custom action, a native executable, a protocol message, a credential, a package, or an Agent tool result are execution/transport substrates. They change policy gates, provenance, host process, privilege context, observability, and defensive exposure.

They do **not** necessarily change the semantic world effect.

This distinction is essential for CA1: script/macro/installer research should determine when carrier choice changes adversarial outcome, not pretend that each carrier is a new strategic objective.

### 6. Malware architecture != payload effect

“Virus,” “worm,” and similar malware labels often encode how code is hosted, replicated, delegated, propagated, or disguised.

A host-attached virus is structurally about replication through another program. A worm is structurally about autonomous or delegated propagation across entities. The payload can still collect, modify, deny, observe, persist, or do nothing beyond reproduction.

Therefore `self-propagating` belongs first as a **control mode / continuation property**, not as a peer semantic effect beside credential access or data destruction.

### 7. Atomic action != attack

A real attack is not one technique invocation. It is a policy or flow that chooses actions to create the preconditions for later actions while an opponent changes the world.

Attack Flow makes action dependency explicit. CALDERA separates abilities from adversary profiles/planners. CyberBattleSim separates primitive local/remote/connect actions from the policy that selects them. CAGE separates an Agent policy from the environment action implementation.

This is the exact boundary CA6 will later test physically:

```text
classical capability mechanics
!=
Agent tactical selection and adaptation
```

## Competing decomposition A — tactic/lifecycle tree

The first candidate is the familiar lifecycle/tactic decomposition:

```text
reconnaissance
→ initial access
→ execution
→ persistence
→ privilege / credential
→ discovery / movement
→ collection / C2 / exfiltration
→ impact
```

### What it gets right

It preserves operational purpose. It is excellent for communicating why observed adversary behavior matters and for coverage analysis against known campaigns.

### What breaks

It is not an Agent capability contract.

A technique can legitimately serve several tactics. A single action can simultaneously alter control, authority, persistence, observability, and asset state. Scripts/macros/installers largely disappear into technique details. Vulnerability opportunity and exploit attempt are easy to collapse. Defense becomes a separate ontology. Replication/autonomy is poorly represented. ATT&CK itself evolves its tactic split as the community's conceptual model improves.

**CA0 result:** retain ATT&CK tactic/technique mappings as external coordinates, not Security capability identity.

## Competing decomposition B — tool/artifact tree

The second candidate groups by concrete classical thing:

```text
shell / PowerShell
macro / document
installer / loader
exploit
credential
malware / virus / worm
C2
scanner / fuzzer
IDS / EDR / SIEM
forensics
```

### What it gets right

It is concrete, provider-friendly, and close to operator vocabulary. It captures carrier-specific policy and telemetry differences that a pure tactic tree hides.

### What breaks

It mixes almost every semantic layer.

A macro is a carrier. A scanner is an observation/opportunity-discovery provider. A credential is both an artifact and an authority resource. A worm is a propagation architecture. C2 is a control/communication relation. EDR is a family of sensors, detectors, and responders. An exploit is a mechanism bound to an opportunity. None are peers.

It also transfers badly to Agent systems: indirect prompt injection and a self-replicating prompt would force new leaves even though their deeper mechanics reuse old trust, induced-action, authority, and propagation structures.

**CA0 result:** retain exact tool/carrier/provider identity as evidence and operational metadata, not as the top-level world model.

## Competing decomposition C — pure relation-state graph

The third candidate removes tool vocabulary and models only world relations.

A useful conceptual world can be projected as relations such as:

```text
knowledge(actor, proposition/evidence)
authority(principal, resource, operation)
control(actor, entity/service)
continuity(control, disruption/time)
reachability(entity, interface/entity)
asset_state(resource)
observability(observer, artifact/event)
opportunity(target, transition family)
```

Then an offensive or defensive action is simply a relation change.

### What it gets right

This is the strongest first-principles representation. It naturally expresses Red/Blue symmetry:

- acquire credential / revoke credential -> authority relation;
- lateral movement / isolate host -> control + reachability relation;
- install persistence / eradicate persistence -> continuity relation;
- exploit / patch or harden -> opportunity relation;
- stealth or sensor impairment / instrumentation -> observability relation;
- destructive effect / restore -> asset-state relation.

It also transfers cleanly from VMs to simulations and from binary malware to Agent systems.

### What breaks

It is too abstract to be the complete practical capability contract.

Two transitions can have the same semantic result but radically different preconditions, provider fidelity, exposure, reversibility, evidence, and cleanup. “Obtain execution” via valid credential, parser exploit, macro-induced user action, or prompt-injected tool use is not operationally interchangeable.

A pure graph would therefore make CA1/CA2 provider choice and Blue detection research artificially invisible.

**CA0 result:** use relation-state transition as the semantic spine, but do not expose it alone.

## Competing decomposition D — orthogonal capability contract

The retained candidate combines the strengths of the other three while refusing to turn any projection into the whole ontology.

### Axis A — semantic relation/effect

The current bounded candidate effect domains are:

```text
KNOWLEDGE
  acquire, validate, reduce, or deny decision-relevant evidence

CONTROL
  establish, transfer, restrict, or remove effective ability to cause effects

AUTHORITY
  acquire, delegate, escalate, restrict, or revoke identity/privilege/credential authority

CONTINUITY
  preserve or eradicate control across time, restart, owner loss, or disruption

REACHABILITY
  create, discover, expand, restrict, or remove paths between entities/interfaces

ASSET
  read, collect, copy, move, disclose, transform, corrupt, destroy, deny, or restore a resource/service

OBSERVABILITY
  increase, reduce, falsify, redirect, delay, or manipulate what another actor/sensor can observe or infer

OPPORTUNITY
  create, discover, validate, remove, or invalidate a condition enabling future transitions
```

These are **research coordinates, not a new public enum**. CA1-CA4 may merge or split them.

`COMMAND_AND_CONTROL` is intentionally not yet a ninth effect domain. It may reduce to a durable control relation plus reachability/communication. CA3 and CA6 should force a separate domain only if that reduction loses a measurable distinction.

### Axis B — mechanism

Mechanism answers how the transition is attempted. CA0 deliberately does not freeze a universal mechanism enum.

Current recurring families include using already-granted functionality, abusing trust or delegation, exploiting a weakness, inducing another principal to act, injecting/replacing/modifying an artifact, manipulating interpretation/protocol/input semantics, and delegated or replicated continuation.

CAPEC, MBC, capa, provider-native semantics, and later CA1/CA2 experiments remain better owners of fine mechanism vocabulary until repeated Agent consumers demand a shared subset.

### Axis C — carrier/substrate

Carrier answers through what medium the mechanism is realized. Examples include shell/script, document/macro, package/installer, native executable/library/driver, protocol/API/message, configuration/data, credential/token, firmware/hardware, and Agent prompt/tool-output/memory.

Carrier is normally provider metadata. It becomes Agent-visible only when it changes a decision-relevant property such as availability, authority source, policy gate, exposure, fidelity, latency, or cleanup.

### Axis D — control mode

Control mode is separate because classic malware and future Agents make it causally important:

```text
one-shot
controller-directed
persistent
locally delegated
self-propagating / autonomous continuation
```

CA3 must compare repeated controller-issued movement against delegated/self-propagating continuation before promoting richer semantics.

### Axis E — applicability and consequence properties

Every physical capability binding may need some subset of:

- exact preconditions/opportunity identity;
- target and topology scope;
- exact provider/tool/version/config/sample identity;
- required authority;
- expected and prohibited consequence families;
- cost, latency, resource consumption, and success uncertainty;
- exposure/detectability and emitted artifacts;
- reversibility, compensation, cleanup, and eradication requirements;
- fidelity and currentness/applicability boundary;
- native evidence plus independent post-condition evidence.

This is intentionally a contract shape, not a giant schema. CA5 may implement nothing if provider-specific adapters plus existing `RangeEffectRequest` already preserve these facts without repeated friction.

## Case falsifiers

The machine-readable case matrix is `research/ca0/classical-capability-cases.json`; the nine-criterion competing-model judgment is retained separately in `research/ca0/competing-model-assessment.json` so the research conclusion does not depend on prose alone. The following cases are the minimum conceptual stress set.

### PowerShell / shell script

A script can express the same host mutation as interactive commands. Execution policy, origin, interpreter identity, and logging change the carrier's exposure and admissibility but not necessarily the semantic effect.

A tool-tree describes this well; a tactic tree and pure state graph both hide useful carrier facts. The orthogonal contract keeps the semantic transition stable while retaining interpreter/provider/provenance evidence.

### Office macro / document-mediated execution

The document is both data and a hosted code carrier. Origin/provenance, trust policy, document opening, and application policy are preconditions. The macro can then realize many unrelated payload effects.

This falsifies “macro = attack capability” as a complete description.

### MSI / installer custom action

An installer is a sequenced execution carrier with a distinct authority and provenance context. It can create the same process/file/service effects as other carriers while producing different artifacts and policy gates.

The existing 目标产品B line is therefore evidence for one carrier/mechanism chain, not an MSI-centric attack ontology.

### Vulnerability discovery and exploitation

A scanner result, static finding, fuzzer crash, exploitability proof, provider execution, and verified target consequence are different states of knowledge and action.

CyberBattleSim makes this separation particularly clear because a vulnerability can be modeled as precondition + probability + outcome without any executable exploit implementation.

This supports CA2 as a capability-generation/opportunity-validation problem distinct from CA1 execution carriers.

### Valid credential versus exploit-based movement

Both may end with effective control of the same remote node. They differ in opportunity, mechanism, authority provenance, detection surface, revocation behavior, and likely cleanup.

A pure state graph collapses too much; a tactic tree collapses both under movement; a tool tree overfocuses implementation. The orthogonal contract retains the shared consequence and the distinct mechanism/preconditions.

### Persistence artifact versus persistent usable control

A service, task, file, registry entry, or startup item may survive reboot while the controller has no usable path back to it. Conversely, durable control might survive through external identity or orchestration without the same local artifact.

Therefore `CONTINUITY` is about effective control over a disruption boundary, not merely persistent bytes.

### Classical virus

Cohen's original structural insight is replication through attachment/infection of other programs. Payload semantics are independent.

Carrier/tool taxonomy can name the virus but cannot explain why the same semantic payload with no replication is strategically different. Control mode does.

### Network worm

The Morris-worm structure combines an opportunity/exploitation or trust mechanism with remote reach, local execution/control, copying/continuation, and repeated propagation.

“Worm” is therefore a composite behavioral architecture, not one atomic effect.

### Indirect prompt injection

InjecAgent and AgentDojo show untrusted external data influencing a tool-using Agent into issuing actions outside the user's intended task.

This looks new at the carrier layer (`prompt/tool result/data`) but old at the deeper layers: attacker-controlled input, induced-principal behavior, delegated victim authority, and downstream consequence.

A basis that requires “prompt injection” to become a new top-level world relation has failed to generalize.

### Self-replicating Agent prompt

Morris-II is the stronger transfer test. The carrier changes from binary/network code to adversarial text/RAG context, yet autonomous propagation and induced downstream action remain recognizable.

This supports keeping propagation/control mode independent of carrier.

### Zeek, Suricata, Sigma, YARA, capa, Velociraptor

These tools jointly falsify a generic `DETECT` primitive:

- Zeek can produce detailed network activity evidence without declaring maliciousness;
- Suricata can produce rule-match alerts tied to network events;
- Sigma describes portable detection logic over log events;
- YARA matches textual/binary patterns in artifacts;
- capa derives candidate executable capabilities from static or dynamic features;
- Velociraptor packages endpoint collection/DFIR operations and can also participate in higher-authority response workflows.

Thus:

```text
observation
!=
derived detection/classification
!=
world truth
!=
response action
```

CA4 should build an adaptive Blue plane out of these separable roles instead of creating one omniscient detector.

## Red/Blue symmetry candidate

CA0 finds substantial evidence that offensive and defensive actions can share a role-neutral transition grammar while differing in objective, authority, direction, and provider.

| Relation domain | Red-style transition | Blue-style transition |
| --- | --- | --- |
| opportunity | discover/create/consume exploit condition | patch/harden/remove condition |
| authority | acquire/elevate credential or privilege | revoke/restrict/rotate authority |
| control | establish foothold | contain/evict control |
| continuity | preserve foothold | eradicate persistence |
| reachability | expand path/movement | isolate/segment path |
| asset | collect/modify/deny | protect/restore/recover |
| observability | hide/impair/deceive | instrument/adjudicate/counter-deceive |
| knowledge | discover/infer | observe/investigate/adjudicate |

This is not yet a constitutional law. CA3 and CA4 must falsify it with physical identity, movement, propagation, detection, revocation, and restoration cases.

If the same relation grammar survives, Security should avoid separate Red and Blue primitive ontologies. Polarity belongs to adversarial objectives and authority, not to the physics of the world transition.

## What “capability” should mean to an Agent

The Agent should normally reason over a bounded projection such as:

```text
capability id / semantic effect
current applicability: AVAILABLE | UNAVAILABLE | UNKNOWN
known preconditions and evidence
allowed target/scope
material cost / latency / exposure
control mode
expected consequence family
important failure/cleanup properties
```

It should **not** need every command line, payload byte, parser detail, ATT&CK mapping, Sigma rule, sandbox record, or native provider field in ordinary deliberation.

Those exact native details remain available as evidence or lower-level provider controls when the consumer needs them.

The key Agent distinction is therefore:

```text
semantic choice surface
!=
physical/provider realization
```

This is analogous to the current Ordivon split between cognition and exact execution, but CA0 derives the split independently from classical cyber systems.

## Current Ordivon Security coverage against the basis

The current repository at CA0 opening revision `f76911743ac2bc86a985eab540f8626bd529fda6` is uneven in a useful way.

### Strong

- exact Range authority and typed effect admission;
- intent/admission/provider receipt/consequence separation;
- independent `world-truth`, fallible sensors, provenance, and `UNKNOWN`;
- actor-specific partial observation and autonomous deception/epistemic experiments;
- interruption, owner loss, successor recovery, idempotency/compensation falsifiers;
- physical isolated Windows + lightweight-peer topology and topology churn;
- CAGE/CybORG composition and model-backed Red/Blue actors.

### Moderate but narrow

- real Windows execution carriers through P1 execution media, installer-oriented apparatus, and the 目标产品B malicious nested-MSI research line;
- persistence and post-run disk evidence;
- reachability/topology change and a small set of CAGE action semantics;
- static sample analysis/quarantine evidence.

### Thin or absent as a reusable capability plane

- deliberate script versus document/macro versus package/loader carrier comparisons;
- target-specific vulnerability discovery/exploitability providers;
- explicit synthetic credential/identity resources and revocation semantics;
- lateral movement and propagation as reusable physical capabilities;
- classical Blue network/endpoint detection and response providers such as Zeek/Suricata/Sigma/YARA/Velociraptor-class systems;
- a proven provider-assimilation seam across materially different capability families;
- physical multi-capability tactical adaptation against an actively changing Blue opponent.

This explains the prior audit result precisely: Security is not “too defensive.” It is **semantically and experimentally mature but mechanically sparse in the classical capability plane**.

## What CA0 rejects

CA0 rejects these candidate world models:

1. **ATT&CK-as-core-ontology** — useful external coordinate, wrong owner and wrong abstraction boundary.
2. **tool/product tree as capability model** — conflates carrier, provider, mechanism, resource, sensor, and effect.
3. **malware type as payload semantics** — virus/worm-like distinctions often live in replication/control architecture.
4. **vulnerability as successful offensive capability** — opportunity, exploit attempt, and verified consequence are separate.
5. **generic DETECT as Blue truth** — telemetry, derived classification, adjudication, response, and truth are separate.
6. **pure state-transition graph as complete provider contract** — elegant but erases decision-relevant mechanism/carrier/evidence properties.
7. **atomic technique as an attack** — attack strategy lives above primitive actions and must handle dependency and counter-adaptation.
8. **separate Red/Blue physics by default** — first try a role-neutral transition grammar; split only when experiments prove a non-reducible difference.
9. **premature universal mechanism vocabulary** — retain source/provider-native mechanisms until CA1/CA2 force a stable shared subset.
10. **prebuilt RangeActionGateway** — CA0 establishes the information a capability binding may need, not that one shared gateway must exist.

## CA0 candidate basis

The smallest retained basis is therefore not a taxonomy tree. It is a layered coordinate system:

```text
Actor objective / opponent state / policy
                    │
                    ▼
         semantic relation transition
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   opportunity   mechanism   control mode
        │           │           │
        └───────────┼───────────┘
                    ▼
             carrier/substrate
                    ▼
            exact provider binding
                    ▼
       authority-bound physical action
                    ▼
 native evidence / sensors / detections
                    ▼
       independent verified consequence
                    ▼
       updated world + new Agent evidence
```

The stable claim is the **separation of these layers**, not the permanence of every current label inside them.

## Consequences for CA1-CA7

CA1 should vary **carrier/substrate** while holding semantic goals as constant as practical.

CA2 should vary **opportunity discovery, exploitability evidence, and mechanism provider** while keeping target revision and consequence truth exact.

CA3 should pressure **CONTROL / AUTHORITY / CONTINUITY / REACHABILITY** plus `controller-directed` versus `delegated/self-propagating` control modes.

CA4 should pressure **KNOWLEDGE / OBSERVABILITY / OPPORTUNITY / CONTROL** from the Blue side while keeping telemetry, detection, adjudication, response, and truth separate.

CA5 should implement only provider-binding semantics that recur across those consumers. It must not encode this entire CA0 coordinate system as a giant schema.

CA6 should finally test what is genuinely Agent-native: capability selection, sequencing, substitution, withdrawal, opponent adaptation, information acquisition, and resource/exposure tradeoffs against held-out counterplay.

CA7 remains gated. Campaign, organization, coevolution, and transfer become separate abstractions only if CA6 produces failures that ordinary trajectory + Host/Harness continuity + fresh world observation cannot explain.

## Stop condition

CA0 is complete when later work can begin without answering “what is a capability?” by naming a tool, tactic, malware family, or ATT&CK technique.

The retained falsifiable statement is:

> **A useful Agent-facing cyber capability is a conditional, authority-bound option for a semantic world-relation transition. Mechanism, carrier, provider, control mode, applicability, evidence, cost/exposure, and recovery properties remain orthogonal coordinates. An attack is a policy over such actions against an adaptive opponent, not the capability atom itself.**

CA1-CA4 are explicitly allowed to falsify, merge, or split the candidate relation domains. Nothing in CA0 authorizes a new production ontology or provider gateway.

## External evidence register

CA0 used only public primary/project-owner material for technical claims. Retrieval date: 2026-08-14.

- MITRE ATT&CK Enterprise tactics, techniques, data/tools, and April 2026 v19 update material.
- MITRE CAPEC 3.9, especially the Mechanisms of Attack view.
- MITRE CWE Introduction to Vulnerability Theory.
- MITRE D3FEND knowledge graph, artifacts, sensors, events, and defensive technique material.
- MITRE CALDERA project material and current release documentation.
- Center for Threat-Informed Defense Attack Flow 3.2 documentation.
- Microsoft CyberBattleSim project documentation.
- CybORG/CAGE project and challenge documentation.
- DARPA Cyber Grand Challenge and AI Cyber Challenge programme material.
- Malware Behavior Catalog and Mandiant/FLARE capa project/rule documentation.
- Red Canary Atomic Red Team documentation.
- Zeek, Suricata, SigmaHQ, YARA, and Velociraptor project documentation.
- Fred Cohen virus theory/experiments and Eugene Spafford's Morris-worm analysis.
- InjecAgent (ACL 2024), AgentDojo, and Morris-II primary research publications.
