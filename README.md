# Ordivon Security

**Agent-native strategic adversarial systems.**

Ordivon Security studies and constructs intelligent actors that pursue strategic
objectives against adaptive opposition in long-horizon, partially observed,
dynamically changing digital environments.

It is not Ordivon's guardrail, compliance, vulnerability-scanning, IAM, sandbox,
SIEM, or incident-response repository. Those are mature classical capabilities
to compose. The project begins where classical automation becomes insufficient:
when attackers, defenders, observers, judges, tools, and other Agents can reason
about one another, conceal intent, manipulate information, change strategy, and
continue a Campaign across time.

```text
Host      gives an Agent cognition and continuity
Runtime   turns decisions into trusted-local effects
World     binds external relationships, providers, actions, evidence, and recovery
Game      supplies general worlds and interaction mechanics
Security  studies how goal-conflicting actors contest information,
          resources, initiative, access, and world state
```

## Core question

> What changes when an intelligent opponent is not a fault in the environment,
> but another adaptive subject actively shaping what an Agent sees, believes,
> does, and learns?

The project's target is not merely automated exploitation or automated defense.
It is **adversarial autonomy**:

- autonomous Campaign formation from strategic objectives;
- opponent modelling under incomplete and manipulated observations;
- deception, counter-deception, reconnaissance, and counter-intelligence;
- offensive and defensive adaptation against active counterplay;
- initiative, tempo, escalation, withdrawal, and strategic resource allocation;
- multi-Agent command, delegation, coordination, collusion, and internal trust;
- adversarial evaluation where monitors and judges may themselves be studied or
  manipulated by evaluated actors;
- attack-defense coevolution across repeated encounters.

Cyber operations are the first experimental domain because they are digital,
replayable, tool-rich, measurable, and compatible with owned isolated ranges.
They are not the final theoretical boundary.

## Layering

```text
Strategic adversarial plane
  objectives · victory conditions · opponent models · initiative · deception
  resource allocation · escalation · withdrawal · alliances

Operational Campaign plane
  Campaign synthesis · phases · intelligence cycle · mission graph
  adaptation history · multi-Agent organization · long-term continuity

Tactical Agent plane
  reconnaissance · analysis · exploitation · detection · repair · restoration
  tool construction · action selection · feedback interpretation

Classical capability plane
  ATT&CK/D3FEND knowledge · scanners · fuzzers · sandboxes · IAM · EDR
  network controls · forensics · patching · mature cyber ranges

Contested world plane
  services · hosts · code · identities · networks · data · tools · Agents
```

Ordivon Security primarily researches the top two planes. It composes rather
than reimplements the lower planes.

## Research vocabulary, not frozen protocol

The current leading vocabulary is:

- **Actor** — a goal-bearing participant with knowledge, beliefs, resources,
  capabilities, organizational relations, and a decision process;
- **Contest** — the conflict structure joining actors, asymmetric information,
  resources, rules, world state, and victory or exit conditions;
- **Campaign** — one actor's or coalition's long-horizon organized attempt to
  change the Contest in service of strategic objectives;
- **Mission / Operation / Action** — progressively narrower units below a
  Campaign;
- **World state** — authoritative physical or digital state;
- **Observation** — what an actor can perceive;
- **Belief state** — what an actor currently believes about the world and other
  actors;
- **Information position** — who knows, believes, or can credibly infer what;
- **Strategic outcome** — change in objectives, initiative, resources,
  information advantage, exposed capability, and future option space.

These are research hypotheses. They must not become a large internal ontology or
new protocol until experiments show that mature frameworks and simpler records
cannot express the required distinctions.

## Current implementation status

The repository already contains an executable experimental-support substrate:

1. Campaign Manifest v0 with capability/consequence separation and exact
   cross-project bindings;
2. an append-only lifecycle ledger, reconciliation, residual classification,
   evidence export, and replay;
3. a historical live infrastructure-only Link/Edge/Runtime composition whose implementation carriers now live inside Ordivon World.

This work proves that an owned experimental world can be admitted, observed,
closed, reconstructed, and verified. It does **not** prove adversarial agency,
strategic planning, opponent modelling, deception, dynamic Red/Blue behavior,
attack capability, defense capability, or coevolution.

The current contracts are therefore retained as a **frozen research substrate**,
not treated as the final architecture or the main roadmap. New lifecycle,
identity, evidence, or coordination abstractions require a concrete adversarial
experiment that cannot be expressed by mature existing systems or the current
minimal substrate.

No Red/Blue Agent, exploit implementation, public target, or executable attack
system currently exists in this repository.

## Route

The route is research-first and experiment-driven:

1. map classical offense, defense, deception, cyber reasoning, autonomous cyber
   ranges, AI control, game theory, opponent modelling, and multi-Agent systems;
2. identify which gaps are genuinely caused by adaptive intelligent opposition;
3. define falsifiable models for Contest, Campaign, belief, deception,
   initiative, organization, and strategic outcome;
4. run small dynamic-opponent experiments on mature simulated substrates before
   expanding Ordivon infrastructure;
5. compare scripted automation, learned policies, LLM Agents, and mixed teams;
6. promote only abstractions that explain or enable results unavailable from
   simpler baselines;
7. move proven responsibilities to Host, Runtime, World, or Game rather than centralizing them in Security.

See:

- [`CHARTER.md`](CHARTER.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/research-agenda.md`](docs/research-agenda.md)
- [`docs/classical-to-agent-adversarial-map.md`](docs/classical-to-agent-adversarial-map.md)
- [`docs/capability-gaps.md`](docs/capability-gaps.md)
- [`docs/research-boundary.md`](docs/research-boundary.md)

## Existing substrate validation

The frozen support substrate remains tested:

```bash
python3 scripts/validate_campaign.py \
  fixtures/campaigns/valid/minimal-owned-range.json
python3 -m unittest discover -v
```

Its validation proves contract and evidence behavior only. Passing these tests
must not be reported as progress in strategic adversarial autonomy.
