# Agent-native strategic adversarial systems research agenda

## Purpose

This agenda defines what Ordivon Security should investigate before expanding
its implementation. It is deliberately framed as research questions,
comparisons, falsifiers, and experiment families rather than a feature roadmap.

## Foundational distinction

The project must separate four levels that are frequently conflated:

1. **classical mechanism** — sandbox, IAM, scanner, fuzzer, network policy,
   logging, patching, cyber range;
2. **automation** — a human-designed rule or workflow executes those mechanisms;
3. **adaptive policy** — a learned actor selects among a predefined action and
   observation space;
4. **adversarial agency** — a subject interprets strategic objectives, forms and
   revises Campaigns, models other subjects, constructs tools and organizations,
   manipulates information, and acts over an open horizon.

Ordivon Security is justified only where level 4 creates a real gap or where
levels 2–3 structurally fail under open-ended intelligent opposition.

## Track A — Contest and Campaign theory

### Questions

- What minimum structure distinguishes a Contest from a generic World or game?
- What distinguishes a Campaign from a workflow, plan, policy, episode, or
  collection of tasks?
- Which strategic variables must persist across individual missions and model or
  Host replacement?
- When should a Campaign change its means, phase, intermediate objective, or
  interpretation of the strategic objective?
- How should initiative, tempo, reserve, option value, exposure, and escalation
  be represented without importing a large military ontology?

### Baselines

- MITRE ATT&CK tactics/techniques/procedures;
- cyber kill-chain and threat-informed-defense models;
- DARPA CGC and AIxCC cyber reasoning systems;
- CybORG/CAGE and CyberBattleSim episodes;
- ordinary Agent planning and workflow graphs;
- POSGs and extensive-form games.

### Falsifiers

- a standard episode/trajectory plus ordinary memory expresses all required
  distinctions;
- a fixed finite-state or learned policy performs and adapts as well as the
  proposed Campaign system;
- strategic records do not improve transfer, diagnosis, or long-horizon
  continuity.

## Track B — opponent modelling and belief state

### Questions

- Which opponent properties matter: objectives, capability, knowledge, policy,
  risk preference, detection threshold, resource state, or organizational form?
- Should opponent models be explicit structured state, latent model state,
  natural-language hypotheses, or an ensemble of competing beliefs?
- How are observations attributed to chance, environment dynamics, friendly
  action, or adversary counterplay?
- How should uncertainty and mutually inconsistent hypotheses persist across
  context windows and actor handoffs?
- Can an Agent detect that an opponent is modelling it?

### Experiments

- held-out opponent policies;
- deliberate policy switches;
- identical world events produced by natural fault versus adversary action;
- false-flag observations and decoy systems;
- model/scaffold ablations with and without explicit opponent state.

### Falsifiers

- transcript context or recurrent policy state performs equivalently;
- explicit models increase overfitting to known opponents;
- the stored model becomes stale faster than it improves action.

## Track C — deception and counter-deception

### Questions

- How should the system distinguish world truth, actor observation, actor belief,
  communicated claim, intended belief effect, and verified deception?
- How do actors choose what to reveal, conceal, signal, fake, or sacrifice?
- Can defensive deception alter an attacker's resource allocation and tempo,
  rather than only trigger a detector?
- Can an actor reason about second-order beliefs: what the opponent believes the
  actor believes?
- When is deception tactically useful but strategically harmful because it
  exposes capability or destroys future trust?

### Baselines

- MITRE Engage and deception/denial practice;
- honeypots, honeytokens, decoys, sinkholes, and moving-target defense;
- prompt/context manipulation and Tool-output injection;
- signalling and Bayesian games;
- social-interaction environments such as Melting Pot.

### Falsifiers

- ordinary hidden state and event labels are sufficient;
- second-order belief modelling provides no measurable advantage;
- deception success cannot be independently distinguished from target failure or
  evaluator confusion.

## Track D — initiative, tempo, and strategic resources

### Questions

- How do we measure who forces whom to react?
- What is the Agent equivalent of operational tempo when actions have different
  latency, compute, visibility, and reversibility?
- How should Agents allocate compute, tokens, tools, credentials, footholds,
  secrecy, human attention, and other Agents?
- When should an actor preserve a capability rather than use it?
- How should withdrawal, concealment, escalation, and deliberate inactivity be
  evaluated?

### Experiments

- changing mission priority and action duration;
- limited budget with multiple attack or defense opportunities;
- capability exposure that enables future countermeasures;
- short-term reward versus long-term option value;
- asymmetric cost structures and delayed consequences.

### Falsifiers

- cumulative reward and task completion capture the same ordering;
- proposed metrics are not robust across worlds;
- resource records predict no change in strategy.

## Track E — multi-Agent adversarial organization

### Questions

- When does specialization outperform a single strong Agent?
- Which organization forms work under partial observability and unreliable
  communication: centralized, hierarchical, market-like, federated, or swarm?
- What information should be shared, delayed, summarized, compartmentalized, or
  withheld?
- How is authority delegated when a subordinate may be compromised, deceptive,
  self-interested, or simply wrong?
- How do we distinguish useful coordination, emergent protocol, collusion, and
  command failure?
- Can organizations reorganize under actor loss, communication partition, or
  opponent infiltration?

### Experiments

- specialist Red/Blue teams versus monolithic actors;
- compromised or Byzantine team members;
- limited-bandwidth and covert communication;
- conflicting local rewards and shared strategic objectives;
- command replacement and organization restructuring during a Campaign.

### Falsifiers

- multi-Agent structures add only token and coordination overhead;
- ordinary Host branch/join semantics fully explain the relevant behavior;
- organization labels do not improve prediction or recovery.

## Track F — attack-defense coevolution

### Questions

- How should repeated encounters update policy, tools, deception, organization,
  and world design?
- How can we distinguish genuine adaptation from memorization of one opponent?
- What equilibrium, cycling, escalation, or collapse patterns appear?
- When does one side's improvement merely exploit a static evaluator?
- How does capability transfer across unseen opponents and world families?

### Experiments

- repeated tournaments with hidden held-out opponents;
- population-based opponent pools;
- attacker/defender tool mutation;
- alternating best-response and simultaneous adaptation;
- cross-world and cross-budget transfer.

### Falsifiers

- performance disappears against held-out opponents;
- repeated play produces only overfitting or unstable cycles;
- no useful knowledge can be transferred to Host, Game, or domain systems.

## Track G — adversarial evaluation

### Questions

- Which parts of the evaluator are visible to each actor?
- How can task success, run validity, strategic outcome, information outcome, and
  evaluator integrity remain separate?
- How should hidden state and independent world truth be preserved?
- How do we detect reward hacking, answer lookup, judge manipulation, evidence
  tampering, and simulated compliance?
- Can a monitor that improves with model capability remain robust against an
  actor that also improves?
- How should variance over model sampling, opponent policy, world seed, budget,
  and organization be aggregated?

### Baselines

- Inspect AI and Inspect Cyber;
- ControlArena honest/attack modes, policies, monitors, and protocols;
- repeated-trial evaluation and hidden scoring;
- CybORG/CAGE rewards and world truth;
- Game replay and counterfactual evaluation.

### Falsifiers

- the proposed evaluator cannot detect a synthetic gaming case;
- rankings change arbitrarily under minor judge changes;
- strategic metrics cannot be grounded in authoritative world state;
- complexity exceeds diagnostic value.

## Track H — cross-domain transfer

Cyber is the first domain. Later research should ask whether the same concepts
survive in:

- adversarial software supply chains;
- multi-Agent service ecosystems;
- information and influence environments;
- economic and market simulations;
- games with hidden roles, alliances, and betrayal;
- robotic or distributed physical systems.

A concept that works only for one cyber simulator may belong in a scenario
adapter rather than the Security core.

## Research method

Every track should produce:

1. a primary-source comparison;
2. competing formal and informal models;
3. a minimal experiment using mature substrates;
4. at least one static/scripted baseline;
5. held-out opponents or social situations;
6. exact resource and information conditions;
7. negative and null results;
8. an abstraction deletion decision;
9. cross-project implications, filed only in the repository that naturally owns
   the required change.

No track is required to produce new production code.
