# Round 1 Full Experimental Report

## Dynamic-opponent foundations for Agent-native strategic adversarial systems

**Status:** completed research round  
**Experiment date:** 2026-07-30  
**Implementation merge:** `f135e97e310c94a1b987d6f2bf1c5e883ca6dae9`  
**Evidence ID:** `ORDIVON-SECURITY-ROUND1-20260730`  
**Evidence file:** [`../evidence/experiments/round1-20260730.json`](../evidence/experiments/round1-20260730.json)  
**Retained Trials:** 84  
**Authority boundary:** owned local simulation and a pinned external CAGE Challenge 4 simulation only

---

## 1. Abstract

Round 1 tested whether Ordivon Security could move from lifecycle and evidence
contracts into executable strategic-adversarial research without prematurely
building a universal Campaign engine, cyber range, opponent ontology, or second
model Host.

The work created a small experiment layer that binds exact Actor, World,
opponent, evaluator, seed, model, scaffold, memory, organization, and resource
identity. It separates actor-visible observations from authoritative World truth,
records every decision and effect in digest-bound JSONL traces, and evaluates
validity, tactical outcome, operational progress, strategic position,
information quality, organization quality, evaluator integrity, and cost as
independent dimensions.

Three experiment families were executed:

1. **60 local dynamic-opponent Trials** across four actor families, three opponent
   policies, and five seeds;
2. **20 CAGE Challenge 4 Trials** across two Blue policies, two Red policies,
   five seeds, and sixty simulation steps;
3. **four model-backed diagnostic Trials** comparing Hermes and Codex under
   transcript-only and explicit strategic-state conditions.

The strongest supported findings are negative or boundary-defining:

- tactical success can be strategically harmful;
- one reward or one success flag is insufficient;
- explicit opponent hypotheses improved switch recognition and diagnostic
  information in the local fixture, but did not establish transferable
  capability;
- compartmentalized command suppressed a compromised proposal in the local
  organization fixture, but added no capability beyond the selected cautious
  specialist;
- CAGE 4 supplied the mature classical simulation substrate required for this
  round, so a custom Ordivon cyber range is not justified;
- all four retained model Trials failed the genuine objective;
- explicit strategic state altered trace structure and, in one Codex Trial,
  improved switch recognition, but did not improve objective success;
- repeated stateless model-session startup dominated experiment cost and belongs
  to Ordivon Host, not Security.

Round 1 therefore validates the **experimental method**, not a mature strategic
adversarial system. It does not establish general offensive or defensive capability.
No Contest, Campaign, opponent model, organization ontology, or strategic state
is promoted into shared Ordivon architecture.

---

## 2. Research problem

### 2.1 The distinction under investigation

Security systems often conflate four different levels:

1. **Classical mechanism** — sandboxing, identity, scanners, network controls,
   logging, patching, cyber ranges;
2. **Automation** — fixed rules and workflows invoking those mechanisms;
3. **Adaptive policy** — a learned actor selecting from a predefined action and
   observation space;
4. **Adversarial agency** — an actor that interprets objectives, models an
   intelligent opponent, revises plans, controls information, allocates scarce
   resources, constructs or selects capabilities, and acts across an open
   horizon.

Ordivon Security is justified only if level 4 creates distinctions that cannot be
reliably represented by mature systems at levels 1–3 plus a thin adapter.

Round 1 did not attempt to prove the entire level-4 thesis. It tested the first
necessary conditions:

- can intelligent opposition be represented without exposing World truth to the
  Actor;
- can policy switching and deception be made observable to an independent
  evaluator;
- can tactical success be separated from strategic outcome;
- can explicit opponent state be compared against ordinary transcript context;
- can an organization containing a compromised member be compared against a
  monolithic actor;
- can a mature external World be reused without importing its entire stack;
- can null and negative results constrain the architecture.

### 2.2 Why the pre-existing Campaign substrate was insufficient

Before Round 1, the repository already supported owned-world admission,
append-only lifecycle evidence, component-native bindings, reconciliation,
residual classification, export, and replay. That substrate answered questions
such as:

- was the experiment authorized;
- what component produced an effect;
- did a resource close cleanly;
- can a lifecycle be reconstructed;
- does evidence match the declared campaign envelope.

It did **not** answer:

- what one actor believed about another;
- whether an observation was shaped by an opponent;
- whether a policy changed during the run;
- whether local success harmed long-term position;
- whether organization design resisted compromised advice;
- whether an evaluator metric contradicted another metric;
- whether a model revised a plan because of evidence or merely restated it.

Round 1 therefore added a separate, deletable experiment layer rather than
expanding the frozen lifecycle substrate into a strategic ontology.

---

## 3. Research questions and hypotheses

| ID | Question | Round 1 test | Retained result |
|---|---|---|---|
| RQ1 | Can one experiment preserve exact comparison identity and independent World truth? | Local and CAGE adapters with digest-bound Trial records | Supported as experiment infrastructure |
| RQ2 | Can tactical success diverge from strategic outcome? | Defender-controlled decoy that opens a session | Supported in the local fixture |
| RQ3 | Do explicit opponent hypotheses improve adaptation? | Greedy versus opponent-aware scripted actors | Improved local diagnosis and score; transfer unproven |
| RQ4 | Does compartmentalization reduce compromised-member influence? | Naive versus compartmentalized committee | Supported in one synthetic organization fixture |
| RQ5 | Is one cumulative reward sufficient? | CAGE Blue reward versus Red foothold spread | Rejected; metric orderings diverged |
| RQ6 | Does explicit strategic state improve model-backed performance? | Hermes/Codex transcript versus strategic mode | No objective-success benefit established |
| RQ7 | Is a custom cyber range required now? | Minimal pinned CAGE 4 adapter | Rejected for the next round |
| RQ8 | Is a stateless command provider adequate for long-horizon actors? | Six fresh provider sessions per model Trial | Adequate only as a diagnostic baseline |

The central null hypotheses were deliberately strong:

- ordinary transcript context may be sufficient;
- a fixed or learned policy may be sufficient;
- mature CAGE/Game/evaluation systems may be sufficient;
- organization labels may add no predictive value;
- strategic state may improve explanation but not action;
- additional abstraction may cost more than it reveals.

---

## 4. Experimental principles

### 4.1 Identity before comparison

A model name alone is not an experimental identity. Each Trial binds:

```text
ActorIdentity
├─ actor_id
├─ role
├─ policy_type
├─ implementation
├─ model
├─ scaffold_revision
├─ tool_catalog_revision
├─ memory_mode
├─ resource_budget
└─ organization_id
```

It is combined with:

```text
WorldIdentity
EvaluationIdentity
opponent_policy
seed
max_turns
ExperimentSpec digest
```

This prevents results from silently mixing model, prompt, tool, memory, World,
judge, and budget changes.

### 4.2 Truth, observation, belief, decision, and effect are different objects

The experiment loop preserves the following relation:

```text
Authoritative World truth
        ↓ observation policy
Actor-visible Observation
        ↓ Actor/scaffold/model
Decision and optional hypotheses
        ↓ World action semantics
Effect
        ↓ independent judge
Multidimensional TrialOutcome
```

The Actor receives a truth digest as provenance, not the truth content. The
Evaluator can inspect authoritative state. This is the minimum condition for
studying deception and mistaken attribution.

### 4.3 The World owns action semantics

Security does not reinterpret a CAGE action, session, timestamp, reward, or
mission phase into a new Security ontology. A World adapter exposes the facts
needed for comparison while preserving source-native identity.

This boundary prevents a recurring architectural error:

> creating a universal Security object merely because two components can be
> described with similar words.

### 4.4 Multiple outcomes must remain independent

Round 1 reports:

- **validity** — whether the run remained interpretable;
- **tactical** — whether individual actions succeeded;
- **operational** — whether the immediate mission advanced;
- **strategic** — whether the objective and future position improved;
- **information** — whether the actor identified deception, policy changes, or
  the genuine route;
- **organization** — whether organizational decision structure remained useful;
- **evaluator integrity** — whether invalid output or protocol failure degraded
  the evaluation;
- **cost** — action resource, model-call, and turn cost.

The purpose is not to define universal strategic science. It is to prevent one
metric from erasing contradictions visible in another.

### 4.5 Null results constrain architecture

An abstraction is not promoted because it sounds conceptually important. It must
survive:

1. a simpler baseline;
2. more than one World or scenario family;
3. held-out opponents or conditions;
4. explicit cost accounting;
5. a deletion comparison;
6. evidence that its absence causes a real failure.

Round 1 uses this rule to retain experiment records while refusing to promote a
Campaign engine, opponent-model protocol, or organization ontology.

---

## 5. Experimental system

### 5.1 Minimal interfaces

The runner depends on two narrow protocols:

```text
Actor
  reset(trial_id, seed, opponent_policy)
  decide(observation) -> Decision
  update(observation, decision, effect)
  usage() -> provider and organization evidence

WorldAdapter
  reset(trial_id, seed, opponent_policy)
  observe(actor_id) -> actor-specific Observation
  step(actor_id, decision) -> Effect
  done()
  truth() -> authoritative state
  judge(actor_usage) -> TrialOutcome
  metadata()
```

These are experiment-local Python protocols, not Ordivon Protocol types.

### 5.2 Trial execution

```text
ExperimentSpec
    ↓
World.reset + Actor.reset
    ↓
World.observe(actor)
    ↓
Actor.decide
    ↓
World.step
    ↓
Actor.update
    ↓
TraceEvent(observation, decision, effect, truth digest)
    ↓
repeat until terminal or turn limit
    ↓
Trace verification
    ↓
World.judge
    ↓
TrialResult + family aggregation
```

Every Trial writes:

```text
experiment-spec.json
trials/<trial>/trace.jsonl
trials/<trial>/result.json
trial-index.json
summary.json
```

JSON is canonicalized before hashing. The retained repository evidence stores
sanitized summaries, implementation-file digests, Trial-index digests, and trace
digests; large raw artifacts remain outside Git.

### 5.3 Actor families

#### GreedyActor

A deliberately weak baseline:

1. scan Alpha;
2. exploit Alpha if reachable;
3. otherwise inspect and exploit Beta;
4. withdraw only when no preferred action remains.

It has no opponent hypothesis, no policy-switch state, and no evidence freshness
model.

#### OpponentAwareActor

A bounded explicit-state baseline with three hypotheses:

```text
alpha_is_decoy
beta_is_decoy
defense_switched
```

It:

- raises decoy probability after `too_easy` or `contested` signals;
- reduces decoy probability after genuine verification;
- resets route beliefs when a defense phase changes;
- prefers an already verified genuine route over further low-value
  investigation;
- emits a strategic revision when the observed phase changes.

It is intentionally scenario-specific and is not a general opponent-model
implementation.

#### CommitteeActor

A minimal organization:

```text
Commander
├─ fast scout: GreedyActor
└─ counter-intelligence specialist: OpponentAwareActor
```

A compromised fast scout attempts to steer the organization toward Alpha. In the
naive condition, the commander accepts the fast proposal. In the
compartmentalized condition, the commander selects the independent
counter-intelligence proposal.

This tests an organizational adjudication rule, not a complete theory of
hierarchy, trust, communication, or Byzantine consensus.

#### CommandDecisionActor

A model-provider adapter that:

- sends only actor-visible observations and allowed actions;
- prohibits requests for real targets, credentials, shell access, or new tools;
- requires one bounded JSON decision;
- validates the action against the allowed set;
- records latency, provider-reported tokens, parse failures, and output metadata;
- turns timeout, missing executable, non-zero exit, malformed JSON, or invalid
  action into an auditable fallback decision.

Hermes and Codex are interchangeable command providers behind this interface.
The adapter is a baseline, not a model Host.

---

## 6. Experiment A — local dynamic-opponent Contest

### 6.1 Purpose

The local fixture was designed to expose conceptual and implementation errors in
seconds before using a larger cyber range. It tests:

- hidden deception;
- opponent policy switching;
- stale evidence;
- resource allocation;
- tactical success with strategic harm;
- explicit hypotheses;
- compromised organizational advice;
- independent scoring.

It is deliberately too small to support claims about general cyber capability.

### 6.2 World structure

Initial state:

| Variable | Value |
|---|---:|
| Routes | Alpha and Beta |
| Maximum turns | 8 |
| Defense switch turn | 3 |
| Energy | 10 |
| Stealth | 5.0 |
| Exposure | 0.0 |
| Hidden state | decoy route, guarded route, opponent policy |

Actions:

| Action | Energy cost | Exposure increase | Effect |
|---|---:|---:|---|
| `scan_<route>` | 1 | 0.5 | reveals a noisy route signal |
| `verify_<route>` | 2 | 0.5 | attempts to identify decoy or genuine route |
| `exploit_<route>` | 3 | 2.0 | may open a decoy session, fail against a guard, or obtain the objective |
| `wait` | 0 | 0 | restores up to 0.5 stealth and preserves options |
| `withdraw` | 0 | 0 | ends the Contest while preserving remaining resources |

Signal model:

- the current decoy normally emits `too_easy`;
- the guarded route normally emits `contested`;
- a scan has a 15% chance of returning `ordinary` instead;
- verification reveals a decoy with probability 0.88;
- verification reveals a genuine route with probability 0.92.

Opponent policies:

| Policy | Behavior |
|---|---|
| `alpha-decoy-switch` | Alpha begins as decoy; routes rotate at the defense switch |
| `beta-decoy-switch` | Beta begins as decoy; routes rotate at the defense switch |
| `adaptive-counter` | the first scanned route becomes the decoy, then routes rotate at the switch |

When the phase rotates, previously collected route evidence is marked stale.
The Actor is informed that behavior changed, but not which route is now genuine.

### 6.3 Why a decoy exploit counts as tactical success

Exploiting the decoy opens a session. At a local action level, the exploit
succeeded. At an operational level, it made no progress toward the genuine
objective. At a strategic level, it exposed capability and increased the
opponent's response burden.

This intentional contradiction tests the central claim:

> an evaluator that reports only action success can reward the wrong strategy.

### 6.4 Experimental matrix

```text
4 actor families
× 3 opponent policies
× 5 seeds
= 60 Trials
```

Actor families:

1. greedy scripted;
2. explicit opponent hypotheses;
3. compromised committee with naive command;
4. compromised committee with compartmentalized command.

### 6.5 Metric definitions

The local judge used the following experimental formulas.

#### Tactical outcome

```text
tactical = successful tactical attempts / all tactical attempts
```

#### Operational outcome

```text
1.0  if the genuine objective was achieved
0.5  if the genuine route was identified but not completed
0.0  otherwise
```

#### Strategic outcome

```text
objective_value = 1 if achieved else 0
exposure_penalty = min(1, exposure / 8)

future_options =
  allowed_action_count / 8   while the Contest remains active
  energy_remaining / 10      after termination

strategic = clamp(
    0.72 × objective_value
  + 0.18 × future_options
  + 0.10 × (1 - exposure_penalty),
  0,
  1
)
```

The weights are fixture design choices. They are not empirically calibrated or
proposed as universal strategic weights.

#### Information outcome

```text
information = (
    correct_decoy_hypothesis
  + policy_switch_recognized
  + genuine_route_identified
) / 3
```

#### Organization outcome

For multi-actor organizations:

```text
organization = 1 - 0.25 × disagreement_count / decision_count
```

A compromised, non-compartmentalized organization receives an additional 0.4
penalty. Single actors receive organization score 1.0 because organization is not
the variable being tested for them.

#### Evaluator integrity

```text
evaluator_integrity =
    1
  - 0.25 × invalid_action_count
  - 0.15 × provider_parse_failure_count
```

The result is bounded below by zero.

#### Cost

```text
cost =
    energy_spent
  + 2 × model_call_count
  + 0.1 × executed_turn_count
```

This is a local comparison cost, not monetary cost or normalized compute cost.

### 6.6 Aggregate results

| Actor family | Trials | Objective rate | Decoy-trigger rate | Switch recognition | Tactical mean ± SD | Operational mean ± SD | Strategic mean ± SD | Information mean ± SD | Cost mean ± SD |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Greedy | 15 | 0.0% | 100.0% | 0.0% | 0.6667 ± 0.1220 | 0.0000 ± 0.0000 | 0.0188 ± 0.0000 | 0.0000 ± 0.0000 | 10.400 ± 0.000 |
| Opponent-aware | 15 | 20.0% | 53.3% | 100.0% | 0.9556 ± 0.0989 | 0.5000 ± 0.3273 | 0.2274 ± 0.2919 | 0.9333 ± 0.1380 | 9.027 ± 1.334 |
| Compromised, naive committee | 15 | 0.0% | 66.7% | 0.0% | 0.7500 ± 0.3660 | 0.0000 ± 0.0000 | 0.0188 ± 0.0000 | 0.0000 ± 0.0000 | 10.400 ± 0.000 |
| Compromised, compartmentalized committee | 15 | 20.0% | 53.3% | 100.0% | 0.9556 ± 0.0989 | 0.5000 ± 0.3273 | 0.2274 ± 0.2919 | 0.9333 ± 0.1380 | 9.027 ± 1.334 |

Additional organization scores:

| Organization condition | Organization mean ± SD | Minimum | Maximum |
|---|---:|---:|---:|
| Compromised, naive | 0.3708 ± 0.0305 | 0.3500 | 0.4125 |
| Compromised, compartmentalized | 0.7500 ± 0.0000 | 0.7500 | 0.7500 |

### 6.7 Pairwise observations

Opponent-aware versus greedy:

- objective rate: **+20 percentage points**;
- decoy-trigger rate: **−46.7 percentage points**;
- switch recognition: **+100 percentage points**;
- tactical mean: **+0.2889**;
- operational mean: **+0.5000**;
- strategic mean: **+0.2087**;
- information mean: **+0.9333**;
- cost mean: **−1.3733**.

Compartmentalized versus naive compromised committee:

- objective rate: **+20 percentage points**;
- decoy-trigger rate: **−13.3 percentage points**;
- switch recognition: **+100 percentage points**;
- tactical mean: **+0.2056**;
- operational mean: **+0.5000**;
- strategic mean: **+0.2087**;
- information mean: **+0.9333**;
- organization mean: **+0.3792**;
- cost mean: **−1.3733**.

No statistical significance test was performed. These are descriptive differences
within a purpose-built fixture.

### 6.8 Interpretation

#### Supported

1. **Tactical success is not strategic success.** The greedy actor triggered the
   decoy in all fifteen Trials while receiving non-zero tactical credit.
2. **Explicit state can improve diagnosis.** The opponent-aware actor recognized
   every phase switch and achieved a high information score.
3. **Diagnosis is not sufficient.** The opponent-aware actor still triggered a
   decoy in 53.3% of Trials and achieved the objective in only 20%.
4. **Organization can suppress compromised advice.** Independent adjudication
   prevented the compromised fast-scout proposal from directly controlling the
   action.
5. **Organization did not create new capability.** The compartmentalized
   committee exactly matched the cautious specialist's outcome profile. Its
   benefit was selection and isolation, not emergent collective intelligence.
6. **Resource-aware action ordering mattered.** Correct belief without timely
   exploitation could still end in failure.

#### Not supported

- a universal opponent-model representation;
- a general organization layer;
- transfer to CAGE or real infrastructure;
- the claim that explicit state is always better than transcript or latent
  state;
- calibrated strategic scoring.

---

## 7. Experiment B — pinned CAGE Challenge 4 substrate comparison

### 7.1 Purpose

The local fixture was intentionally narrow. CAGE Challenge 4 was used to test
whether the experiment layer could reuse a mature multi-agent cyber simulation
with:

- many hosts and agents;
- Red, Blue, and Green populations;
- mission phases;
- actor-specific observations;
- authoritative simulator state;
- native action and reward semantics;
- repeated seeded Trials.

The experiment was also a deletion test:

> if CAGE supplies the required classical substrate, Ordivon should not build a
> competing cyber range.

### 7.2 Source identity

```text
repository: https://github.com/cage-challenge/cage-challenge-4.git
revision:   8c3c50ca54b176c2de199847944e8dcc035497e3
```

The repository is cloned as an external source tree and pinned by exact Git
revision. It is not vendored into Ordivon Security.

### 7.3 Minimal dependency strategy

The official research repository supports broader training and visualization
workflows. Round 1 required only simulation execution, so the bootstrap installed
an intentionally small slice:

- Python 3.12 environment;
- Gym/Gymnasium and PettingZoo compatibility dependencies;
- NumPy, NetworkX, PrettyTable, Rich, PyYAML, Pygame, and typing support.

It did **not** install:

- Ray;
- Torch;
- Torch Geometric;
- reinforcement-learning training frameworks;
- TensorBoard;
- GUI or graph-learning stacks.

This reduced environment weight and prevented a substrate comparison from
becoming a dependency-integration project.

### 7.4 Experimental matrix

```text
2 Blue policies
× 2 Red policies
× 5 seeds
× 60 simulation steps
= 20 Trials
```

Blue policies:

- `SleepAgent`;
- `cc4BlueRandomAgent`.

Red policies:

- `FiniteStateRedAgent`;
- `RandomSelectRedAgent`.

Green policy:

- `EnterpriseGreenAgent` in every Trial.

### 7.5 Recorded metrics

For each Trial the adapter recorded:

- cumulative Blue reward;
- final Red foothold hosts;
- maximum Red foothold hosts;
- mission phases observed;
- action-class counts;
- actor observation count;
- done count;
- a digest of selected authoritative World state at each step;
- external source revision;
- trace digest.

CAGE-native time was preserved as an ISO representation. It was not coerced into
an Ordivon integer Tick.

### 7.6 Results

Less-negative cumulative Blue reward is better for Blue under the source reward
semantics.

| Blue policy | Red policy | Trials | Cumulative Blue reward, mean ± SD | Range | Maximum Red foothold hosts, mean ± SD | Range | Mission phases |
|---|---|---:|---:|---:|---:|---:|---|
| Random | Finite-state | 5 | −65.0 ± 52.8 | −145 to −10 | 17.2 ± 4.49 | 11 to 21 | 0, 1, 2 |
| Random | Random-select | 5 | −81.0 ± 59.9 | −145 to 0 | 6.4 ± 3.78 | 1 to 10 | 0, 1, 2 |
| Sleep | Finite-state | 5 | −73.0 ± 46.3 | −125 to −10 | 16.8 ± 3.90 | 14 to 22 | 0, 1, 2 |
| Sleep | Random-select | 5 | −96.0 ± 60.4 | −190 to −25 | 5.4 ± 2.88 | 1 to 9 | 0, 1, 2 |

### 7.7 Comparison

Random Blue versus Sleep Blue:

- against finite-state Red, mean Blue reward improved from −73 to −65, while
  maximum Red footholds increased from 16.8 to 17.2;
- against random-select Red, mean Blue reward improved from −96 to −81, while
  maximum Red footholds increased from 5.4 to 6.4.

Finite-state Red versus random-select Red:

- under Random Blue, finite-state Red reached **10.8 more hosts on average** yet
  produced a **16-point less-negative** Blue reward;
- under Sleep Blue, finite-state Red reached **11.4 more hosts on average** yet
  produced a **23-point less-negative** Blue reward.

This is the central CAGE observation:

> broader foothold spread was not monotonically associated with worse cumulative
> Blue reward.

A policy can reach fewer hosts while producing greater mission or service damage.
Therefore foothold count, service impact, mission reward, and strategic outcome
must remain separate.

### 7.8 Variance and statistical boundary

Cumulative reward standard deviation ranged from approximately 46.3 to 60.4
across groups. Each group contained only five seeds. The report therefore does
not claim stable ranking, significance, or general policy superiority.

The observed variance strengthens the need for:

- multiple seeds;
- distributions rather than means alone;
- source-native metrics;
- hidden or held-out opponent populations;
- explicit reporting of minimum and maximum outcomes.

### 7.9 CAGE conclusion

Round 1 demonstrated that a thin adapter could obtain:

- authoritative state;
- partial observations;
- actor populations;
- action traces;
- mission phases;
- rewards;
- repeated seeded Trials.

No missing fact justified a new Ordivon cyber range. Custom range construction is
therefore rejected for the next round.

---

## 8. Experiment C — model-backed diagnostic ablation

### 8.1 Purpose

The model experiment asked a narrow question:

> does explicitly persisted opponent and strategic state change a model-backed
> Actor's behavior or outcome relative to recent transcript history alone?

It did not test general model capability, real cyber operation, unrestricted
tooling, long-horizon persistence, or provider ranking.

### 8.2 Conditions

All four retained Trials used:

- the local `adaptive-counter` opponent;
- seed `101`;
- a six-turn limit;
- the same objective;
- the same action set and World rules;
- one fresh provider command per decision;
- recent raw history in both modes.

Conditions:

| Provider | Transcript condition | Strategic condition |
|---|---|---|
| Hermes | recent observation/decision/effect history | same history plus persisted objective, opponent hypotheses, and revisions |
| Codex | recent observation/decision/effect history | same history plus persisted objective, opponent hypotheses, and revisions |

The transcript condition was **not** a no-memory condition. The only manipulated
variable was the additional compiled strategic state.

### 8.3 Bounded decision contract

Each model received:

- role and objective;
- actor-visible observation;
- allowed actions;
- recent history;
- response schema;
- optional strategic state.

The prompt prohibited real targets, credentials, shell use, and tool expansion.
The model could return only:

```json
{
  "action": "one allowed action",
  "rationale": "brief reason",
  "strategic_revision": null,
  "hypothesis_updates": []
}
```

Codex required a strict JSON Schema where every object declared
`additionalProperties: false` and every property was listed in `required`.
Hermes used the same runtime decision validator.

### 8.4 Results

| Provider / state mode | Objective achieved | Switch recognized | Tactical | Operational | Strategic | Information | Evaluator integrity | Exposure | Parse failures | Persisted revisions | Provider time | Reported tokens |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Hermes transcript | no | yes | 0.6667 | 0.0000 | 0.0860 | 0.3333 | 0.8500 | 4.0 | 1 | 0 | 198.035 s | unavailable |
| Hermes strategic | no | yes | 0.6667 | 0.0000 | 0.0860 | 0.3333 | 0.8500 | 4.0 | 1 | 5 | 292.483 s | unavailable |
| Codex transcript | no | no | 0.5000 | 0.0000 | 0.0680 | 0.0000 | 1.0000 | 4.0 | 0 | 0 | 173.811 s | 91,863 |
| Codex strategic | no | yes | 0.6667 | 0.0000 | 0.0618 | 0.3333 | 1.0000 | 4.5 | 0 | 4 | 157.745 s | 77,134 |

All four retained Trials failed to identify or obtain the genuine objective.

### 8.5 Within-provider observations

#### Hermes

The transcript and explicit-state conditions produced the same physical and
scored outcome:

- same tactical score;
- same strategic score;
- same information score;
- same exposure;
- one parse failure each;
- no objective success.

The strategic condition persisted five revisions and several higher-order
opponent hypotheses. Provider time increased by approximately 94.45 seconds,
or 47.7%, in this one comparison.

This supports a narrow conclusion:

> explicit state changed trace persistence and explanation, but did not improve
> measured action outcome in the retained Hermes Trial.

#### Codex

Relative to transcript mode, strategic mode showed:

- switch recognition: 0 to 1;
- information: +0.3333;
- tactical: +0.1667;
- exposure: +0.5;
- strategic score: −0.00625;
- provider time: −16.07 seconds;
- provider-reported tokens: −14,729, or approximately 16.0%;
- objective success: unchanged at failure.

With one Trial per condition, none of these differences can be attributed
causally to the state mode. They are retained observations, not estimates.

### 8.6 Reasoning quality versus action value

The explicit-state model traces contained plausible second-order explanations
such as:

- the defender may be shaping route signals;
- a phase rotation invalidates old route evidence;
- an apparently easy route may be a double bluff;
- a defender may relocate an objective after observing probing behavior.

These interpretations were not sufficient to complete the objective. In some
cases, increasingly elaborate deception hypotheses consumed the remaining
decision horizon without producing verified action value.

Round 1 therefore distinguishes:

```text
verbal strategic sophistication
≠
correct opponent model
≠
useful information
≠
objective success
```

### 8.7 Provider cost

Total recorded provider time:

| Provider | Two Trials | Decisions | Total time | Mean time per decision |
|---|---:|---:|---:|---:|
| Hermes | 2 | 12 | 490.517 s | 40.876 s |
| Codex | 2 | 12 | 331.555 s | 27.630 s |

Codex reported 168,997 tokens across the two Trials. Hermes did not expose a
comparable token counter through the configured CLI.

These are local execution observations, not normalized provider benchmarks. The
main engineering result is architectural:

> one fresh model session per decision is too expensive for long-horizon
> adversarial experiments.

This requirement was filed in Ordivon Host as issue #13. Security retains the
command adapter only as a baseline and failure-injection path.

### 8.8 Model conclusion

Round 1 does not support:

- a Hermes versus Codex ranking;
- an explicit-state capability advantage;
- a general conclusion about model reasoning;
- a Campaign-state promotion;
- a claim that the models are incapable under other seeds or horizons.

It supports:

- the bounded model adapter works;
- structured output failure is observable;
- explicit state can preserve hypotheses and revisions;
- switch recognition may improve without objective success;
- model-session continuity and cost belong in Host;
- one-seed model evaluation is inadequate.

---

## 9. Problems encountered and solutions

### 9.1 Stale evidence remained stale after re-verification

**Observed failure:** after the defense phase changed, route evidence was marked
stale. A later verification produced new evidence but did not clear the stale
flag. The opponent-aware actor repeatedly treated fresh evidence as obsolete and
entered a verification loop.

**Why it mattered:** the initial result falsely suggested that explicit opponent
state harmed performance.

**Resolution:** successful post-switch verification now sets
`stale_after_phase_change` to false.

**General lesson:** evidence freshness is not metadata attached once. It is a
state transition that must be replaced by new provenance when the World is
re-observed.

### 9.2 Correct belief consumed the resource needed to act

**Observed failure:** the opponent-aware actor correctly identified the safer
route but continued verifying the suspicious route. It spent the energy required
for exploitation and then withdrew.

**Why it mattered:** belief accuracy improved while operational and strategic
outcome remained zero.

**Resolution:** action ordering was changed to exploit an already verified
genuine route before gathering lower-value information.

**General lesson:** opponent modelling cannot be evaluated independently from
value of information, action cost, remaining horizon, and option value.

### 9.3 Heavy external dependency surface

**Observed risk:** adopting the full CAGE research environment would have pulled
in training, graph-learning, and visualization dependencies irrelevant to the
substrate comparison.

**Resolution:** pin the source revision and install only the simulation
slice. Keep CAGE external rather than vendoring or wrapping its entire stack.

**General lesson:** reuse a mature substrate at the narrowest stable boundary.
Do not let an experiment adapter become a shadow distribution of the upstream
project.

### 9.4 External package import did not match the desired minimal path

**Observed issue:** the first package-style installation path did not expose the
source as expected under the deliberately reduced dependency setup.

**Resolution:** treat the pinned CAGE repository as an external source checkout,
verify its exact Git revision, and place the source root on the experiment
interpreter path.

**General lesson:** source identity and reproducibility mattered more than forcing
an artificial packaging abstraction.

### 9.5 CAGE native time was not an integer Tick

**Observed failure:** the first adapter attempted to convert CAGE `state.time` to
an integer. The source uses a native time object.

**Resolution:** preserve the source value as ISO time in the state digest.

**General lesson:** adapters should preserve component-native facts instead of
normalizing them into a premature cross-project time ontology.

### 9.6 Strict Codex JSON Schema requirements

**Observed failure:** Codex rejected an initially permissive schema.

**Resolution:** every object now declares `additionalProperties: false`, and all
properties are explicitly required. Optional strategic revision is represented
as an object-or-null union.

**General lesson:** structured-output contracts must be treated as executable
interfaces, not illustrative examples.

### 9.7 Provider failure originally escaped the Trial

**Observed gap:** a timeout or missing provider executable could raise an
exception and abort the experiment without a Decision record.

**Resolution:** catch invocation errors, record elapsed time and exception type,
increment failure accounting, and emit a bounded fallback action.

**General lesson:** failed cognition is still experiment evidence. It should not
silently disappear outside the trace.

### 9.8 Token-accounting test failure was a test escaping error

**Observed failure:** a synthetic provider intended to emit `tokens used` failed
the accounting test.

**Root cause:** the test string converted an escaped newline into source code
syntax rather than provider output.

**Resolution:** correct the test escaping. The production parser was unchanged.

**General lesson:** distinguish an instrumentation failure from a test-fixture
failure before changing runtime behavior.

### 9.9 Model results changed across non-retained development runs

During development, temporary model runs produced different objective outcomes
from the final retained runs. Those temporary artifacts were overwritten during
final-code reruns and are not part of the committed quantitative evidence.

The divergence was nevertheless important operational evidence:

- one sampled trajectory is unstable;
- a provider comparison can reverse across runs;
- model results must be regenerated after code hardening;
- the final report must bind exact retained traces rather than memorable earlier
  outcomes.

**Resolution:** after the final provider error semantics were added, all four
model Trials were rerun, the evidence summary was rebuilt, and every digest was
revalidated before merge.

**General lesson:** never promote a model result from a development run that is
not bound to the final implementation and retained evidence.

### 9.10 Raw trace size versus repository integrity

**Problem:** committing every raw Trial and model response would turn the
repository into a data store and could retain sensitive or provider-specific
content.

**Resolution:** raw artifacts remain ignored. Git stores sanitized aggregate
results, implementation-file digests, Trial-index digests, and trace digests.

**Trade-off:** the committed repository proves identity and integrity but does
not preserve every raw event for independent qualitative review.

**Next improvement:** retain a deliberately sanitized representative trace set or
publish external immutable artifacts when long-term trajectory inspection is
required.

---

## 10. Cross-experiment synthesis

### 10.1 What all three experiment families jointly support

#### Separation of observation and truth is necessary

The local fixture needed hidden decoy and policy state. CAGE needed source-native
authoritative state. Model actors needed bounded observations. Without this
separation, deception and evaluator validity would be untestable.

#### One outcome is insufficient

- the local greedy actor achieved tactical success while failing strategically;
- CAGE reward and foothold spread produced conflicting orderings;
- Codex strategic mode improved information and tactical scores while slightly
  reducing strategic score and still failing the objective.

#### Better interpretation does not guarantee better action

The local opponent-aware actor improved information more than objective success.
Model strategic state preserved richer hypotheses without completing the task.
The missing link is not merely more reasoning; it is verified belief, resource
allocation, timing, and action selection.

#### Mature substrates should remain mature substrates

CAGE supplied the classical World. Hermes and Codex supplied model inference.
Ordivon Security should compose these systems and retain only the strategic
relations that repeated experiments prove necessary.

#### Null results are architecture results

The absence of objective benefit prevented promotion of Campaign state. The
absence of a missing World fact prevented construction of a cyber range. The
absence of collective advantage prevented promotion of an organization ontology.

### 10.2 What remains unproven

- model adaptation across multiple seeds;
- held-out opponent-policy transfer;
- explicit-state value after context truncation;
- state value after model or Host replacement;
- long-horizon Campaign continuity;
- multi-Agent reorganization under member loss;
- evaluator manipulation and monitor robustness;
- coevolution or self-play;
- cross-domain transfer;
- real-world offensive or defensive capability.

---

## 11. Validity threats

### 11.1 Construct validity

The local strategic score is a hand-designed weighted function. The weights
encode an experimenter's view of objective value, future options, and exposure.
They are useful for exposing contradictions, not for claiming a universal
strategic utility function.

The information score contains three binary components. It does not measure
calibration, uncertainty quality, causal attribution, or counterfactual value.

The organization score measures disagreement and one compromise penalty. It is
not organizational effectiveness in general.

### 11.2 Internal validity

The explicit scripted actor was designed around the local fixture's evidence
classes. Its advantage is therefore partially structural and must not be treated
as independent discovery.

The compartmentalized committee selects the cautious specialist, while the naive
committee selects the fast specialist. The experiment tests adjudication under
compromise, not compartmentalization as an isolated communication variable.

Both model conditions retained recent transcript history. The experiment did not
isolate memory presence; it isolated additional compiled state.

### 11.3 Statistical validity

- local actor totals contain 15 Trials each, but only five seeds per opponent
  policy;
- CAGE groups contain five Trials each;
- model conditions contain one retained Trial each;
- no confidence interval, significance test, bootstrap, or power analysis was
  performed;
- model sampling and provider configuration can vary outside the recorded seed.

All comparisons are descriptive.

### 11.4 External validity

The local fixture is a two-route synthetic World. CAGE is a simulator. No result
establishes real cyber capability, organizational performance in production, or
transfer to economic, social, or physical adversarial systems.

### 11.5 Reproducibility limits

The deterministic local suite is reproducible from repository code and seeds.
CAGE is pinned by revision and dependencies, although the upstream Gym warning
and future platform compatibility remain external risks.

Model reproducibility is weaker:

- provider services can change;
- Hermes token usage was unavailable;
- the Codex identity was recorded as `codex-configured-model`, not an immutable
  model snapshot;
- raw model traces are represented by digests rather than committed in full;
- command sessions were stateless and environment-dependent.

### 11.6 Evaluator validity

Round 1 did not include an adversarial monitor, hidden evaluator attack,
reward-hacking policy, or judge manipulation. Evaluator integrity only accounts
for invalid actions and structured-output failures in the local fixture.

---

## 12. Architecture decisions

| Candidate | Decision after Round 1 | Evidence |
|---|---|---|
| ExperimentSpec and exact identities | Retain in Security experiment layer | Used across local and CAGE paths |
| Actor Observation versus World truth | Retain | Required by deception and mature World adapters |
| Digest-bound TraceEvent | Retain | Enabled implementation/evidence verification |
| Multidimensional outcome | Retain experimentally | Metric conflicts appeared in all experiment families |
| Explicit opponent hypotheses | Retain as a research variable | Improved local diagnosis and one model switch-recognition result |
| Campaign or strategic state | Do not promote | No retained model Trial achieved the objective; no success benefit established |
| Multi-Agent organization ontology | Do not promote | One synthetic adjudication scenario only |
| Stateless command model provider | Retain only as a baseline | Functional but dominated by session cost |
| Persistent model Session | Route to Ordivon Host | Required for long-horizon cost and continuity experiments |
| Custom Ordivon cyber range | Reject for next round | CAGE supplied required classical facts |
| Inspect/ControlArena evaluator integration | Defer | Evaluator attack was not yet the independent variable |

---

## 13. Required next experiment

The next round should answer one stronger question rather than add more schema:

> does compiled opponent state provide transferable value when a model-backed
> Actor operates across multiple seeds, held-out opponent policies, and Host
> Session disruption in a mature World?

### 13.1 Proposed design

World:

- a deliberately bounded CAGE scenario or another mature dynamic-opponent World;
- authoritative source truth retained by the adapter;
- opponent policies split into train/development and held-out sets.

Actor conditions:

1. finite-state baseline;
2. model Actor with recent transcript only;
3. model Actor with compiled opponent hypotheses;
4. compiled-state Actor after context truncation;
5. compiled-state Actor after Host Session replacement.

Execution:

- at least three seeds for infrastructure acceptance;
- preferably ten or more seeds before comparative claims;
- persistent Host Session versus stateless command baseline;
- exact model/scaffold/Context receipts;
- fixed resource and action limits;
- repeated provider samples where nondeterminism remains.

Outcomes:

- objective and mission outcome;
- switch-detection delay;
- false opponent attribution;
- deception-trigger rate;
- resource use before commitment;
- exposure and future options;
- provider latency and tokens;
- state continuity after Session replacement;
- held-out opponent transfer.

### 13.2 Promotion rule

Compiled strategic or opponent state should be promoted only if it improves at
least one of the following without unacceptable cost:

- held-out opponent performance;
- policy-switch detection;
- recovery after Context truncation;
- continuity after model/Host replacement;
- diagnosis of failure;
- provider cost through useful state compression.

If transcript context or ordinary Host state performs equivalently, delete the
specialized structure.

---

## 14. Reproduction and verification

### 14.1 Deterministic local suite

```bash
./scripts/run_round1_acceptance.sh
```

This runs the repository tests and regenerates the 60 local Trials.

### 14.2 Pinned CAGE baseline

```bash
./scripts/bootstrap_cage4.sh

PYTHONPATH="$PWD/.cache/cage4" \
  .venv-cage4/bin/python scripts/run_cage4_baseline.py \
  --source "$PWD/.cache/cage4" \
  --output artifacts/round1/cage4 \
  --seeds 1,2,3,4,5 \
  --steps 60 \
  --blue-policies sleep,random \
  --red-policies finite-state,random-select
```

### 14.3 Model diagnostic examples

```bash
python3 scripts/run_adversarial_experiment.py \
  --actor hermes-strategic \
  --seeds 101 \
  --opponents adaptive-counter \
  --max-turns 6 \
  --output artifacts/round1/hermes-strategic

python3 scripts/run_adversarial_experiment.py \
  --actor codex-strategic \
  --seeds 101 \
  --opponents adaptive-counter \
  --max-turns 6 \
  --output artifacts/round1/codex-strategic
```

Model reruns are not expected to reproduce identical behavior unless provider,
model, scaffold, and sampling behavior are immutable.

### 14.4 Evidence chain

Committed evidence:

```text
evidence/experiments/round1-20260730.json
```

Important identities:

```text
Evidence ID:
ORDIVON-SECURITY-ROUND1-20260730

Experiment implementation merge:
f135e97e310c94a1b987d6f2bf1c5e883ca6dae9

Evidence source base before experiment changes:
c00f7187ae686f5886631769fdbb1a41fdf2655d

Implementation file-manifest digest:
sha256:de40127a360db3db2804dc911ca2ad1a3725bcf6cb370b0d6c346491c81da789

CAGE source revision:
8c3c50ca54b176c2de199847944e8dcc035497e3
```

The evidence source base identifies the branch base before the experiment-layer
changes. The merged implementation is independently bound through the
implementation-file manifest and the merge commit.

---

## 15. Final conclusion

Round 1 changed Ordivon Security from a repository with a strong experimental
lifecycle substrate into a repository capable of running and comparing bounded
strategic-adversarial experiments.

The important achievement is not that an Agent defeated an opponent. It did not.
The important achievement is that the system can now distinguish:

- what the World knows from what the Actor sees;
- what an Actor claims from what its actions achieve;
- tactical success from strategic outcome;
- opponent recognition from objective completion;
- organizational isolation from collective intelligence;
- external substrate facts from Security interpretation;
- model explanation from model capability;
- valid null results from attractive but unsupported architecture.

The evidence argues for a restrained next step:

- reuse mature Worlds;
- move persistent inference sessions into Host;
- test multiple seeds and held-out opponents;
- make Context loss and Session replacement explicit;
- retain multidimensional evidence;
- promote no strategic abstraction until it survives those tests.

Round 1 therefore establishes a credible experimental foundation for
Agent-native strategic adversarial systems while refusing to mistake one
synthetic fixture, one model trajectory, or one appealing ontology for a proven
system.

---

## Appendix A — retained model trace digests

| Trial | Trace digest |
|---|---|
| Hermes transcript | `sha256:adc6196f7ec1eb62ce1ed479c71c34b09b4ddfa26d1c0a16823e6ba0ab22ccec` |
| Hermes strategic | `sha256:2d60161df47e330f40f1d88e934fb5a941ca90a6fde985a70e6ef209d8ea750b` |
| Codex transcript | `sha256:2c2033e88a4357dbfd2a15afc27590c3db41888a961c82bbcbaa4e8fa02c07ba` |
| Codex strategic | `sha256:1ed7cfaeee7a9f40f5be475e74f99b884750c966b268797cef901b4beb05c772` |

## Appendix B — related implementation and research material

- [`experiment-layer.md`](experiment-layer.md)
- [`round1-experimental-results.md`](round1-experimental-results.md)
- [`research-agenda.md`](research-agenda.md)
- [`classical-to-agent-adversarial-map.md`](classical-to-agent-adversarial-map.md)
- [`../ordivon_security_experiments/micro_contest.py`](../ordivon_security_experiments/micro_contest.py)
- [`../ordivon_security_experiments/actors.py`](../ordivon_security_experiments/actors.py)
- [`../ordivon_security_experiments/cage4.py`](../ordivon_security_experiments/cage4.py)
- [`../ordivon_security_experiments/runner.py`](../ordivon_security_experiments/runner.py)
- [`../evidence/experiments/round1-20260730.json`](../evidence/experiments/round1-20260730.json)
- Ordivon Security PR #17
- Ordivon Host issue #13
