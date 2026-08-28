---
schema_version: 1
id: security.tactical-adaptation-ca6
title: Tactical Adaptation CA6
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-14
summary: Bounded tactical comparison showing that current-evidence capability selection and replanning outperform a fixed script, while a thin deterministic adaptive policy matches the canonical DeepSeek/Harness Agent and no Campaign/Gateway abstraction is forced.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.classical-capability-basis-ca0
  - security.provider-assimilation-ca5
  - security.intent-ceremony-ablation-if3
---
# Tactical Adaptation CA6

## Question

CA6 asks the first genuinely Agent-level question in the classical capability line:

> Given several already-verified capability properties, does selecting, abandoning and substituting actions against current evidence and active counterplay require a new tactical state architecture, or can ordinary observation-driven composition already explain the gain?

The experiment deliberately does **not** re-run malware, exploits, real credentials or external providers. CA1-CA4 already established the physical/provider facts. CA6 freezes those facts into a semantic tactical arena so the independent variable is policy rather than mechanism noise.

## Frozen capability surface

The two-turn owned arena exposes four typed effects:

- `control.credential` — CA3 current synthetic-credential authority semantics;
- `control.script` — CA1 carrier/policy applicability semantics;
- `control.exploit` — CA2 target-revision-bound exploitability semantics;
- `inspect.applicability` — CA0/CA4 explicit information-acquisition/currentness semantics.

Each consequential option carries fixed cost and exposure. Applicability is projected as `AVAILABLE`, `UNAVAILABLE` or `UNKNOWN`. Variant labels are not visible to either adaptive policy.

No gateway is inserted between the policy and the existing `RangeEffectRequest` surface.

## Treatments

### Static scripted baseline

One fixed sequence is frozen for every world:

```text
credential -> script
```

It never reads current capability properties.

### Constrained adaptive baseline

One deterministic policy, with no variant-specific branches, reads only current applicability/cost/exposure:

1. among `AVAILABLE` control capabilities choose minimum `cost + 2*exposure`;
2. when no control capability is currently `AVAILABLE` but at least one is `UNKNOWN`, inspect applicability;
3. after every effect/counterplay, choose again from the fresh observation.

This is intentionally thin. If it is enough, a richer tactical abstraction is not earned.

### DeepSeek/Harness Agent

The model treatment uses `deepseek-v4-flash`, Harness revision `6639cf575eb006e8be2864037d9427b9913dd8a3` and Computing protocol revision `c96eccd2e2d6fe78c39bc7127ac8c9c8eb267833`.

A direct ordinary-AF2 diagnostic exhausted the three-call loop budget before producing a tactical decision. CA6 therefore reuses the already-accepted IF3 structure rather than arbitrarily increasing retries:

```text
one no-effect, non-authoritative deliberation turn
-> ordinary replaceable AF2 pending-intent authority phase
-> Security world action
-> fresh observation
-> repeat if budget remains
```

Natural-language deliberation remains cognition evidence only; the structured Tool intent is authoritative for the selected action.

## Held-out worlds

Four worlds pressure different CA0-CA4 laws:

1. `visible-low-exposure` — every path is available; credential is cheapest/least exposed;
2. `revoked-and-script-blocked` — credential currentness is unknown, script is unavailable, exploit is currently available;
3. `all-control-unknown` — all consequential paths are unknown, so current evidence requires inspection before justified action;
4. `adaptive-counterplay` — Blue observes and counters the first control attempt, then tightens adjacent applicability before the final turn.

The Blue counterplay treatment is causal, not a label trick: after the first credential attempt, current credential and script applicability become unavailable while exploit remains available.

## Canonical result

Apparatus revision:

`c59aa0a2d7c36c34ee0ddc62060b0ed9e6a70afb`

Canonical Runtime Job:

`job-019fff05-30cd-7c12-a2c0-ac9d235ce2aa`

Full result digest:

`sha256:5028f6b3b791643f227da5fb14bc16488eb632a6b2b33ec3041fbbb6b1bec295`

All seven canonical gates pass.

| World | Static | Constrained adaptive | DeepSeek/Harness |
| --- | --- | --- | --- |
| visible-low-exposure | credential ✅ | credential ✅ | credential ✅ |
| revoked-and-script-blocked | credential→script ❌ | exploit ✅ | exploit ✅ |
| all-control-unknown | credential→script ❌ | inspect→exploit ✅ | inspect→exploit ✅ |
| adaptive-counterplay | credential→script ❌ | credential→counter→exploit ✅ | credential→counter→exploit ✅ |

Static fails 3/4 worlds.

The adaptive regret vectors against a full-hidden-truth oracle are identical:

```text
constrained adaptive = {0, 0, 1, 0}
model-backed         = {0, 0, 1, 0}
```

The `1` occurs in the all-UNKNOWN world because the full-truth oracle can choose exploit immediately while both admissible adaptive treatments spend one action acquiring current applicability. This is epistemic cost, not strategy error under their visible evidence.

## What CA6 establishes

### CA6-L1 — adaptation lives above capability mechanics

The capability mechanics are frozen. The measured gain comes from choosing among current options after observations and counter-effects. This is the first CA-series evidence that the Agent-native residual is chiefly **conditional capability selection/composition**, not a new exploit/malware primitive.

### CA6-L2 — fresh applicability is enough for this tactical horizon

The deterministic adaptive policy has no Campaign state, persistent opponent model, technique graph or provider gateway. Current observation plus ordinary action history is sufficient to handle revocation, unknown applicability and one active Blue switch.

### CA6-L3 — information acquisition is a tactical action

When all control paths are UNKNOWN, both adaptive treatments choose `inspect.applicability` and then exploit. This independently reproduces the earlier epistemic law in a capability-selection consumer: UNKNOWN can justify information acquisition without justifying a hidden-world assertion.

### CA6-L4 — replanning is not retry order

In active counterplay the first credential action is explicitly countered; Blue then changes current applicability. Both adaptive treatments select exploit from the new state. The static pre-authored fallback selects script and fails.

Thus the useful distinction is not “has a longer fallback list.” It is “recomputes choice after current world evidence changes.”

### CA6-L5 — LLM capability is not automatically the residual abstraction

The canonical model succeeds, but it does not outperform the thin deterministic adaptive policy. Earlier diagnostics also expose model/Harness friction: direct AF2 exhausted its bounded loop, and one non-canonical deliberation-primed batch did not satisfy all aggregate gates before a later replicate and the clean canonical run succeeded.

Therefore CA6 rejects the claim that model-backed planning alone justifies a new tactical-state subsystem.

### CA6-L6 — CA5 remains closed

The arena directly consumes heterogeneous verified capability facts through existing effect interfaces and `RangeEffectRequest`. No provider gateway is required. CA6 therefore does not reopen CA5.

## What CA6 does not prove

CA6 does not test:

- objectives persisting across missions or actor replacement;
- scarce foothold/credential/compute resources across episodes;
- strategic opponent hypotheses whose history matters causally;
- multi-Agent command/compartmentalization;
- team loss and reorganization;
- coevolution across repeated encounters;
- transfer from semantic arena back to VM/physical tactical performance.

Those are exactly the facts CA7 must require before admitting Campaign/Organization work.

## CA7 implication

CA6 produced **no failure that ordinary current-observation composition cannot explain**. The correct CA7 action is therefore an admission decision, not implementation of the remaining roadmap.

Unless another independent consumer demonstrates cross-episode strategic state that materially changes decisions, Campaign, Organization and coevolution remain unearned.

## Post-closeout executable standing — 2026-08-28

CA6's accepted/falsified research result and source-fenced evidence remain canonical. The one-shot `cli_ca6_tactical_adaptation.py` experiment runner is retained under `fixtures/archive/runners/` rather than the current package because it has no installed command, current source/research consumer, exact documentation invocation, or current surface claim; its remaining unit test exercised runner-local experiment apparatus. The accepted evidence is indexed by the `c59aa0a` receipt. Restoring the runner is an explicit reproduction/new-experiment action, not a current Security capability requirement.
