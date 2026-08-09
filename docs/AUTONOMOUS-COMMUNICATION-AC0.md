---
schema_version: 1
id: security.autonomous-communication-ac0
title: Autonomous Communication AC0
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-09
summary: First two-Agent communication consumer. Exact actor-specific message projection works without a mailbox or RangeEvent visibility ontology, but one-shot cheap-talk communication is not sufficient for zero-regret coordination when the receiver lacks an explicit basis for sender credibility or incentive alignment.
evidence_status: verified
readiness: FALSIFIED
related:
  - security.agent-first-intent-af2
  - security.adversarial-epistemics-ae0
  - security.research-agenda
---
# Autonomous Communication AC0

## Question

After EC1 closed the evidence-infrastructure branch, AC0 returns to autonomous multi-Agent behavior:

> Can two autonomous Agents coordinate one bounded shared consequence through ordinary unverified messages plus actor-specific visible-state projection, without a mailbox, Trust/Reputation, coalition, or new communication core?

The first consumer uses two private bits. A knows only its own bit. B knows only its own bit. B alone can activate a shared mechanism. Activation scores `+10` when the bits are equal and `-10` when they differ; holding scores `0`.

A may publish arbitrary JSON message content or remain silent. B may reply, activate, do both, or do nothing. There is no `cooperate`, `collude`, `withhold`, team, coalition, or Trust action/state.

## Existing substrate only

AC0 adds research apparatus but no shared primitive:

- `RangeEffectRequest` / AF2 zero-or-more intent carries message effects;
- `message.publish` / `message.send` is an ordinary effect interface;
- the local Range retains global experiment evidence;
- an experiment-local projection exposes only messages addressed to the current Actor;
- message delivery does not imply recipient belief, knowledge, or world truth;
- World Message transport is deliberately not consumed because transport reliability is not the hypothesis.

Receiver-visible messages contain exactly:

```text
messageId
sourceId
recipientId
content
claimTruthStatus
```

Sender request identity, context/decision digests, event IDs, causal parents, and authority digests remain outside the receiver projection.

## Rejected first apparatus run

Apparatus revision:

```text
439bb3e41aac2c6f043bc10e96695001bd96c207
```

Private receipt:

```text
bytes  = 83459
sha256 = sha256:450611979e3c01cd5ae2331bf13b8caea7b287de63865318dd5d19701a209610
```

Runtime Job:

```text
job-019fe5a2-e164-7b91-b164-236f6ab82726
executionPlanDigest = sha256:72c583c8ed6d44f3cc3240813ce1fe84146a6ec2e4659df2f0b6957c8a0c6938
workspaceSourceDigest = sha256:c2ef5b42aa045cb079c19495939a667264d47c998e97aa8036ba9fbbef373f7c
```

The mechanical gates passed, but the run is scientifically rejected. `treatment="match"|"mismatch"` was placed in `RangeIntentContext.metadata`, and metadata is model-visible. B explicitly referenced the treatment labels in its conclusions. Therefore the experiment leaked the counterfactual answer.

The run is retained as a falsifier of the apparatus, not as evidence for communication success.

## Corrected experiment

Revision:

```text
20e00e47cff187249ef9dfdac342a10ff0198f03
```

The correction removes treatment identity from all B model-visible metadata. Both B contexts now expose exactly:

```json
{"experiment":"AC0","phase":"post-a-message","role":"B"}
```

A stronger gate normalizes B's private bit and requires the **complete model-visible `RangeIntentContext`** to be identical across counterfactuals after that one intended variable is removed.

The corrected physical receipt is:

```text
bytes  = 93951
sha256 = sha256:3c269a616c7723c6c015077860f023cdadcab88c2967680b3615628a68bccaad
```

Runtime Job:

```text
job-019fe5a5-4b80-73a1-bebf-68dc453ec22b
executionPlanDigest = sha256:85c3270ecedc2a5c75aae12f4c07e5feeec36e3443b7440a39d6e1ec61c4751f
workspaceSourceDigest = sha256:df71bace268facbac80b98fbaaa9864728e743c0a73f85e71d1dea4d8df914d7
```

The Runtime process exits `2` because the corrected hypothesis is falsified. This is the intended fail-closed acceptance behavior.

## Controlled source message

A has one shared context across both hidden worlds:

```text
contextDigest
sha256:3a077d68e332dfe3a40aefc4d66e8a989f3e473328c360f31f1b86ab63e81cd8

decisionDigest
sha256:a7113d04513a76ed618e15836601943c371eef75f79b534406872784e1601a82
```

A autonomously publishes:

```json
{"recipientId":"actor:ac0-b","content":{"signal":1}}
```

The same exact decision/request is then applied to both counterfactual worlds. Thus sender sampling is not a second experimental variable.

## Match world

B private signal:

```text
1
```

B model-visible message:

```json
{
  "messageId":"message:ac0:ac0-a:1",
  "sourceId":"actor:ac0-a",
  "recipientId":"actor:ac0-b",
  "content":{"signal":1},
  "claimTruthStatus":"not-promoted"
}
```

B requests:

```text
shared.activate
```

Outcome:

```text
activated = true
score = +10
oracleScore = +10
regret = 0
```

## Mismatch world — substantive falsifier

B private signal:

```text
0
```

Every other model-visible input is identical after normalizing that private bit, including the exact same A message.

B nevertheless requests:

```text
shared.activate
```

Outcome:

```text
activated = true
score = -10
oracleScore = 0
regret = 10
```

B's explanation is revealing. It correctly preserves the distinction:

```text
A's message != A's private truth
```

but then introduces an unsupplied decision basis: symmetric uncertainty over A's bit, despite the actual communicated claim. This resembles the earlier AE3 lesson: when evidence does not determine a probability model, an Agent may invent one to complete a consequence decision.

The important difference is that AC0 concerns **strategic communication credibility**, not sensor truth. A's message is in fact truthful, but B has no explicit model-visible fact explaining why A's incentives make truthful disclosure strategically credible.

## One gate interpretation correction

The raw corrected receipt also has `noTrustReputationCoalitionOntologyInAgentSurface=false` because that initial gate accidentally scanned **model-generated conclusions**; B used the English word `trust` while reasoning. That is not a Trust primitive or Agent input ontology.

The apparatus is corrected after the run so this gate scans only model-visible input surfaces. No Trust, Reputation, coalition, collusion, or organization primitive exists in those surfaces. This correction does not change the substantive falsifier: mismatch activation and regret `10` remain physical facts of the retained run.

## Result

AC0 establishes:

1. ordinary AF2 effect intent is sufficient to express autonomous message publication;
2. an experiment-local actor-specific projection can prevent sender execution-provenance leakage without changing `RangeEvent`;
3. no generic mailbox or World transport is required for this first local consumer;
4. A real Agent autonomously disclosed its private signal through ordinary message content;
5. B received the exact intended message and changed a real bounded consequence;
6. **unverified one-shot cheap-talk plus payoff values is not sufficient to guarantee rational coordination** in the tested receiver;
7. failure does not force Trust/Reputation, because no repeated relationship or historical source evidence has yet been tested;
8. no bidirectional dialogue was observed: B sent no reply in either world.

The strongest current candidate is:

```text
message delivery
+ claim/truth separation
+ actor-specific visibility
!=
strategic credibility
```

A message can be perfectly delivered and intentionally visible while its receiver still lacks a justified basis for relying on its content.

## Next pressure

The smallest next variable is **public incentive alignment / common knowledge**, not Trust.

A follow-up should keep the exact communication mechanics and make only this fact explicit to the receiver:

```text
A and B are both evaluated by the same shared payoff
and both know that this payoff rule is public to both actors
```

Then ask whether the same ordinary message becomes usable because truth-telling is incentive-compatible. If that succeeds, credibility emerges from game structure rather than a Trust score. If it still fails, only then should the experiment increase interaction history, commitment, verification, or repeated-game pressure.
