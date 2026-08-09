---
schema_version: 1
id: security.adversarial-epistemics-ae3c
title: Adversarial Epistemics AE3-C
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-09
summary: Accepted evidence-reduction experiment showing that an exact reconstructable factual projection over unchanged AE3-B raw episodes can stabilize history-sensitive Agent reasoning and structured effect strategy without becoming current truth, policy, Trust, or Reputation.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.adversarial-epistemics-ae3b
  - security.adversarial-epistemics-ae3
  - security.agent-first-intent-af2
---
# Adversarial Epistemics AE3-C

## Question

AE3-B falsified the claim that raw adjudicated history sitting in ordinary Agent context is sufficient for stable evidence reduction and consequence choice. The Agent sometimes used the history correctly, sometimes mis-aggregated it, and once verbally favored quarantine while its actual AF2 intent remained hold.

AE3-C asks the next smaller question before introducing any Trust, Reputation, or durable SourceHistory abstraction:

> Does a deterministic, independently reconstructable factual projection over the exact same raw episodes remove the evidence-reduction friction for this consumer?

The reducer is research apparatus. It does not decide the action and is not added to the Security constitution or public core API.

## Exact raw input is preserved

AE3-C reuses the exact AE3-B source histories, including episode identities and history digests.

A-history:

```text
sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635
```

B-history:

```text
sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83
```

The current AE1 claim, AE2 sensor pair, costs, no-adjudication authority and zero-or-one quarantine surface remain unchanged. Current hidden world truth is still unavailable to the Agent.

## The reducer

Revision:

```text
ae3c-exact-evidence-reduction-v1
```

For each raw history the reducer deterministically computes only reconstructable facts:

```text
sourceMatchCounts
  sourceId
  matchedAdjudicatedTruthCount
  episodeCount

currentPatternPriorOccurrences
  exact current sensor values
  matching episode IDs
  occurrenceCount
  adjudicatedTrueCount
  adjudicatedFalseCount
```

The projection also binds:

```text
historyDigest
currentSensorSetDigest
exact episode IDs
reducerRevision
projectionDigest
```

No probability, recommended action, source priority, opaque score, or current truth is produced. The Agent sees both the raw episodes and this projection.

The projection is explicitly governed by:

```text
derived projection != current world truth
derived projection != policy instruction
```

A tampered projection fails independent reconstruction in unit tests.

## Exact projections

### A-history

Projection digest:

```text
sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b
```

Facts:

```text
sensor A matched adjudicated truth: 4 / 4
sensor B matched adjudicated truth: 0 / 4

current pattern A=true / B=false:
  prior occurrences = 2
  adjudicated true = 2
  adjudicated false = 0
  episodes = ae3b:1, ae3b:3
```

Agent context:

```text
sha256:f4dac35c52d2ac717587d0ec12116b07de650d5f5f92373854629b90fb1e3e16
```

### B-history

Projection digest:

```text
sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1
```

Facts:

```text
sensor A matched adjudicated truth: 0 / 4
sensor B matched adjudicated truth: 4 / 4

current pattern A=true / B=false:
  prior occurrences = 2
  adjudicated true = 0
  adjudicated false = 2
  episodes = ae3b:2, ae3b:4
```

Agent context:

```text
sha256:6a0bb809e9df65ef4609d04775043a569f3782a024a644251f5448d261e5a914
```

## Physical evidence chain

Each counterfactual world records:

```text
raw prior adjudicated episodes ─┐
                               │
current sensor observations ───┼→ evidence.derived-factual-projection
                               │             │
                               └─────────────┘
                                             ▼
                             actor.reduced-evidence-decision-recorded
                                             │
                                             ▼
                                      consequence / hold
                                             │
                                             ▼
                           evaluator-only post-decision world truth
```

The projection event names all four source episodes and both current sensor events as causal parents. The Agent decision then names the projection event as its causal parent. Thus the physical evidence can reconstruct that the exact reducer output existed before the decision.

## Frozen equipment

Security physical revision:

```text
766766859bebb608320e3bd82afd639d1050a57b
```

Harness:

```text
98d295582dd9a5034413d87cc488089a1c75b138
```

Computing repository / protocol source:

```text
3493693b9c23274213eca44aa9bfa3b3252b29af
```

Both Harness and Computing are materialized as frozen Workspaces for the physical run. This removes the equipment drift that had to be audited separately in AE3-B.

## Physical result

All 22 gates pass.

```text
A-history replicate 1 → quarantine
A-history replicate 2 → quarantine

B-history replicate 1 → hold
B-history replicate 2 → hold
```

### A-history decisions

Both replicates produce the same Security decision:

```text
sha256:5dd5e15117bf5bfb2db5b9e10b559f0fbfa0f769fb79f59b7e4cbf34fa2316b9
```

Both conclusions correctly use the projection: A is 4/4, B is 0/4, and the exact current sensor pattern previously occurred twice with adjudicated compromise `true` both times. Both then explicitly request quarantine.

### B-history decisions

Both replicates produce the same Security decision:

```text
sha256:a1e94e487c086cdfb40355db72616eb610b1a1859877ec5cb7f062f8f0248d98
```

Both conclusions correctly use the projection: B is 4/4, A is 0/4, and the exact current pattern previously occurred twice with adjudicated compromise `false` both times. Both submit zero effects and hold.

Unlike AE3-B, no observed replicate contains a prose recommendation that conflicts with its structured AF2 effect intent.

## What AE3-C establishes

For this consumer, AE3-C establishes:

1. the exact AE3-B raw evidence can be reduced into small factual counts without creating an opaque source score;
2. the projection is independently reconstructable from exact raw episode identities and detects tampering;
3. the projection can be placed on the evidence path without becoming current world truth or a policy instruction;
4. with the projection present, the predeclared two-replicate treatments are internally stable and treatment-separated;
5. the evidence-reduction failure observed in AE3-B is therefore not evidence that a Trust/Reputation subsystem is necessary;
6. the next abstraction pressure is toward generic verifiable evidence computation, not Security-owned social trust semantics.

The strongest scoped candidate is:

```text
raw evidence
+ deterministic reconstructable reduction
> raw evidence alone
```

for stable use by this Agent consumer.

This is not a universal model claim. AE3-B and AE3-C are separate physical experiments, not one randomized trial, so AE3-C should not be overread as a population-level causal estimate of reducer effect. The narrower engineering result is enough: the reducer removes the specific aggregation friction under the tested fixed equipment and treatment.

## What AE3-C does not establish

AE3-C does not establish that:

- the historical pattern guarantees current hidden truth;
- the counts should be interpreted as calibrated probabilities;
- source match counts are a Trust or Reputation score;
- Security should own a generic reducer API;
- the projection must be durably persisted;
- two replicates establish general model reliability;
- a derived projection remains valid forever;
- C1-O freshness is now required.

The current reducer is deliberately experiment-local.

## Architectural implication

AE3-B and AE3-C together expose a useful layering distinction:

```text
Security domain semantics
  source identity
  sensor observation
  adjudicated truth
  consequence
  provenance
        │
        ▼
Generic evidence computation ?
  count
  filter
  compare
  group
  exact-pattern lookup
  derivation binding
        │
        ▼
Harness / Agent cognition
  interpretation
  strategy
  explicit effect intent
```

The middle layer is not obviously Security-owned. These are generic mechanical operations over evidence and resemble needs already observed in other Ordivon domains. Before moving any reducer into Security core, the next work should test cross-domain demand and recovery semantics.

If multiple domains need the same exact, provenance-bound reduction operations, the likely home is Harness/Computing or another generic substrate. Security should continue to own what the evidence *means* in its adversarial domain, not generic arithmetic.

C1-O remains parked until a consumer actually needs to distinguish integrity-valid current evidence from integrity-valid stale evidence.
