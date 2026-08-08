---
schema_version: 1
id: security.intrinsic-idempotency-c1k
title: Intrinsic Consequence Idempotency C1-K
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-08
summary: Physical proof that an exact ensure-state consequence can tolerate repeated invocation and acknowledgement loss without a sidecar dedup/inbox object: two invocations converge to one verified world consequence, while absent and already-satisfied worlds share the same safe retry policy.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.recipient-commit-gap-c1j
  - security.information-loss-c1i
  - security.law-profiles-c0
---
# Intrinsic Consequence Idempotency C1-K

## Question

C1-J proved that a non-idempotent consequence plus a separate durable dedup/completion write has an unavoidable crash gap. Reversing the writes only selects duplicate versus loss, and an honest `reserved` inbox preserves uncertainty without resolving it.

C1-K therefore tests the smaller candidate before any transaction framework:

> What if repeat safety belongs to the consequence itself?

## Exact consequence

C1-K uses one owned local no-uplink world object:

```text
authorityId = range-authority:c1k-local-idempotent-world
zoneRef     = zone:c1k-local-no-uplink
capability  = world-object.ensure-state
effectType  = world-object.ensure-exact-symlink
effectId    = range-effect:c1k-idempotent-world-object-v1
targetKey   = effect-bf78afed8c7a661aea2781e9
desiredValue = ordivon-world-state:c1k-idempotent-v1
```

Request digest:

```text
sha256:46cc4d19d49c2019b30e76d7a436359b071a1715ff1be5fed4a4732086f3561b
```

Admission digest:

```text
sha256:6888af8fe226f794a399695aebe486e03a960d8066d41adfb9cd86816107fca3
```

The symlink is the consequence itself. There is no adjacent recipient dedup marker, inbox, completion file, or transaction record in the effect world.

The operation is:

```text
absent
→ atomically create exact symlink
→ applied

exact same symlink already present
→ no mutation
→ already-satisfied

same name but wrong type/value
→ conflict
→ fail closed
```

The wrong-type case is unit-tested so name equality is not treated as consequence identity.

## History A — consequence committed, ACK lost

The first recipient receives the exact effectId, creates the exact symlink, records that the ensure operation returned `applied`, then is SIGKILLed before sending an ACK.

After crash:

```text
sender completion publication = absent
world target                  = exact
semantic consequence count    = 1
```

A fresh restricted sender retries the same effectId.

The new recipient executes the same effect operation again. It observes the exact target and returns:

```text
status = already-satisfied
worldMutated = false
semanticEffectSatisfied = true
```

Physical result:

```text
physical invocation count            = 2
world mutations by accepted effect   = 1
final semantic consequence count     = 1
```

This is the central C1-K result:

```text
at-least-once invocation
+
intrinsically idempotent consequence
→ exactly-one semantic world result
```

## History B — crash before consequence

The first recipient receives the same effectId and is SIGKILLed before applying it.

After crash:

```text
world target = absent
```

The exact same recovery retry policy is used. This time `ensure-state` returns `applied`, and the final world contains one exact consequence.

So recovery did not need a different command for “probably applied” versus “probably not applied.” The effect protocol itself made the same retry safe in both states.

## History C — exact state already satisfied

C1-K also starts with the exact desired symlink already present before this request's effect body runs.

The first recipient then dies before applying anything. Recovery retries the same effectId and returns `already-satisfied` without mutation.

For this request:

```text
worldMutationCountByAcceptedEffect = 0
finalSemanticConsequenceCount      = 1
semanticEffectSatisfied            = true
```

This separates two questions:

```text
Did this invocation cause the state?
!=
Is the admitted ensure-state consequence satisfied?
```

For this declarative effect, causal invocation history is not required to verify semantic satisfaction. The independently observable world invariant is the completion criterion.

This does **not** generalize to non-idempotent event effects such as C1-I/J's vanishing pulse.

## What C1-K proves

For this exact local ensure-state effect and tested crash paths, C1-K proves:

- exactly-once invocation is not necessary for exactly-one semantic consequence;
- acknowledgement loss after a committed consequence can be recovered by reissuing the same effectId without creating a second semantic consequence;
- crash before application can use the same retry policy and reach the same exact target state;
- an already-satisfied world requires zero request-owned mutation and still satisfies the effect;
- the consequence itself can provide the repeat-safety boundary without an adjacent dedup/inbox object;
- exact type/value observation is required: same name alone is not enough;
- for a declarative `ensure-state` effect, semantic completion may be defined as independently verified invariant satisfaction rather than proof that one particular invocation executed;
- sender publication, invocation history, world mutation, and semantic satisfaction remain distinct facts;
- neither a generic transaction manager nor a generic causal DAG was forced by this effect.

The useful distinction is:

```text
exactly-once invocation
!=
exactly-one semantic consequence
```

and:

```text
causal execution history
!=
verified invariant satisfaction
```

## What C1-K does not prove

C1-K does not prove:

- that every consequence can be expressed as an idempotent state invariant;
- idempotency for irreversible events, payments, messages, physical actuation, or other consumptive effects;
- generic exactly-once delivery;
- that effect identity alone is sufficient without exact resource/value identity;
- multi-resource atomicity;
- multi-host, partition, quorum, or adversarial-target semantics;
- compensation for non-idempotent effects;
- that transaction semantics are never required.

## Resulting pressure

C1-I/J/K now divide consequence protocols into a clearer hierarchy:

```text
1. observable + idempotent state effect
   → re-observe / retry safely

2. information lost, but downstream repeat-safe
   → retry safely despite uncertain history

3. non-idempotent effect + separate dedup record
   → recipient commit gap remains

4. non-idempotent effect with no atomic/repeat-safe boundary
   → UNKNOWN / transaction / compensation pressure
```

C1-L has now tested a genuinely non-idempotent but compensable local consequence. The original effect duplicated under ACK loss; a distinct compensation repaired the invariant, while blind compensation retry overcompensated. Re-observing the repair invariant safely distinguished compensation-not-yet-applied from compensation-already-applied. See [`COMPENSATION-C1L.md`](COMPENSATION-C1L.md).

The next experiment should remove that surviving observability and ask what compensation requires when repaired and unrepaired histories become indistinguishable after crash.
