---
schema_version: 1
id: security.compensation-c1l
title: Compensation C1-L
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-08
summary: Physical proof that a non-idempotent duplicated consequence can be repaired by a distinct compensation effect without a generic transaction manager when the repair invariant remains independently observable; blind compensation retry overcompensates, while post-crash re-observation distinguishes needs-compensation from already-repaired.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.intrinsic-idempotency-c1k
  - security.recipient-commit-gap-c1j
  - security.law-profiles-c0
---
# Compensation C1-L

## Question

C1-K showed that an intrinsically idempotent `ensure-state` consequence can tolerate repeated invocation without exactly-once delivery.

C1-L moves back to a genuinely non-idempotent effect:

```text
initial balance = 0
original effect = +1
desired semantic result = 1
```

Applying the effect twice produces a different world:

```text
0 → 1 → 2
```

The experiment asks:

> Can a distinct compensation effect restore the declared invariant after duplicate execution, and what happens when the compensation itself loses acknowledgement?

No transaction manager, compensation journal, generic saga framework, or causal DAG is introduced first.

## Exact identities

Original effect:

```text
authorityId = range-authority:c1l-local-compensable-world
zoneRef     = zone:c1l-local-no-uplink
capability  = counter.increment-one
effectType  = counter.add-one
effectId    = range-effect:c1l-non-idempotent-increment-v1
delta       = +1
desiredBalance = 1
```

Request digest:

```text
sha256:f05df3307a862b66988e15ad4ff7573a24fe66d5db6b9e42985363271515e3c0
```

Admission digest:

```text
sha256:31f9476f492b745a841d302c483d6b446ab49201f1482acd04983543db6ffb9a
```

Compensation is a separate effect identity:

```text
compensationEffectId = range-effect:c1l-compensate-duplicate-increment-v1
compensatesEffectId  = range-effect:c1l-non-idempotent-increment-v1
capability           = counter.compensate-duplicate
effectType           = counter.subtract-one-duplicate
duplicateBalance     = 2
repairedBalance      = 1
```

Compensation repairs the world. It does not rewrite or erase the fact that the original effect was executed twice.

## Duplicate baseline

Every C1-L recovery history first reproduces the same original fault:

```text
balance = 0
→ original +1
→ recipient SIGKILL after effect, before ACK
→ balance = 1
→ sender cannot distinguish delivery from ACK loss and retries
→ original +1 again
→ balance = 2
```

The durable sender ledger remains unchanged across the duplicate:

```text
sha256:c6a2524494b6c1b235498f7ffa1ac50b638b7193d4e585204ba65060cc9ea951
```

So C1-L begins from a real duplicated non-idempotent consequence, not from a synthetic preloaded state.

## Falsifier: compensation is not automatically retry-safe

The smallest compensation is also non-idempotent:

```text
balance -= 1
```

From the duplicate state:

```text
2
→ compensation -1
→ 1
→ SIGKILL before ACK
```

The declared invariant is now restored, but acknowledgement is missing.

If recovery blindly retries compensation:

```text
1
→ compensation -1 again
→ 0
```

This physically overcompensates.

Therefore:

```text
Compensation
!=
blind-retry safety
```

and a compensation effect has its own recovery semantics.

## Accepted recovery: re-observe before compensating

C1-L does not deliberately ignore world truth merely to force a stronger mechanism. The balance remains independently observable, so the accepted recovery rule is:

```text
balance == 2
→ exact duplicate is still present
→ needs-compensation
→ compensation authorized

balance == 1
→ repair invariant already holds
→ already-repaired
→ compensation forbidden
→ repair publication authorized

anything else
→ unexpected-world-state
→ no compensation
→ no completion publication
```

This also prevents compensation from becoming a hidden alternate path for the original effect. In particular:

```text
balance == 0
```

is not repaired by compensation into `1`; it fails closed.

## Compensation crash before application

Start from the real duplicate state `2`.

The compensation worker receives the exact compensation effectId and is SIGKILLed before mutating the world.

Post-crash truth:

```text
balance = 2
```

Fresh recovery re-observes and classifies:

```text
status                  = needs-compensation
compensationAuthorized  = true
repairPublication       = false
```

It then executes compensation once:

```text
2 → 1
```

The declared invariant is restored.

## Compensation applied, ACK lost

Again start from duplicate state `2`.

This time compensation executes:

```text
2 → 1
```

and the worker is SIGKILLed before ACK.

Fresh recovery observes:

```text
balance = 1
```

and classifies:

```text
status                       = already-repaired
compensationAuthorized       = false
repairPublicationAuthorized  = true
```

No second decrement is executed. Recovery repairs only the semantic publication of compensation completion.

So the accepted paths are:

```text
crash before compensation
→ observe 2
→ compensate
→ 1

crash after compensation before ACK
→ observe 1
→ do not compensate
→ publish repaired
```

## What C1-L proves

For this exact local compensable effect and fault model, C1-L proves:

- a genuinely non-idempotent original effect can duplicate under acknowledgement loss;
- a distinct compensation effect can restore the declared world invariant after that duplicate;
- compensation identity and original effect identity must remain distinct;
- compensation repairs current world state but does not erase the historical duplicate;
- blind retry of a non-idempotent compensation is unsafe and can overcompensate;
- when the repair invariant remains independently observable, compensation progress can be reclassified after crash without exactly-once compensation invocation;
- crash-before-compensation is distinguishable from crash-after-compensation because world truth remains `2` versus `1`;
- publication-only recovery is sufficient after compensation has already restored the invariant;
- compensation should be authorized only from the exact compensable state, not from arbitrary nearby states;
- a generic transaction manager, generic saga framework, or generic causal DAG is still not forced by this consumer.

The new distinction is:

```text
Compensation repairs state
!=
Compensation rewrites history
```

and:

```text
Compensable
!=
blindly replayable compensation
```

## What C1-L does not prove

C1-L does not prove:

- compensation when the repaired world state is not independently observable;
- compensation for irreversible external events whose effects cannot be reversed or measured exactly;
- compensation across multiple resources or multiple parties;
- concurrent compensation races;
- compensation when `2 → 1` itself is only partially materialized;
- generic saga semantics;
- generic exactly-once delivery;
- that transactions are never required.

## Resulting boundary

C1-I through C1-L now expose four materially different recovery tools:

```text
Re-observation
  when consequence truth survives

Intrinsic idempotency
  when retry itself converges

Compensation
  when a wrong-but-observable world can be repaired

UNKNOWN
  when evidence is gone and neither retry nor repair is sound
```

A transaction is not yet the universal answer.

C1-M has now removed caller observability of compensation progress. Repaired and unrepaired downstream-private histories became byte-indistinguishable to the caller and therefore remained historically `UNKNOWN`; naive replay was unsound. A distinctly identified downstream `ensure-repaired` compensation contract nevertheless made retry converge safely in both hidden histories without caller read authority or a sidecar receipt. See [`COMPENSATION-INFORMATION-LOSS-C1M.md`](COMPENSATION-INFORMATION-LOSS-C1M.md).

The next pressure moves inside the owning boundary: destroy, corrupt, fork, or otherwise invalidate the downstream private truth that makes the convergent repair decision possible. Only then should stronger external evidence, atomicity, or distributed coordination be considered.
