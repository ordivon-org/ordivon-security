---
schema_version: 1
id: security.compensation-information-loss-c1m
title: Compensation Information Loss C1-M
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-08
summary: Physical dual-history proof that compensation-applied and compensation-not-applied worlds can be indistinguishable to the recovery caller when downstream repair truth is private; naive retry is unsound, while a distinctly identified downstream idempotent compensation contract safely converges both hidden histories without granting caller read authority or adding a sidecar receipt.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.compensation-c1l
  - security.information-loss-c1i
  - security.law-profiles-c0
---
# Compensation Information Loss C1-M

## Question

C1-L made compensation recoverable because the caller could independently observe whether the repair had happened:

```text
balance 2 → needs compensation
balance 1 → already repaired
```

C1-M removes that observation authority.

The downstream balance remains real and durable, but it is recipient-private. The recovery caller can invoke the compensation capability while being physically unable to read the balance.

The question is:

> What happens when compensation-applied and compensation-not-applied histories become indistinguishable to the caller?

## Authority boundary

The recovery principal runs as UID 65534.

The downstream private world is root-owned and contains exactly one consequence-state object:

```text
balance.json
```

No adjacent compensation receipt, dedup file, inbox, or transaction record exists in that world.

Physical permission probes prove UID 65534 cannot read `balance.json`, while the same principal can invoke the public local Unix-domain compensation capability.

This creates a deliberate authority split:

```text
caller can act
!=
caller can inspect callee-private truth
```

## Baseline protocol — non-idempotent compensation

The baseline compensation is explicitly identified as a non-repeat-safe protocol:

```text
compensationEffectId
= range-effect:c1m-naive-private-compensation-v1

capability
= private-counter.subtract-one

effectType
= private-counter.subtract-one

retrySemantics
= non-idempotent-subtract-one
```

Request digest:

```text
sha256:a888c967b680b8eccedf418ea03bc70e653e3c49cbb291df66f36383e94ad357
```

Admission digest:

```text
sha256:dbbeb88d9e8e5017c36732991124f2c55e1dbbe05ac9a22168dd05e9f97782b6
```

Each history first physically creates the same duplicate consequence:

```text
0 → original +1 → 1 → original +1 → 2
```

### History A — compensation happened

```text
private balance = 2
→ compensation -1
→ private balance = 1
→ recipient SIGKILL before ACK
```

### History B — compensation did not happen

```text
private balance = 2
→ recipient SIGKILL before compensation
→ private balance = 2
```

Evaluator truth therefore differs:

```text
A = repaired balance 1
B = unrepaired balance 2
```

But the two durable sender ledgers are byte-equivalent:

```text
sha256:c0f7551b7a6f9ac1c70af9f8cbc64fddaed1aca21bda3469e93743c526dfc38e
```

and the caller-visible recovery views are byte-equivalent:

```text
sha256:485509bf26a8527f77c59edd06a37b0241f96ec39f4c2ce259ebddf9a6285704
```

Both views contain:

```text
completionPublished          = false
controllerAlive              = false
recipientProcessAlive        = false
recipientSocketPresent       = false
compensationEvidenceAvailable = false
recipientPrivateStateVisible = false
```

Both classify:

```text
status = unknown
reason = compensation-history-not-observable
blindCompensationAuthorized = false
```

This is the same information law seen in C1-I, now applied to compensation.

## Blind retry falsifier

C1-M deliberately ignores that `UNKNOWN` result and blindly replays the naive compensation.

Results:

```text
already-repaired hidden history:
  1 → 0
  overcompensated

unrepaired hidden history:
  2 → 1
  correctly repaired
```

Therefore the same caller-visible state plus the same naive retry produces different correctness.

The caller cannot infer which history it is in, so blind compensation remains unsound.

## Candidate protocol — downstream idempotent compensation

C1-M then changes the compensation protocol explicitly rather than silently changing implementation semantics.

The repeat-safe protocol has a distinct identity:

```text
compensationEffectId
= range-effect:c1m-idempotent-private-compensation-v1

capability
= private-counter.ensure-repaired

effectType
= private-counter.ensure-repaired

retrySemantics
= convergent-repair-duplicate
```

Request digest:

```text
sha256:8718a1a25ca1058edabafd356e504bd4af90b88125b60229f01bc8c96771506f
```

Admission digest:

```text
sha256:1402b3b703bbeeea6f30f4da172fbf6a6338d162c38d2a0ed5c6034f6e1dbfd4
```

The downstream contract is:

```text
private balance == 2
→ set exact repaired state 1
→ applied

private balance == 1
→ no mutation
→ already-repaired

anything else
→ conflict
```

The caller still cannot read the private balance.

## Same uncertainty, safe operation

C1-M repeats the same two crash histories under the new protocol.

Within the idempotent protocol, compensated and uncompensated histories again have byte-equivalent sender ledgers:

```text
sha256:311ce5706376e8438d60f96ba4df76da3f9e72450cecde2664fb125d97cd044d
```

and byte-equivalent caller recovery views:

```text
sha256:f038637698fe7108075f397806b8e4581548f74d2858d88220a981fc06aeb0e1
```

The caller therefore still does **not** learn whether compensation happened.

Yet retrying the explicitly repeat-safe compensation protocol is sound:

```text
hidden repaired history:
  private balance 1
  → already-repaired
  → no mutation
  → final 1

hidden unrepaired history:
  private balance 2
  → applied
  → final 1
```

Both ACKs report `semanticRepairSatisfied=true`.

So historical uncertainty remains while operational safety is restored.

## What C1-M proves

For this exact local private-world compensation boundary, C1-M proves:

- compensation-applied and compensation-not-applied histories can be information-theoretically indistinguishable to the caller;
- caller authority to invoke compensation does not imply authority to read downstream repair truth;
- when those histories expose the same admissible evidence, the caller's historical classification must remain `UNKNOWN`;
- naive non-idempotent compensation is unsafe to replay from that `UNKNOWN` state;
- an explicitly distinct downstream idempotent compensation protocol can safely converge both hidden histories;
- the caller does not need historical certainty to retry a contract whose repeat safety is part of the effect semantics;
- the caller does not need read authority over recipient-private state when the recipient itself owns the repeat-safe state transition;
- all four private worlds physically contain only `balance.json`; no sidecar compensation receipt or dedup object was used;
- protocol identity must distinguish non-repeat-safe and repeat-safe compensation semantics;
- a durable caller-visible compensation receipt and a shared atomic transaction boundary were not forced by this candidate.

The central distinctions are:

```text
caller UNKNOWN
!=
downstream unsafe
```

and:

```text
private truth unavailable to caller
!=
private truth unavailable to the authority that owns the effect
```

and:

```text
retry semantics are part of effect identity
```

## What C1-M does not prove

C1-M does not prove:

- safety if downstream private consequence state is lost, corrupted, forked, or partitioned;
- that every compensation can be expressed as an idempotent convergent repair;
- multi-resource or cross-party compensation;
- concurrent compensation races;
- generic exactly-once delivery;
- generic saga semantics;
- that durable compensation receipts are never useful;
- that shared transactions are never required.

## Resulting boundary

C1-L and C1-M together separate two cases:

```text
repair truth visible to caller
→ caller re-observes and chooses compensate vs publication-only

repair truth private to callee
→ caller may remain UNKNOWN
→ safe retry depends on the downstream effect contract
```

This suggests a more general Agent-first rule:

> Do not demand global visibility of every truth. Put retry safety at the authority boundary that actually owns the consequence whenever that boundary can enforce it.

C1-N has now destroyed, corrupted, and forked the callee-private predicate truth. The unchanged `ensure-repaired` effect fails closed with zero mutation when even the owning authority cannot establish its predicate. A distinct digest-bound state witness outside that private boundary restores the exact state in the tested static faults, after which the original compensation semantics work again. See [`DOWNSTREAM-TRUTH-FAILURE-C1N.md`](DOWNSTREAM-TRUTH-FAILURE-C1N.md).

The next pressure is witness freshness: fault the ordering between consequence-state changes and witness publication so a digest-valid witness can be stale. Only then can generation, atomic publication, or stronger coordination be justified.

## Post-closeout executable standing — 2026-08-28

C1-M's canonical result and acceptance evidence remain current research standing. Its one-shot local fault runner `cli_compensation_information_loss_acceptance.py` is retained under `fixtures/archive/runners/` rather than the current `ordivon_security` package. No installed command, current source consumer, research/script consumer, or exact documentation invocation requires the runner in the live package; the remaining unit test exercised only runner-local fixtures/classifiers. The accepted apparatus is source-fenced at `404e7e691fd2ed6e557ad525c9ff0b63c8aceedd` and may be restored explicitly for reproduction or a new experiment. Archiving the runner does not promote its local protocol mechanics into a general Security service.
