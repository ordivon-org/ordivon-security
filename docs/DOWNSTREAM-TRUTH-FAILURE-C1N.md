---
schema_version: 1
id: security.downstream-truth-failure-c1n
title: Downstream Truth Failure C1-N
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-08
summary: Physical proof that an idempotent downstream compensation contract still depends on trustworthy local predicate truth: missing, corrupt, and forked truth force zero-mutation fail-closed recovery. A digest-bound state witness outside the private truth boundary can restore this static fault model, while a tampered witness is rejected; witness freshness and publication atomicity remain unproved.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.compensation-information-loss-c1m
  - security.law-profiles-c0
---
# Downstream Truth Failure C1-N

## Question

C1-M proved that caller historical uncertainty does not prevent safe retry when the downstream authority still owns trustworthy private truth and exposes an explicitly repeat-safe `ensure-repaired` contract.

C1-N removes that final assumption:

> What if the authority that owns the consequence can no longer establish its own predicate truth?

The same C1-M compensation identity is preserved:

```text
compensationEffectId = range-effect:c1m-idempotent-private-compensation-v1
capability           = private-counter.ensure-repaired
retrySemantics       = convergent-repair-duplicate
```

No new transaction manager or generic replication layer is added first.

## Truth-failure histories

For each fault, C1-N starts two histories with different real pre-fault truth:

```text
repaired   = balance 1
unrepaired = balance 2
```

Then the downstream truth is physically transformed so the owning authority itself can no longer distinguish those histories.

### Missing

Both canonical `balance.json` objects are deleted.

The two post-fault authority observations are identical:

```text
status = missing
reason = canonical-truth-absent
```

### Corrupt

Both canonical truth objects are replaced with the same malformed bytes.

The two authority observations are identical:

```text
status = corrupt
reason = invalid-json
```

### Fork

The canonical object is removed and two exact valid candidates are presented:

```text
candidate-a = balance 1
candidate-b = balance 2
```

The two authority observations are identical:

```text
status = fork-conflict
reason = multiple-authoritative-candidates-disagree
```

The authority has valid data, but no valid lineage fact selecting one candidate.

## Idempotency does not manufacture truth

For all six histories, invoking the unchanged `ensure-repaired` contract without additional evidence performs **zero mutation**.

Missing/corrupt return:

```text
status = truth-unavailable
```

Fork returns:

```text
status = truth-conflict
```

For every case:

```text
treeDigestBefore == treeDigestAfter
worldMutated = false
```

Therefore:

```text
repeat-safe transition
+
untrustworthy predicate state
!=
safe recovery
```

Idempotency can make a known state transition repeat-safe. It cannot tell the authority which state is true when its own predicate substrate is missing, malformed, or forked.

## Minimal candidate: sealed state witness

C1-N next tests a smaller mechanism than transactions: a digest-bound state witness located **outside the downstream private truth boundary**, but still on the same Host/state-root fault domain.

The witness binds:

```text
truthRecoveryId
lineage
exact state object
stateDigest
witnessDigest
```

It is not a compensation completion receipt. It is a sealed copy of the last exact authoritative consequence state available before the targeted private-truth fault.

Truth recovery has its own identity:

```text
truth-recovery:c1n-sealed-state-witness-v1
```

and remains distinct from the C1-M compensation effect identity.

### Recovery

For missing, corrupt, and forked truth:

```text
verify witness identity + digest + state digest + lineage
→ restore exact local predicate state
→ run original ensure-repaired
```

Results are preserved across all three fault classes:

```text
pre-fault repaired 1
→ witness restores 1
→ ensure-repaired = already-repaired
→ final 1

pre-fault unrepaired 2
→ witness restores 2
→ ensure-repaired = applied
→ final 1
```

So the witness does not collapse repaired and unrepaired history. It restores the missing truth needed for the original compensation semantics to classify correctly.

A deliberately tampered witness is rejected:

```text
status = invalid-witness
worldMutated = false
local truth remains missing
```

## What C1-N proves

For this exact single-host static fault model, C1-N proves:

- downstream idempotency still requires a trustworthy predicate substrate;
- missing local truth is not safe to infer;
- malformed local truth is not safe to infer;
- two valid but conflicting candidates without lineage authority are not safe to choose between;
- the owning authority must fail closed when it cannot establish the predicate required by its repeat-safe effect;
- a distinct digest-bound state witness outside that private truth boundary can restore exact state after the targeted missing/corrupt/fork faults tested here;
- after truth restoration, the unchanged C1-M compensation effect again distinguishes `already-repaired` from `applied` correctly;
- witness integrity is part of admission: tampered witness data cannot become recovery truth;
- a generic transaction manager or shared atomic boundary is still not forced by these static faults.

The central law is:

```text
Idempotency requires truth.
```

More precisely:

```text
repeat-safe effect semantics
+
authoritative predicate truth
→ safe convergence
```

not:

```text
repeat-safe effect semantics
→ reconstruct missing truth
```

## What C1-N does not prove

C1-N does not prove:

- witness freshness;
- atomic publication between consequence state and witness state;
- an independent disk/node/failure domain for the witness;
- safety when both private truth and witness are lost;
- authenticity against a malicious writer with authority to forge a new valid witness;
- multi-node quorum or consensus semantics;
- concurrent writers or dynamic partitions;
- generic exactly-once, saga, or transaction semantics.

The witness is outside the downstream private truth boundary, but it remains on the same Host/state-root substrate in this experiment.

## Next pressure

C1-N now makes the next experiment precise: **witness freshness / publication gap**.

Fault the ordering between:

```text
consequence state changes
↔
witness publication
```

and create histories where a valid witness is stale relative to the real consequence. If a digest-valid but stale witness can restore the wrong semantic state, integrity alone is insufficient and generation/freshness/atomic publication pressure becomes real.

Only after that experiment should a transaction-like boundary be considered.
