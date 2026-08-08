---
schema_version: 1
id: security.information-loss-c1i
title: Information Loss C1-I
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - evaluator
  - agent
updated: 2026-08-08
summary: Physical dual-history proof that delivered and undelivered non-idempotent consequences can converge to the same recoverable sender state, forcing UNKNOWN when completion evidence is destroyed; recipient-side durable effect identity then proves safe same-effect retry without granting the successor access to recipient-private state.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-recovery
related:
  - security.unpublished-completion-c1h
  - security.world-entity-migration-recovery
  - security.law-profiles-c0
---
# Information Loss C1-I

## Question

C1-H recovered a completed-but-unpublished effect because enough consequence truth remained observable in persistent topology, Guest result, and packet evidence.

C1-I removes that advantage.

It asks:

> If a consequence happened but all completion evidence available to the recovery principal disappears, can recovery still infer the past from durable sender state and current world observation?

The experiment does not add sender completion receipts, a transaction log, a generic exactly-once layer, or a causal DAG first.

## Physical effect

C1-I uses an owned local Unix-domain capability endpoint with no IP network and no external target.

The exact admitted effect is:

```text
authorityId = range-authority:c1i-local-vanishing-consequence
zoneRef     = zone:c1i-local-no-uplink
capability  = local.ephemeral-pulse
effectType  = local.emit-one-ephemeral-pulse
effectId    = range-effect:c1i-vanishing-pulse-v1
```

The pulse is intentionally non-idempotent: every accepted delivery emits another evaluator-observable pulse. The pulse itself leaves no recovery-visible persistent world state.

Request and admission identity:

```text
requestDigest
= sha256:c82056cc62c0f299fd9206bff1de037465ecbded878be94dfc65b3537a5891b9

admissionDigest
= sha256:4496e438ef20a3f98f5e4e61e9c64efab6d0c0f7b6c713c4b2f01716eb4d2f93
```

## Baseline: two different histories, one recoverable state

C1-I physically executes two histories.

### Delivered history

```text
same admitted sender ledger
→ controller sends exact effectId
→ recipient emits pulse
→ recipient returns transient ACK=applied
→ controller receives ACK in memory
→ controller SIGKILL before durable acknowledgement publication
→ recipient is closed
→ Unix socket is removed
```

Evaluator-only oracle proves one pulse occurred before controller loss.

### Undelivered history

```text
same admitted sender ledger
→ controller SIGKILL before send
→ recipient is closed
→ Unix socket is removed
```

Evaluator-only oracle proves zero pulses occurred before controller loss.

The evaluator oracle exists only to establish experimental ground truth. It is not included in the successor's authority or observation.

## Byte-equivalent recovery facts

After the transient recipient world is closed, the two sender ledger files are byte-identical:

```text
sha256:208cb48c1c39f1267385f2245a536e4174f2a8c3c1fa707689d67ac3e30050d0
```

The successor re-reads that durable ledger from disk after the crash. Its recoverable view is also identical in both histories:

```text
completionPublished          = false
controllerAlive              = false
recipientProcessAlive        = false
recipientSocketPresent       = false
completionEvidenceAvailable  = false
recipientInternalStateVisible = false
senderState                  = admitted-pending-acknowledgement
```

Successor-view digest in both histories:

```text
sha256:7d2abd6480fc8d112b63f385d5257541d0c20a8ea6ec5b59271aabcce1d0b2cc
```

Yet evaluator ground truth differs:

```text
History A = one pulse delivered
History B = zero pulses delivered
```

Therefore no recovery rule that consumes only this view can know which history occurred.

The accepted classifier returns in both cases:

```text
status                         = unknown
reason                         = delivery-history-not-observable
blindResendAuthorized          = false
completionPublicationAuthorized = false
```

This is not a conservative preference. It is the only sound epistemic classification under the declared evidence boundary.

## Blind replay falsifier

C1-I then deliberately performs the action that the accepted recovery rule refuses.

A restricted recovery principal runs as UID 65534 and blindly resends the same exact effectId to a fresh non-idempotent recipient.

Results:

```text
previously delivered history:
  initial pulses = 1
  replay pulses  = 1
  total pulses   = 2

previously undelivered history:
  initial pulses = 0
  replay pulses  = 1
  total pulses   = 1
```

So:

```text
same recovery view
+
same blind resend
→ different semantic correctness
```

Blind retry is therefore not a valid repair for missing information when the downstream consequence is non-idempotent.

## Minimal candidate: recipient-side durable effect identity

The second half of C1-I does not make the sender know the lost history. Instead it changes the recipient protocol.

The recipient now owns a durable private record:

```text
appliedEffectIds
applicationCount
```

keyed by the exact `effectId`.

The sender-facing ledger and successor view remain byte-equivalent between delivered and undelivered histories. The recipient-private record is intentionally outside the successor's read authority.

This is physically checked, not merely declared:

```text
restricted successor UID = 65534
read recipient-private state → denied
stdout bytes                 = 0
```

The same restricted principal still has the public capability to resend to the Unix-domain delivery endpoint.

### Delivered-before-crash history

Recipient-private state already contains the effectId. On recovery resend:

```text
ACK = duplicate-suppressed
applicationCount remains 1
```

### Undelivered-before-crash history

Recipient-private state does not contain the effectId. On recovery resend:

```text
ACK = applied
applicationCount becomes 1
```

Both histories therefore converge to:

```text
appliedEffectIds = [range-effect:c1i-vanishing-pulse-v1]
applicationCount = 1
```

and both recovery resends produce an acknowledgement sufficient for the sender to publish semantic completion.

The successor still did not learn which pre-crash history occurred.

It gained something different:

```text
safe continuation without historical certainty
```

## What C1-I proves

For this exact single-host, local no-uplink fault model, C1-I proves:

- a delivered and undelivered non-idempotent consequence can converge to byte-identical recoverable sender state and current sender-visible world facts;
- when those available facts are identical, recovery cannot infer the lost history and must preserve `UNKNOWN` rather than manufacture certainty;
- recovery authority does not create missing information;
- blind resend over a non-idempotent recipient is unsafe: the delivered history duplicates the consequence while the undelivered history applies it once;
- a stable exact effect identity plus recipient-owned durable duplicate suppression can make retry safe even while the sender remains unable to inspect recipient-private state;
- the recovery principal can be physically denied recipient-state reads while still retaining the capability to resend the same effectId;
- recipient ACK on both first application and duplicate suppression lets both ambiguous histories converge to one observed application and then publish sender completion;
- a sender-side durable completion receipt is therefore not the only mechanism capable of resolving this fault class;
- no generic transaction manager, sender exactly-once framework, or causal DAG was forced.

The new distinction is:

```text
Epistemic recovery:
  Can I know what happened?

Operational recovery:
  Can I act safely despite not knowing what happened?
```

C1-I baseline answers the first with `UNKNOWN`.

Recipient idempotency answers the second with safe same-effect retry.

## Resulting law pressure

The evidence supports two sharper recovery rules.

### Information cannot be recovered by authority

```text
same admissible evidence
+
different true histories
→ UNKNOWN
```

A stronger recovery role, lock, lease, or grant cannot reconstruct information that is absent from its observation boundary.

### Replay safety belongs to the effect protocol

```text
retry permission
!=
proof of non-delivery
```

Retry is sound only when the effect/recipient contract makes repeated delivery safe or when independent evidence establishes that delivery did not occur.

## What C1-I does not prove

C1-I does not prove:

- generic exactly-once delivery;
- that recipient-side deduplication is always available or desirable;
- that sender-side completion receipts are unnecessary in other protocols;
- atomicity between a real irreversible consequence and the recipient's durable dedup record;
- safety if the recipient crashes after emitting the consequence but before recording the effectId;
- safety if recipient dedup state is lost, corrupted, forked, or partitioned;
- multi-recipient, multi-host, quorum, or shared-resource semantics;
- adversarial recipient behavior;
- generic `RangeEvent.causalParents` enforcement;
- external or uncontrolled target authority.

The accepted recipient implementation records the effectId/application count before returning the acknowledgement. C1-I has not yet injected failure between the real consequence and that durable recipient record.

## Next pressure

The next useful experiment is the **recipient commit gap**.

Construct a recipient where:

```text
physical consequence occurs
↓
💥 recipient/controller loss
↓
durable dedup/effect record not yet committed
```

Then retry the same effectId.

If that produces a duplicate, C1-I has not solved exactly-once; it has merely moved the ambiguity from the sender to the recipient.

That experiment should determine whether the unavoidable primitive is:

- atomic consequence + dedup commit inside one recipient transaction;
- an intrinsically idempotent downstream effect;
- a durable recipient-side inbox/effect record established before the irreversible consequence;
- compensation semantics;
- or explicit `UNKNOWN` when the recipient itself loses the commit boundary.

Only that fault should decide whether a stronger transaction-like abstraction is actually required.
