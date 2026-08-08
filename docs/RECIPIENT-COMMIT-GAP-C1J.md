---
schema_version: 1
id: security.recipient-commit-gap-c1j
title: Recipient Commit Gap C1-J
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
summary: Physical fault injection proving that ordering a non-idempotent consequence and a separate durable recipient dedup marker cannot provide exactly-once semantics: effect-first duplicates on retry, marker-first can suppress an effect that never happened, and a durable reserved inbox preserves but cannot resolve the same information ambiguity.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.information-loss-c1i
  - security.unpublished-completion-c1h
  - security.law-profiles-c0
---
# Recipient Commit Gap C1-J

## Question

C1-I showed that a stable exact `effectId` plus recipient-owned durable duplicate suppression can make sender retry safe after sender-side acknowledgement loss.

That result left one untested boundary inside the recipient:

```text
irreversible consequence
<->
durable dedup / completion fact
```

C1-J asks whether ordinary ordering of those two independent writes is enough.

It deliberately does not introduce a transaction manager, distributed log, exactly-once framework, or causal DAG before fault injection.

## Exact effect

The experiment remains owned and local:

```text
authorityId = range-authority:c1j-local-recipient-gap
zoneRef     = zone:c1j-local-no-uplink
capability  = local.ephemeral-pulse
effectType  = local.emit-one-ephemeral-pulse
effectId    = range-effect:c1j-recipient-commit-gap-pulse-v1
```

Request digest:

```text
sha256:25301a8b7ae4dfb70cfb54b6a75d6c2ce715f07c8f98b25a52079a6b7b3295e4
```

Admission digest:

```text
sha256:4c187b9620938dcd996fde90c794c98e3073bc2b2f69757bfb7ce19f85361959
```

The consequence is an evaluator-observed non-idempotent vanishing pulse. Every real application adds another pulse, but the pulse leaves no recovery-visible durable world state.

The restricted delivery principal remains UID 65534 and cannot read recipient-private marker state.

## Gap A: consequence before marker

First ordering:

```text
receive effectId
→ emit physical pulse
→ SIGKILL recipient
→ durable marker not written
→ no ACK
```

After the crash:

```text
physical pulses = 1
dedupEffectIds  = []
```

Recovery retries the exact same effectId against a healthy recipient.

Because no marker exists, it is accepted again:

```text
retry ACK          = applied
retry pulses       = 1
total pulse count  = 2
```

So:

```text
effect → crash → marker
```

creates duplicate consequence on retry.

## Gap B: marker before consequence

Reverse the writes:

```text
receive effectId
→ persist dedup marker
→ SIGKILL recipient
→ physical pulse never occurs
→ no ACK
```

After the crash:

```text
physical pulses = 0
dedupEffectIds  = [exact effectId]
```

Recovery retries the same effectId.

The marker suppresses it:

```text
retry ACK          = duplicate-suppressed
retry pulses       = 0
total pulse count  = 0
```

So:

```text
marker → crash → effect
```

can permanently lose the consequence.

Changing write order merely chooses between duplicate risk and loss risk.

## Durable inbox experiment

A reasonable correction is to stop calling a pre-effect record “completed.” C1-J therefore tests a durable inbox with explicit phase:

```text
phase = reserved
```

Two real histories are created.

### History R0 — reserved, effect not executed

```text
persist reserved
→ SIGKILL before pulse
```

Evaluator ground truth:

```text
pulse count = 0
```

### History R1 — reserved, effect executed

```text
persist reserved
→ emit pulse
→ SIGKILL before completed publication
```

Evaluator ground truth:

```text
pulse count = 1
```

Yet both durable inbox files are byte-equivalent:

```text
sha256:107ecb3e4c64ad93a1c8028467f5bf241c7f0c243b6b2c19b55806f1ee56a8d9
```

and both recovery views are byte-equivalent:

```text
phase                       = reserved
completionEvidenceAvailable = false

digest
= sha256:8be64a988cfa78d73c18aaca93e549aa7726f5867c26f82d601671945be38107
```

Therefore `reserved` truthfully records that work was admitted/in-flight, but does not reveal whether the irreversible consequence crossed the commit boundary.

## No universal decision from `reserved`

C1-J physically exercises retry from both `reserved` histories.

```text
R0: 0 prior pulses + retry = 1   correct
R1: 1 prior pulse  + retry = 2   duplicate
```

Suppressing retry has the opposite failure:

```text
R0: suppress → 0 pulses   lost consequence
R1: suppress → 1 pulse    correct
```

The same durable state therefore admits no universally correct binary decision:

```text
retry
or
suppress
```

without another fact or stronger effect semantics.

The correct epistemic interpretation of this `reserved` state is again:

```text
UNKNOWN whether consequence occurred
```

## What C1-J proves

For this exact local non-idempotent consequence and fault model, C1-J proves:

- recipient-side duplicate suppression from C1-I is not generic exactly-once;
- if consequence and dedup/completion publication are independent commit points, `effect → marker` can duplicate after crash and retry;
- reversing the order to `marker → effect` can suppress a consequence that never occurred;
- therefore ordering two independent writes cannot by itself make them one atomic semantic event;
- renaming the first durable write to an honest `reserved` inbox state avoids false completion claims but does not reconstruct the missing history;
- `reserved-before-effect` and `reserved-after-effect` can have byte-identical durable state and recovery views while physical ground truth differs;
- retry from that common state is correct for one history and duplicates the other;
- suppress from that common state is correct for one history and loses the other;
- durable state can preserve uncertainty without eliminating it;
- a generic transaction manager and generic causal DAG are still not justified solely by this consumer, but a stronger atomic or intrinsically idempotent effect boundary is now genuinely pressured.

A concise relation is:

```text
separate consequence commit
+
separate dedup/completion commit
+
crash between them
→ irreducible ambiguity
```

and:

```text
ordering != atomicity
reservation != completion
```

## What C1-J does not prove

C1-J does not prove:

- that a general transaction manager is required;
- that every consequence can participate in an atomic transaction;
- that an intrinsically idempotent downstream operation would fail;
- that compensation cannot be sufficient for some domains;
- that a durable pre-effect inbox is useless; it preserves exact identity and an honest in-flight state, but cannot alone settle post-effect ambiguity;
- multi-host, multi-recipient, partitions, quorum, or adversarial-recipient semantics;
- generic exactly-once delivery;
- generic causal-DAG enforcement;
- external or uncontrolled target authority.

## Next pressure

The next experiment should compare the smallest mechanisms that can actually cross this boundary instead of merely moving it.

Candidate 1 is an **intrinsically idempotent consequence** keyed by exact effect identity: repeated execution must converge physically, not merely be hidden by an adjacent marker.

Candidate 2 is an **atomic local transaction** only where the consequence and completion record genuinely share one transactional substrate.

Candidate 3 is **compensation** for effects that cannot be atomic or idempotent.

A durable inbox should remain because it preserves intent and `UNKNOWN`, but C1-J provides no evidence that adding more inbox phases alone can solve the commit gap.

The next experiment should start with the smallest candidate—intrinsic idempotency—before inventing a generic transaction layer.
