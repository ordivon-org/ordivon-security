---
schema_version: 1
id: security.interrupted-consequence-c1b
title: Interrupted Consequence C1-B
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
summary: Physical proof that owner loss during one admitted consequential Range effect requires durable semantic effect identity in addition to physical resource identity, and that exact effect binding plus durable phase plus independent Host truth can classify two interrupted states without blind replay or a generic causal DAG.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.autonomous-intent-c1a
  - security.executable-authority-c1
  - security.persistent-range-recovery-s6r
  - security.law-profiles-c0
  - security.authority
  - security.evidence
---
# Interrupted Consequence C1-B

## Question

S6-R proved that a new management process can close exact physical Range resources after the original owner dies. C1 and C1-A then added an admitted Actor effect with durable consequences. That creates a different recovery question:

> After an admitted consequential effect has started and its controller disappears, can a new process determine which effect was in flight and what the world has already done, without guessing or blindly replaying the operation?

C1-B deliberately starts with one existing effect:

```text
fabric.replace-peer-a-with-peer-b
```

It does not introduce a generic transaction engine, persistent `RangeSession`, effect DAG, or universal exactly-once framework first.

## Baseline: physical recovery is not semantic recovery

The first physical probe used Security revision:

```text
git:43517b01267711c60444b495bbcea7cbb03a8372
```

The deterministic C1-B owner created the existing actor-authorized S6 world, submitted an admitted `RangeEffectRequest`, bound the backend effect, completed peer A locally to isolate Windows cold-start variance, and was killed with `SIGKILL` at the exact boundary:

```text
request admitted
→ backend request bound
→ peer A removed
→ Host confirms peer A absent
→ topologyPhase = peer-a-removed durably persisted
→ SIGKILL owner
→ peer B has not been created
```

Immediately before death, in-memory Security state retained exact:

```text
requestDigest
admissionDigest
authorityDigest
effectId
actor / authority / zone / capability / effectType
```

The surviving root-owned S6 ledger retained physical state:

```text
topologyPhase       = peer-a-removed
currentPeerAddress  = null
QEMU                = live
swtpm                = live
tcpdump              = live
peer process          = absent
```

Independent Host truth retained the fabric namespace and Windows TAP but no peer namespace.

However, the durable ledger retained none of the effect binding. A new process could therefore answer **what physical resources exist**, but not **which admitted Actor effect caused this intermediate world**.

The existing S6-R reconciler still safely closed the exact physical resources to zero. This is the C1-B baseline falsifier:

> **physical recovery ≠ semantic recovery**

The private baseline receipt is retained outside Git and bound by the C1-B acceptance index.

## Minimal mechanism

The baseline did not justify persisting the whole `RangeSession`. The smallest missing fact was already present in live S6 state: the immutable binding between Security admission and the backend effect.

At revision:

```text
git:dbd6b4c69379980389220001f96f2715de58ae83
```

S6 running-ledger persistence was extended only with deep-copied:

```text
actorReplacementRequest
actorReplacementReceipt
```

The request binding already contains:

```text
requestId
requestDigest
admissionDigest
authorityId
authorityDigest
actorId
zoneRef
capability
effectType
effectId
```

The receipt remains deliberately non-authoritative for consequence:

```text
status = accepted-pending-execution
worldEffectVerified = false
```

The S6 execution-identity revision advances from `4` to `5` because durable recovery semantics changed.

No completion claim, causal graph, or generic transaction state was added.

## Physical acceptance A: interrupted intermediate world

The same exact `after-peer-a-removed-before-peer-b` fault was repeated after the minimal change.

At owner death:

```text
durable effect identity       = present
topologyPhase                 = peer-a-removed
currentPeerAddress            = null
Host fabric namespace         = present
Host peer namespace           = absent
QEMU / swtpm / tcpdump        = live
owner                         = dead
```

The surviving ledger's effect binding exactly matched the in-memory binding recorded at the kill gate, including request, admission, authority, and effect identity. Its backend receipt still did not claim world truth.

A new process could therefore classify the state as:

```text
known admitted effect
+
known intermediate physical phase
+
independent Host world observation
```

rather than as an unexplained network failure.

The existing reconciler was then deliberately used only for the claim it already owns: safe physical closure to zero. C1-B does **not** claim that it can resume the missing suffix and create B.

## Physical acceptance B: effect materialized, completion lost

A second fault point was added without changing production Range semantics. The owner was killed after peer B had been created and `peer-b-present` had been durably persisted, but before the normal world-truth/completion events could be emitted:

```text
request admitted
→ request bound
→ A removed
→ B created
→ peer-b-present durably persisted
→ SIGKILL owner
→ normal completion event is lost
```

The accepted run is bound to Security revision:

```text
git:360673436f23554621cf46b8d7eb1c2ac4aeb743
```

After owner loss the durable ledger retained:

```text
topologyPhase       = peer-b-present
currentPeerAddress  = 10.253.70.4
exact request/effect/admission identity
non-truth backend receipt
```

Independent Host observation simultaneously found:

```text
fabric namespace = present
peer-B namespace = present
bridge ports      = Windows TAP + peer-B veth
peer-B process    = live
```

This establishes a classic response-loss distinction:

> **missing completion event ≠ missing physical consequence**

Replaying the whole A→B effect would be unjustified. The new process has enough evidence to know that the physical target state already exists even though the original controller never emitted its normal completion event.

## Normal-path regression

The final C1-B revision was also run through the ordinary Guest-driven, backend-owned S6 acceptance. It retained the original:

```text
peer-a-present
→ peer-a-removed
→ peer-b-present
```

Host topology history, Guest A/B challenge success, external packet-sensor dual-flow observation, final peer-B truth, one Windows NIC, and clean residual closure all passed.

Persisting Actor effect identity therefore strengthens recovery semantics without replacing or breaking the original S6 progression profile.

## What C1-B proves

For one exact typed effect over the deterministic S6 topology, C1-B proves:

- physical resource identity alone is insufficient to reconstruct the meaning of an interrupted consequential action;
- the original S6-R reconciler can safely close an interrupted world to zero while still lacking semantic knowledge of the admitted effect;
- persisting the exact existing effect binding is sufficient to recover Actor, authority, request, admission, and effect identity after owner loss;
- durable effect identity remains separate from world truth: the persisted backend receipt still says `worldEffectVerified=false`;
- `peer-a-removed` plus Host observation distinguishes a known admitted effect that stopped before B materialization;
- `peer-b-present` plus Host observation distinguishes a physically materialized effect whose completion event was lost;
- neither ambiguous state justifies blindly replaying the whole A→B mutation;
- the normal Guest-driven S6 world still works after this strengthening.

The useful relation for this consumer is:

```text
durable effect identity
+
durable physical phase
+
independent Host truth
→ classify interrupted consequence
→ do not guess or blindly replay
```

## What C1-B does not prove

C1-B does not prove:

- automatic resumption from `peer-a-removed` to peer B;
- exactly-once execution across arbitrary effects;
- crash safety at every instruction inside peer-B materialization;
- recovery when multiple consequential effects overlap on the same resources;
- durable resurrection of the entire `RangeSession` event stream;
- that `RangeEvent.causalParents` is unnecessary in general;
- external/Internet authority or uncontrolled targets.

The current S6-R reconciler still chooses safe closure to zero after owner loss. C1-B recovers semantic identity before that closure; it does not silently turn cleanup into continuation.

## Causality result

C1-B was intentionally expected to pressure `RangeEvent.causalParents`. It did not yet do so.

For this single effect, exclusive deterministic topology and exact effect identity made the relevant causal question answerable without a generic DAG:

```text
Which admitted effect was in flight?
→ exact durable effect binding

How far did the physical world get?
→ durable topology phase + independent Host truth
```

This is evidence against prematurely enforcing parent existence/order/acyclicity merely for API completeness. It is **not** evidence that causal graphs will never be needed. Concurrent effects, shared resources, cross-Agent causation, retries, compensation, or effects whose physical state cannot uniquely identify progress may create a real causal consumer later.

## Resulting pressure

The next unresolved boundary is no longer “can we remember which effect this was?” It is **partial materialization inside one physical substep**.

A stronger experiment would interrupt peer-B creation after only some owned resources exist—for example after namespace or veth creation but before the complete `peer-b-present` state is durably established. A replacement process must then decide from exact effect identity plus observed resources whether to:

```text
finish the suffix
repair a partial materialization
abort and compensate
or close to zero
```

Only that pressure can tell us whether we need an idempotent effect-suffix protocol, finer durable substep identity, compensation semantics, or stronger causal structure. C1-B does not prebuild them.
