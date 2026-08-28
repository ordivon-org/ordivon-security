---
schema_version: 1
id: security.executable-authority-c1
title: Executable Range Authority C1
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
summary: First physical proof that a persistent Range effect can remain inert until an Actor request is admitted by exact zone/capability RangeAuthority, then execute without conflating receipt with world truth.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.law-profiles-c0
  - security.range-session-s0
  - security.topology-churn-s6
  - security.persistent-range-recovery-s6r
  - security.authority
  - security.evidence
---
# Executable Range Authority C1

## Question

C0 classified `RangeAuthority` as constitutional intent rather than an action menu, but the active code still treated zone/capability grants as descriptive data. C1 asks one narrower question:

> Can one persistent physical Range effect stay inert until an Actor request is admitted by exact authority, while preserving intent, admission, effect receipt, and independent world consequence as different facts?

C1 does not try to design a generic action framework. It reuses the already accepted S6 peer-A to peer-B topology mutation.

## Exact experiment

The C1 profile keeps the S6 physical world:

```text
Windows Guest 10.253.70.2
        │
   isolated L2
        │
peer A 10.253.70.3
        ↓
peer B 10.253.70.4
```

The one declared Actor receives one authority:

```text
actor:c1-fabric-controller
  authority: range-authority:c1-fabric-controller
  zone:      zone:s6-fabric
  capability:fabric.peer-replacement
```

The only C1 physical effect consumer is:

```text
fabric.replace-peer-a-with-peer-b
```

This is a typed experiment profile. It is not a universal `RangeAction` catalog and does not expose shell execution.

## Law path

C1 adds two thin records:

- `RangeEffectRequest` — Actor intent plus exact authority, zone, capability, effect type, and payload;
- `RangeEffectAdmission` — Security's decision bound to request digest and exact authority digest.

`RangeSession.admit_effect()` checks Actor membership, exact authority identity, authority ownership, zone membership, and capability membership. It records `actor.effect-requested` on the contested plane and `effect.admitted` or `effect.rejected` on the management plane. It does not execute a backend effect.

Exact replay of the same request identity and bytes converges to the previous admission without another event. Reuse of one request identity with changed content fails closed.

The S6 backend's `actor-authorized` profile separately consumes an admitted effect only when zone, capability, and effect type match the one physical operation it implements. Its receipt is intentionally:

```text
accepted-pending-execution
worldEffectVerified = false
```

The receipt proves only that the backend bound the request. Host Linux netlink/bridge observations remain the authority for topology consequence.

## Physical acceptance

Accepted implementation:

```text
git:49f1aa976cd3b78076f97f78accd921870b0ac02
```

The accepted C1 run reached `peerAExitCode=0` while the backend was in `actor-authorized` mode. Before valid authority:

```text
topologyChurnCompleted = false
actorReplacementRequest = null
fabricTruth.phase = peer-a-present
fabricTruth.currentPeerAddress = 10.253.70.3
```

Three requests were rejected without changing the world:

| Request defect | Admission |
|---|---|
| nonexistent authority | `unknown-authority` |
| wrong zone | `zone-not-granted` |
| wrong capability | `capability-not-granted` |

The valid request used `zone:s6-fabric`, `fabric.peer-replacement`, and `fabric.replace-peer-a-with-peer-b`. The backend bound effect identity `range-effect:96c717377b7e9e6db289811b`, returned a non-truth receipt, and the existing S6 physical mechanism then produced independent topology truth:

```text
peer-a-present  10.253.70.3
peer-a-removed  null
peer-b-present  10.253.70.4
```

The maintained Windows Guest completed both peer challenges, external tcpdump observed both flows, final current truth pointed to peer B, and machine plus fabric destruction reported zero declared residuals.

The private accepted receipt is retained outside Git and bound by [`../evidence/acceptance/c1-executable-range-authority-49f1aa9.json`](../evidence/acceptance/c1-executable-range-authority-49f1aa9.json).

The C1 authority/effect contracts, actor-authorized S6 Range behavior and later C1-A+ fault programme remain current. On 2026-08-28 the one-shot `cli_windows_kvm_c1_acceptance.py` physical orchestration was retired after its only surviving shared state predicates moved into neutral Windows-KVM acceptance support. The accepted C1 trial remains recoverable from its bound `49f1aa9` revision; current Security code does not need the historical orchestration module in order to retain or apply the C1 authority laws.

## S6 regression

The same implementation was rerun with the default `backend-owned` S6 profile. It passed replacement start/completion, A-removed/B-present Host truth, Guest and tcpdump dual-flow observations, peer-B current truth, and residual closure. C1 therefore adds a second trigger profile without replacing S6 semantics.

## Falsifier retained

The first physical C1 invocation failed before `RangeSession.start()`: its state root was created mode `0700`, so the `qemu`-owned `swtpm` process could not traverse the experiment root. Historical S6 roots are traversable while `/var/lib/ordivon/security` grants `qemu` execute-only ACL access.

That failed receipt is retained as experiment-setup evidence. It contains no admission and proves nothing about C1 authority semantics. The corrected run used a fresh state root matching the accepted S6 traversal contract; no Security law was loosened.

## What C1 proves

For one physical effect, C1 proves:

- a successful physical precondition is insufficient to mutate the world without required Actor authority;
- fake authority, wrong zone, and wrong capability fail before physical mutation;
- exact request and backend-request replay converge without duplicate mutation requests;
- Security admission and backend effect support remain separate decisions;
- a backend receipt does not become world truth;
- admitted request/effect identity survives into replacement management evidence;
- final consequence is established independently by Host topology truth;
- the default S6 profile remains physically valid.

## What C1 does not prove

C1 does not prove generic action/RBAC/policy design, arbitrary shell authority, model-backed strategic selection of the request, durable Session/admission recovery after controller replacement, exactly-once effects across process death, causal graph validity, or external/Internet authority. The accepted world remains isolated and no-uplink.

## Resulting pressure

C1-A has now tested the first branch of this pressure. A real DeepSeek/Harness Actor used the same visible world and authority as optional power: it chose `hold` for a stability objective and `request-effect` for continuation, then drove the existing C1 physical effect without Security repairing its scope. See [`AUTONOMOUS-INTENT-C1A.md`](AUTONOMOUS-INTENT-C1A.md).

That experiment did not show an immediate need for a generic action bus. Instead it exposed a truth/causality defect—live references from `inspect()` could let future topology changes rewrite retained past history—and forced immutable Range snapshots. The next stronger pressure is therefore interruption after admission/request binding: reconcile the actual world without duplicate mutation and let that failure surface determine whether durable effect state, enforced causal linkage, or resumable `RangeSession` is necessary.
