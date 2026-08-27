---
schema_version: 1
id: security.ordinary-capability-preflight-r2
title: Ordinary Security Capability Preflight R2
type: engineering-result
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - builder
  - agent
  - evaluator
updated: 2026-08-27
summary: Owner-local read-only mechanical eligibility projection that withdraws ordinary Security operations before model-facing disclosure when their exact prerequisites are not currently satisfied.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.ordinary-security-consumption-r1
  - security.research-corpus-p0
  - security.research-corpus-k1-currentness
  - security.authority
---
# Ordinary Security Capability Preflight R2

## Problem

Ordinary Security R1 reduced the navigation surface, but a declared/callable owner operation could still be shown to an Agent even when the current turn did not mechanically satisfy its prerequisites. That leaves a representation gap:

```text
operation exists
!= operation is current
!= prerequisites are satisfied
!= operation should be model-facing now
```

A model should not spend cognition deciding deterministic owner-local housekeeping when the owner can cheaply establish that standing before Tool disclosure.

## Retained architecture

R2 implements one owner-local read-only function:

```text
security_ordinary_capability_preflight(...)
```

and exposes the same projection through the existing command:

```text
uv run ordivon-security-surface --preflight
```

No new console command, capability registry, planner, semantic router, or Environment Compiler is introduced.

The output is an ephemeral derived projection with truth role:

```text
derived-owner-local-mechanical-eligibility-projection
```

Its primary consumer field is:

```text
turnAddressableOwnerOperations
```

An application may use that exact set to filter the model-facing Tool schema. The projection is not itself a Tool the Agent must call and contains no semantic recommendation about which admitted capability to choose.

## Current mechanical checks

R2 is deliberately narrow and covers only the three owner-callable ordinary memory/currentness operations already exposed by Security R1.

### Research query

`security.ordinary.research.query` is turn-addressable only when the exact owner-memory seed sources required by the ordinary projection are present.

### Exact record inspection

`security.ordinary.research.inspect` is **not** initially turn-addressable merely because the implementation exists. Before a record has been selected its standing is:

```text
mechanicalEligibility = input-required
turnAddressable = false
```

After an exact `recordId` from current owner memory is selected and resolves mechanically, the next preflight recompiles the operation to:

```text
mechanicalEligibility = eligible
turnAddressable = true
```

An unknown/stale record identity fails closed without withdrawing independent query/currentness operations.

### Provider-currentness comparison

`security.ordinary.provider-currentness` is exposed only when the exact retained/candidate provider snapshots needed for the existing read-only comparison are present and mechanically comparable. The comparison still does not fetch the provider, mutate the corpus, infer target applicability, or grant execution authority.

## Dogfood transition

A fresh ordinary preflight over the current owner source produced:

```text
S0 turn-addressable:
- security.ordinary.research.query
- security.ordinary.provider-currentness

S0 withdrawn:
- security.ordinary.research.inspect (input-required)
```

An ordinary EICAR query then selected exact record:

```text
sample:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Re-running preflight with that exact identity produced:

```text
S1 turn-addressable:
- security.ordinary.research.query
- security.ordinary.research.inspect
- security.ordinary.provider-currentness
```

This is a real standing transition from owner evidence, not a prompt-side recommendation.

A missing-source treatment withdraws all mechanically dependent operations. An unknown selected record withdraws only inspection. CLI tests also reject `--record-id` outside preflight so the exact selection is not silently ignored.

## Boundaries

R2 does not:

- choose whether the Agent should research, inspect, compare currentness, evaluate software, or enter a Range;
- grant Range/Evaluation authority;
- perform external provider discovery;
- execute a Security effect;
- make research apparatus ordinary;
- expose every mechanically executable CLI to the Agent;
- invent a shared cross-owner projection schema.

The retained local rule is smaller:

> **mechanical admission before model-facing disclosure; semantic choice after admission.**

That rule is consumed here because Security has a concrete ordinary surface that benefits from it. Whether another owner uses the same implementation shape remains that owner's decision.

## Reopen pressure

Extend preflight only when another ordinary Security operation has a deterministic, owner-native prerequisite whose omission measurably causes Agent friction or invalid Tool exposure. Relation relevance that requires semantic judgment is not a mechanical withdrawal criterion by default.
