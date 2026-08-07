---
schema_version: 1
id: security.synchronous-contest-s1
title: Synchronous Contest Profile S1
type: architecture
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - builder
  - evaluator
  - agent
updated: 2026-08-07
summary: Compatibility proof that accepted synchronous Contests compose with a persistent Range Session through management events and sealed evidence references without pretending to be the persistent Range backend.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.range-session-s0
  - security.architecture
  - security.research-agenda
  - security.authority
---
# Synchronous Contest Profile S1

## Result

S1 proves that the existing deterministic Contest core can remain intact while participating in the new persistent Range model. The natural composition boundary is management and evidence, not backend inheritance.

`SynchronousContestProfile` runs an existing Contest against its existing `ContestRunner` and Range, then records exact start/completion/failure management events in a running `RangeSession`. A completed event binds the Contest Trial, Scenario and Trial-identity digests, terminal reason, tick count, and sealed semantic and operational evidence digests.

The persistent Range Session remains running when the bounded Contest completes or when Contest infrastructure raises an exception. The Contest retains its own fail-closed tick semantics and its own Range lifecycle.

## Deliberate non-unification

S1 does not make `ContestRunner` implement `RangeSessionBackend`, does not translate `allowedActions` into `RangeAuthority`, and does not claim that the Contest world and the persistent Range world are the same physical world.

That distinction is intentional. `ContestRunner` remains the reproducible synchronous benchmark/evaluation profile. `RangeSession` remains the lifecycle spine for a world that may continue changing while Actors fail, disappear, or act asynchronously.

A future shared-world adapter is admissible only if a physical Range demonstrates a real need for the same backend instance to support both asynchronous native effects and bounded synchronous experiments.

## S1 contract

```text
running RangeSession
      │
      ├─ profile.synchronous-contest-started
      │
      └─ SynchronousContestProfile
             ↓
         existing ContestRunner
             ↓
         existing synchronous Range
             ↓
         sealed ContestResult + evidence
             │
             └─ profile.synchronous-contest-completed
                or profile.synchronous-contest-failed
```

The profile requires every Contest Actor to already exist in the parent Range Session. Additional parent-session Actors are allowed; no action grants or authorities are inferred from the Contest manifest.

## Acceptance

S1 acceptance proves:

- an existing Micro Contest completes without terminating the persistent Range Session;
- the Range Session records exact sealed Contest evidence digests rather than copying the Contest trace;
- the completion event is causally linked to the profile-start event;
- a Contest infrastructure exception records profile failure but does not terminate the persistent Range Session;
- a Contest containing an Actor outside the parent Range Session is rejected before Contest execution;
- no `allowedActions` or synchronous tick semantics are projected into `RangeAuthority`.

S1 is a compatibility proof, not a War Range. It adds no physical machine, network, native Agent execution, ControlState, or new evidence authority.
