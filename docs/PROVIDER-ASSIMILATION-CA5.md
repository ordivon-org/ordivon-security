---
schema_version: 1
id: security.provider-assimilation-ca5
title: Provider Assimilation CA5
type: decision
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-14
summary: Cross-consumer audit of CA1-CA4 concluding that a shared RangeActionGateway/provider-binding layer is not earned; provider-specific adapters plus existing Runtime, Harness, RangeAuthority and evidence owners remain the smaller architecture.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.classical-capability-basis-ca0
  - security.classical-execution-carriers-ca1
  - security.vulnerability-evidence-ca2
  - security.post-compromise-state-ca3
  - security.defensive-observation-response-ca4
---
# Provider Assimilation CA5

## Question

After four materially different classical capability consumers, has Security finally earned a shared `RangeActionGateway` or provider-binding abstraction?

CA5 answers this by auditing actual accepted code/evidence rather than completing the old R7 roadmap by inertia.

## Consumer pressure

The four consumers are physically heterogeneous:

| Consumer | Mechanics owner | Invocation shape |
| --- | --- | --- |
| CA1 | Windows KVM + Windows carriers | `EvaluationSpec/AuthorityManifest -> EvaluationRunner -> WindowsKvmEvaluationBackend` |
| CA2 | Clang/LLVM | compiler/analyzer/fuzzer/sanitizer subprocesses over exact revisions |
| CA3 | local process/filesystem + synthetic target authority | bounded worker operations + management truth |
| CA4 | ClamAV + filesystem response | scan -> applicability adjudication -> scoped quarantine |

Their accepted evidence objects share only the experiment/evidence envelope:

```text
authority
gates
kind
limitations
runtimeJobId
schemaVersion
securitySourceRevision
status
```

They do **not** force one common provider invocation schema. Provider identity is not even structurally required at the same level for every consumer: CA3's relevant physics is ordinary local state plus target authority, while CA1's exact provider identity lives inside Evaluation execution identity and evidence.

## Three options

### 1. Provider-specific invocation + existing Ordivon owners

**Retain.**

This is the accepted baseline:

```text
Agent/Harness when cognition is needed
        ↓
Security semantic effect / Range authority when consequential
        ↓
provider-specific adapter or existing Evaluation runner
        ↓
Runtime/provider mechanics
        ↓
native evidence
        ↓
Security applicability/consequence interpretation
```

It already passed CA1-CA4 without weakening native evidence.

### 2. New narrow Security provider-binding class

**Not earned yet.**

A useful abstraction must delete repeated responsibility. CA1-CA4 do not show one repeated provider lifecycle, invocation shape, parameter model, or evidence normalization problem that belongs nowhere else.

The repeated facts are already owned:

- execution/recovery -> Runtime or exact provider runner;
- cognition/tool composition -> Harness;
- adversarial consequence admission -> `RangeAuthority`/`RangeEffectRequest` where applicable;
- exact experiment/evidence identity -> Security Evaluation/acceptance evidence;
- mechanics/current provider output -> provider.

Adding a new class would mostly rename these facts.

### 3. `RangeActionGateway`

**Reject now.**

A gateway would not displace Windows KVM, LLVM, local authority/state mechanics, or ClamAV. It would wrap them with optional fields and risk becoming a second grant registry plus lossy native-evidence normalizer.

That fails PF0's provider-first displacement test.

## CA5 result

The stable cross-provider invariant is thinner than a gateway:

> exact provider/native evidence + exact target/world identity + explicit Security authority for consequential effects + independent current applicability/consequence evidence.

This is a **composition rule**, not a new service.

The absence of a new API is the CA5 result, not missing implementation work.

## Reopen conditions

A shared binding may be reconsidered only if later consumers show repeated causal friction, for example:

1. at least two offensive and one defensive Agent-facing consumers require the same missing binding semantics;
2. provider replacement repeatedly changes Security code only because one stable domain contract has no owner;
3. existing Harness/Runtime composition cannot preserve a required Security effect/evidence distinction;
4. CA6 demonstrates measurable tactical failure from heterogeneous provider surfaces and a narrow typed binding removes that failure.

Until then, provider-specific Tools/adapters are a feature: they preserve native semantics and prevent premature lowest-common-denominator design.

## Consequence for CA6

CA6 should not begin by implementing a capability gateway. It should construct the smallest tactical choice surface directly from already verified CA1-CA4 facts and compare:

- static/scripted policy;
- constrained adaptive policy;
- model-backed Agent where current Harness/provider equipment permits.

Only tactical evidence can now force a higher abstraction.
