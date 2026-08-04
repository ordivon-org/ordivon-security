---
schema_version: 1
id: security.migration.round3-p0
title: Security migration round 3 P0
type: closeout
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - maintainer
  - builder
  - researcher
  - evaluator
  - agent
updated: 2026-08-04
summary: P0 failure semantics, complete Trial execution identity, semantic and operational evidence separation, and the Harness Domain Tool Bridge prerequisite for model-backed Actors.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.migration.round2
  - security.architecture
  - security.evidence
---
# Security migration round 3 P0

## Purpose

Round 3 P0 closes the failure, identity, and evidence gaps that would otherwise make model-backed Red/Blue experiments ambiguous or unfair. It precedes any DeepSeek Actor implementation.

## Fail-closed Contest semantics

An adversarial tick is atomic at the semantic barrier. If any Actor cannot produce a valid proposal, no side receives a world transition.

The active outcomes are:

```text
malformed Actor proposal  → actor-failure:malformed
Actor deadline expiry     → actor-failure:timeout
Provider failure          → actor-failure:provider-error
stopped Actor             → actor-failure:actor-stopped
rejected ActionProposal   → invalid-action
```

On Actor failure, proposals already collected from peers receive `not-executed`. On admission rejection, the rejected proposal receives `rejected` and every admitted peer receives `not-executed`. The Range is not resolved, the world remains unchanged, and the Trial terminates with structured evidence.

Security does not silently substitute Sleep, invoke a native fallback policy, retry a Provider, or grant one side a unilateral action. A future Actor adapter may use Harness-owned bounded correction or Provider replacement before returning a final proposal or failure, but that behavior must be part of Actor execution identity and operational evidence.

## Trial execution identity

Trial identity now binds:

- exact Scenario digest and seed;
- Ordivon Security package/source identity;
- evidence schema revision;
- Range adapter identity and semantic configuration;
- external substrate revision where applicable;
- ordered Actor backend implementation and configuration identities.

A clean source checkout uses its Git revision. A dirty development checkout uses the base revision plus a digest of tracked and untracked source changes. Installed packages fall back to their package version unless the operator supplies `ORDIVON_SECURITY_REVISION`.

Model-backed Actors must later extend their Actor execution identity with Harness revision, Provider adapter identity, requested model identity, Domain Tool catalog digest, grant, budget, and non-secret Provider configuration. Credentials never enter Trial identity.

## Evidence separation

The deterministic semantic bundle is schema revision 2 and contains:

```text
manifest.json
trial-identity.json
raw-metrics.json
result.json
bundle-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
```

It remains reproducible for the same semantic inputs and execution identities.

Non-deterministic operating facts are written separately:

```text
operational-manifest.json
events/operational.jsonl
```

Operational events record wall-clock time and durations for Range lifecycle, Actor start/proposal/stop, admission, resolution, and Contest invocation. Their manifest binds the semantic evidence digest, but operational bytes do not alter the semantic evidence digest.

## Harness prerequisite

Ordivon Harness now exposes a generic dependency-inverted `DomainToolBridge`, immutable `DomainToolCatalog`, granted `DomainToolLoopPlan`, and `DomainToolLoopRunner`. Harness does not import Security. Security will supply a side-level CAGE plan catalog and bridge in the next model-Actor stage.

The P0 bridge is intentionally a bounded Agent-loop integration seam, not a second Host Assignment database or Runtime Tool authority. Security remains responsible for Actor state, domain admission, Range truth, and Contest evidence; Harness remains responsible for the model loop, Provider adaptation, budgets, and observable Tool calls.

## Acceptance

The P0 gate requires:

- rejected Micro and CAGE actions terminate without world advance;
- Actor timeout terminates without peer execution;
- execution implementation drift changes Trial identity even when Scenario is unchanged;
- semantic evidence remains deterministic across repeated runs;
- operational evidence verifies independently and detects tampering;
- every previous deterministic and pinned-CAGE test remains green;
- the generic Harness bridge runs a non-Runtime domain Tool through a complete model/tool/conclusion loop;
- Harness has no dependency on Ordivon Security.

## Next stage

Round 3 P1 should implement a Security-owned CAGE team-plan `DomainToolCatalog` and `DomainToolBridge`, then add a Native Harness Actor adapter that maps Harness stop codes to the explicit Security failure taxonomy. The first live model matrix remains plan-level (`native-policy` versus `sleep`) before parameterized CAGE actions are exposed.
