# P0 Core A constraint audit

Audit basis: Ordivon Computer `be5fe779267f0225dd37c570932c7d71ee5223a7`,
`core/foundations.md` SHA-256
`7ac5eb7a158d169277a53f59c6655a4201bacc58e9a00d1fef86ab874560698f`.

This review applies A0–A16 to the active Security research path. It does not
create a Security control plane. Every retained constraint must name the
unrecoverable loss it prevents, its recurring cost, its actual consumer, and a
deletion trigger.

## Active ownership path

```text
ExperimentSpec
→ World + opponent generate authoritative hidden state
→ Actor receives only admitted Observation and allowed actions
→ World applies one bounded Decision
→ immutable Trace records Observation / Decision / Effect / truth digest
→ World emits a sealed hidden evaluation record
→ independent versioned Scorer computes TrialOutcome
→ Trial manifest, trace, hidden record, result, and seal commit atomically
→ analysis consumes retained TrialResult records
```

Security owns the adversarial experiment and evaluation relation. It does not
own Host Task truth, Harness cognition, Runtime execution, Game World truth, or
Ordivon World provider lifecycle.

## Constraint ledger

| Constraint | Core A basis | Unrecoverable loss prevented / capability purchased | Recurring cost | Consumer | Disposition and deletion trigger |
|---|---|---|---|---|---|
| exact ExperimentSpec identity | A2, A6, A10 | prevents results from silently mixing different Actor, World, Scorer, seed, or opponent inputs | digest and admission comparisons | every Trial and family comparison | **keep** |
| Actor-specific Observation separated from World truth | A2, A6, A7 | prevents hidden opponent state from entering cognition as if observed | adapter work per World | adversarial validity | **keep** while partial observability is part of the question |
| independent Scorer identity | A2, A10, A15 | prevents the executing World from being the only authority over its own score and permits offline rescoring | one evaluation adapter and hidden record | evaluation and evaluator-integrity studies | **keep** |
| sealed hidden evaluation record | A5, A10 | preserves the exact inaccessible facts used by a Scorer without exposing them to the Actor | private evidence bytes | offline rescoring and audit | **keep**; narrow fields when a scorer demonstrably does not consume them |
| immutable per-Trial manifest and identity key | A5, A6, A10 | prevents reruns with changed scaffolds or judges from overwriting old evidence | one small manifest | comparison and reproduction | **keep** |
| staging, file seal, `fsync`, atomic rename | A5, A10, A11 | prevents a partial or mixed Trial directory from being admitted as complete evidence | local write latency | retained local Trials | **keep-local**; replace only with an artifact backend providing the same atomicity |
| append-only JSONL Trace with digest | A5, A10 | preserves decision/effect order and detects byte drift | trace storage | diagnosis and replay | **keep**; do not promote to a universal telemetry platform |
| raw per-dimension outcomes | A7, A15 | prevents one aggregate score from hiding tactical/strategic or validity/cost trade-offs | wider reports | research interpretation | **keep** |
| local MicroContest fixture | A1, A11, A14 | buys sub-second deterministic detection of deception, stale evidence, and policy-switch errors | fixture maintenance | PR acceptance | **keep-provisional**; delete when a mature external World provides the same signal at similar cost |
| pinned CAGE 4 adapter | A1, A10 | supplies a mature external substrate and checks transfer beyond the local fixture | optional external checkout | release/periodic acceptance | **keep-conditional**, never a default dependency |
| command-backed model Actor | A1, A11, A13 | temporary access to real model decisions before Harness ownership is available | subprocess startup, parsing, duplicated provider logic | model diagnostic Trials | **freeze**; replace with Harness-backed Actor after Harness v0 |
| R-A control-boundary matrix | A10, A14, A15 | preserves a deterministic truth-table regression over known evidence mutations | scenario maintenance | owner-boundary regression | **keep as evaluation**, not as an open-world safety estimate |
| global context-free risk score or approval threshold | A7, A8, A11 | no demonstrated irreducible capability | false holds and missed evidence corruption | none | **reject** |
| operation-local calibrated monitor threshold | A7, A8, A10 | may purchase bounded admission for a named threat model | monitor calls and false abstentions | only the exact protocol that validates it | **evidence-gated**, not globally forbidden |
| monitor liveness as a system-wide veto | A8, A11 | no demonstrated irreducible capability | broad availability loss | none | **reject**; a specific high-consequence protocol may still require its own monitor |
| Campaign Manifest/ledger/coordinator v0 | A11, A13, A14 | historically proved admission, reconciliation, residual inspection, and evidence export for one disposable range | about 4.6k active contract LOC plus cross-component model drift | historical reproduction only | **frozen/archive**; no new component or lifecycle responsibility; remove from active package after external consumers are checked |
| Security-owned cross-project lifecycle orchestration | A2, A13 | duplicates Runtime/World owner truth | adapter and governance expansion | no valid active consumer | **forbid** |

## P0 changes

1. `control_boundary_adversary` moved from the frozen Campaign contract package
   to `ordivon_security_evaluations`; the old import is compatibility-only.
2. `WorldAdapter` now emits a hidden evaluation record. A distinct `Scorer`
   identity computes `TrialOutcome`, so the same retained record can be scored
   again without rerunning the Actor.
3. Trial identity binds the complete Spec, Actor, World, Scorer, seed, opponent,
   and turn limit. A changed input creates another Trial key.
4. Trial evidence is written to a private staging directory, sealed by exact
   file digest and byte length, synchronized, and atomically renamed. Existing
   Trial evidence cannot be overwritten.
5. Campaign v0 remains reproducible but is explicitly frozen and cannot absorb
   new World, Host, Runtime, or Harness responsibilities.

## R-A claim boundary amendment

The committed 24/24 result is an executable regression against 12 designed
mutations and matched controls. It proves that the implemented
provenance/reconcile/verification decision function matches those declared
labels. It does not estimate unknown-attack coverage, model-policy safety, or
open-world attack success.

The historical result rejects a **global context-free** risk/approval rule and
a **system-wide** monitor-liveness veto. It does not establish that all local
risk thresholds or monitors are useless. A monitor or threshold may be a valid
precondition for one exact high-consequence protocol only after paired honest
and attack evaluations demonstrate positive net value.

## Deferred work

- held-out attack families and blind labels;
- evaluator-manipulation and scorer-integrity experiments;
- Harness-backed Actor and provider-continuity receipts;
- immutable evidence parity for the separate CAGE 4 runner;
- Campaign v0 physical archival after consumer search.

These are evidence-triggered tasks, not reasons to introduce a general Security
state machine now.
