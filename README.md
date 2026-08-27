---
schema_version: 1
id: security.start
title: Ordivon Security
type: start
profile: organization
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
updated: 2026-08-15
summary: Canonical entry to the authorized adversarial-autonomy laboratory, with explicit Range sovereignty, separated truth and evidence, verified consequence, recovery, scoped profiles, and research routes.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.law-profiles-c0
  - security.range-session-s0
  - security.architecture
  - security.research-agenda
  - security.research-boundary
  - security.evidence
  - security.authority
---
# Ordivon Security

Autonomous adversaries create a problem that ordinary execution infrastructure does not solve by itself: **several actors can want incompatible outcomes, observe different evidence, manipulate one another, and still produce real consequences.**

Ordivon Security is an **authorized adversarial-autonomy laboratory** for studying that problem. Cyber is the first high-fidelity domain because mature operating systems, ranges, networks, offensive/defensive tools, sensors, and repeatable consequences already exist. Cyber mechanics are not the definition of the project.

Security asks questions such as:

- Who is allowed to affect this world?
- What did an Actor intend, and what was actually admitted?
- Did an executor run, and did the world really change?
- Is a sensor reporting truth, a fallible observation, or something an adversary can manipulate?
- What can a successor safely do after the original controller disappears?
- When evidence is insufficient, is the correct answer success, failure, or `UNKNOWN`?

## The central boundary

A Security experiment is valid only inside a world that Ordivon owns or has explicit authority to test. The Range must have an independent management boundary capable of establishing what world was created, what authority was granted, what happened, and whether the world was cleaned up.

**Reachability is not authority.** A Provider connection, network route, discovered host, Tool capability, or Actor desire does not silently expand the declared Range.

Inside an authorized Range, experiments may be aggressive: persistent footholds, deception, conflicting objectives, compromised teammates, multi-node effects, autonomous Red/Blue behavior, recovery, replacement, and resource scarcity are legitimate research variables. Outside that Range, undeclared third-party effects invalidate the Trial.

See [`docs/research-boundary.md`](docs/research-boundary.md).

## One consequence journey

Suppose a Red Actor asks to replace one network peer while a Windows Guest remains alive:

```text
Actor observes its local world
→ Agent decides what it wants to do
→ exact Actor / zone / capability authority is checked
→ Security admits one typed effect
→ backend or Runtime performs physical work
→ executor returns a receipt
→ independent world observation checks the consequence
→ Security records what is known, unknown, or needs recovery
```

Each arrow is a different fact.

An Actor request does not prove permission. Permission does not prove execution. Execution does not prove the world consequence. A sensor packet does not automatically become world truth. A later evaluator score does not rewrite any of those facts.

That separation is the reason Security exists as a domain layer rather than as another Tool wrapper.

## Four rule classes

Security does not treat every current restriction as universal law. [`docs/LAW-PROFILES-C0.md`](docs/LAW-PROFILES-C0.md) owns the exact classification.

### Constitutional law

These distinctions have repeatedly survived stronger experiments:

- **sovereignty and authority** — effects stay inside declared owned/delegated scope;
- **truth separation** — Actor claims, communicated claims, sensors, management observations, executor receipts, evaluator judgments, and independent world truth are different authorities;
- **causal accountability** — intent, admission, execution, receipt, observed effect, and verified consequence remain distinguishable;
- **exact identity and provenance** — worlds, Actors, effects, Tools, evidence, resources, and revisions remain attributable;
- **honest uncertainty** — when two materially different histories collapse to the same admitted evidence, recovery must preserve `UNKNOWN` rather than invent a missing past;
- **recoverability without guessing** — owner loss or response loss is resolved from durable identity plus current observation, not blind replay or broad deletion;
- **subsystem authority remains scoped** — Host continuity, Harness cognition/Run structure, Runtime physical execution, Security admission, and native world truth do not inherit one another's authority.

These laws make autonomous conflict intelligible. They do not choose the Agent's strategy.

### Authority and resource grants

A grant states what one principal may control or spend inside a declared scope: zones, capabilities, Samples, environments, time, processes, model/Tool budgets, or an explicitly delegated external boundary. A grant is not a moral judgment and need not be permanent.

Current `RangeSession` engineering intentionally binds an **exact grant snapshot** in `RangeSessionSpec`; it does not silently refresh a remote entitlement or mutate the grant in place. Admissions retain the exact authority digest that decided them. If a future world needs live revocation/rotation, that becomes an explicit new authority revision/epoch for future decisions, while earlier admissions remain historical facts. See [`docs/AUTHORITY-LIFECYCLE-ENGINEERING.md`](docs/AUTHORITY-LIFECYCLE-ENGINEERING.md).

### Experiment profiles and fixtures

A profile may intentionally narrow the world to isolate a variable. Current examples include synchronous Contest ticks, CAGE team plans, benign-only Windows admission, no-uplink ranges, preparation-only installer gates, and fixed budgets. These restrictions belong to the named profile unless a constitutional boundary says otherwise.

`no network in P0` therefore does **not** mean `all Security experiments must have no network`.

### Evaluator judgments

Findings, severity, confidence, reward, score, and `EvaluationDisposition` interpret evidence for one purpose. They do not become world truth or action authority.

## What Security owns — and what it composes

Security owns the adversarial semantics:

- declared Range and Scenario identity;
- Actor identities, objectives, asymmetric observations, and domain grants;
- admission of consequential adversarial intent;
- independent truth/evidence relationships needed by the experiment;
- Contest, Evaluation, recovery, deception, communication, and strategic-outcome semantics when the experiment needs them.

It composes rather than replaces:

- **Harness** for generic model/Tool cognition and bounded Agent Runs;
- **Host** for durable higher-level work continuity;
- **Runtime** for exact local execution and recovery facts;
- **World/native providers** for external capability and occurrence truth where applicable;
- mature hypervisors, containers, operating systems, cyber ranges, scanners, fuzzers, telemetry, forensics, identity systems, and network machinery.

A shared Security abstraction earns existence only when adversarial semantics leave a recurring responsibility that those owners cannot correctly hold.

## Current execution shapes

### Persistent Range

`RangeSession` is the persistent semantic spine for contested worlds that may change without a global tick barrier or universal action menu. It binds Actors, Range authority, asynchronous events, admitted effects, checkpoints, and lifecycle to an exact Range identity.

### Synchronous Contest

`SynchronousContestProfile` is a bounded reproducible profile. It may collect one proposal per Actor, resolve accepted proposals simultaneously, and fail a tick as a unit. Those semantics are useful for controlled comparison; they are not universal `RangeSession` law.

CAGE Challenge 4 is a revision-pinned Contest Range used to reuse mature adversarial simulation while Security owns scheduling, admission, information boundaries, and evidence.

### Software Evaluation

Evaluation is a separate path for authorized software assessment. It binds exact Sample identity, Authority, Environment, Guardian, Observation plan, backend, Findings, residual closure, and evidence. A software Sample is not modeled as a Contest Actor.

Static analysis, Case Snapshots, and Windows KVM are scoped Evaluation/Range profiles with their own truth boundaries. Guest claims remain observations; management-plane QMP/Host evidence owns the management facts it can actually establish.

### Vulnerability and Sample research corpus

`ResearchCorpus` gives Agents a revisioned query/inspection surface over exact vulnerability and Sample identities without turning possession or provider labels into authority. Provider/advisory classifications, Security observations, maintained-fixture facts and Case conclusions remain visibly separate. Sample bytes stay in the private `SampleVault` or provider-owned systems; every corpus Sample is `denied-by-default` for execution.

The accepted P0 seed set contains CA2 owned vulnerability evidence, the harmless EICAR test fixture, and metadata-only 目标产品B Case identity. ResearchCorpus consumes provider evidence only as explicit exact snapshots and implements no automatic fetch, malware download/upload, database mirror or family ontology. Current discovery may use a mature external provider/tool outside Security; retain an exact snapshot in ResearchCorpus only when owner memory, comparison, or reproducibility needs it. Use `uv run ordivon-security-research-corpus ...`; [`docs/RESEARCH-CORPUS-P0.md`](docs/RESEARCH-CORPUS-P0.md) owns the exact boundary.

## Recovery laws that survived the C1 programme

The C1 fault programme is extensive; the retained current laws are smaller:

- **durable publication is not complete physical state** — after owner loss, current world state may have advanced beyond the last ledger generation;
- **recovery authority requires exclusion and re-observation** — the current single-host mechanisms permit one recovery mutator for one lineage, then require fresh world observation before consequential continuation;
- **completion, publication, and executor liveness are different facts** — a consequence can be complete while publication is stale and the one-shot executor is gone;
- **missing evidence can force `UNKNOWN`** — identical recoverable views can hide delivered versus undelivered histories;
- **retry safety does not prove what happened** — a repeat-safe effect can converge safely while the original delivery history remains unknown;
- **ordering two independent writes does not create atomicity** — effect-first and marker-first simply choose different failure modes;
- **reservation can represent uncertainty without resolving it**;
- **intrinsically idempotent/declarative effects can tolerate repeated invocation when their exact invariant is independently observable**;
- **compensation repairs state, not history** — compensation needs its own identity, and blind compensation retry can itself be wrong;
- **private consequence truth may remain authority-local** when the owning effect boundary can classify and converge safely;
- **idempotency still needs trustworthy predicate truth** — missing, corrupt, or conflicting current truth fails closed instead of letting an idempotent protocol guess.

These results did **not** earn a universal causal DAG, transaction service, compensation ontology, trust service, or global truth database. The exact experiments remain in the C1 research documents listed by [`docs/authority.md`](docs/authority.md).

## Current research frontier

Recent Agent-first experiments narrowed several tempting abstractions:

- verified disclosure can remove one epistemic ambiguity without forcing a universal reputation/trust system;
- exact evidence computation identity matters where derived evidence is reused, but a shared `EvidenceReducer` service was not earned;
- aligned incentives and bidirectional communication do not by themselves make cheap talk strategically credible;
- explicit intent readback/finalization ceremony did not guarantee correct action convergence in the tested consumer;
- deliberation **before** effect authority succeeded with the ordinary AF2 intent path in the exact consumer, so the extra ceremony was removed rather than promoted.


A previously detached W5-B physical result is now recovered as [`research/w5b/README.md`](research/w5b/README.md): exact 2026-08-09 acceptance is preserved, today's KVM/migration/Guest-runner substrate remains relevant, and the standing is explicitly `HISTORICAL_VALID + CURRENT_RELEVANT + NOT_REEXECUTED_20260827`. It does not create a production Embodiment/Presence contract or claim a fresh physical replay.

The next pressure should come from independent consumers or stronger adversarial worlds, not from completing an ontology because the research numbering exists.

CA-LIC V0-V8/R1 adds one engineering correction rather than a new subsystem: distinguish a frozen grant, current/future authority, external authorization carriers, external capability execution, and already delivered information. Security therefore keeps exact grant/admission identity and historical evidence, while rejecting a generic lease/revocation manager until a real owned consumer needs dynamic authority. The same audit also hardened evidence-bundle verification so manifest path claims cannot escape the bundle or traverse symlinks.

The first ordinary-consumption round is accepted in [`ORDINARY-SECURITY-CONSUMPTION-R1.md`](docs/ORDINARY-SECURITY-CONSUMPTION-R1.md). A derived `--view ordinary` projection reduces mixed-maturity navigation pressure without deleting research reproduction paths; ResearchCorpus earns a normal pre-analysis role for exact vulnerability/Sample/provider evidence; a bounded EICAR/ClamAV incident consumer closes current/stale response without new EDR/SIEM or higher-fidelity transfer.

Use [`docs/research-agenda.md`](docs/research-agenda.md) and the scoped AF/AE/EC/AC/IF documents for the exact hypotheses and evidence.

## What is usable now

The repository currently contains experimentally accepted implementations for:

- deterministic multi-Actor Contest execution and evidence;
- revision-pinned CAGE 4 composition;
- content-addressed SampleVault and static Evaluation;
- disposable/recoverable Windows KVM machine substrate;
- isolated Windows/Linux contested fabric and live topology churn;
- exact Range authority admission for a physical peer-replacement effect;
- owner-loss reconciliation and successor-continuation experiments;
- model-backed Actor paths through Harness, with Host/Runtime variants where the experiment requires them;
- separated Actor, management, sensor, world-truth, and operational evidence streams.

This is a research system, not a production attack platform. `readiness: EXPERIMENTAL` is intentional.

## Start according to your job

| Need | Read / invoke |
| --- | --- |
| start an ordinary vulnerability/Sample/evaluation/response job without browsing research chronology | `uv run ordivon-security-surface` — ordinary task navigation is the default; it runs no experiment and grants no authority |
| inspect the complete maturity-classified Security surface, including research apparatus | `uv run ordivon-security-surface --view full` — explicit full projection; research reproduction remains available and execution authority is unchanged |
| understand why Security exists and where experiments may act | this README + [`docs/research-boundary.md`](docs/research-boundary.md) |
| understand constitutional law versus profiles/fixtures | [`docs/LAW-PROFILES-C0.md`](docs/LAW-PROFILES-C0.md) |
| understand current components and data flow | [`docs/architecture.md`](docs/architecture.md) |
| understand mission and long-lived project boundary | [`CHARTER.md`](CHARTER.md) |
| inspect exact ownership of current/research documents | [`docs/authority.md`](docs/authority.md) |
| inspect open questions and falsifiers | [`docs/research-agenda.md`](docs/research-agenda.md) |
| verify active/historical evidence | [`evidence/README.md`](evidence/README.md) |
| inspect or register exact vulnerability/Sample research records without granting execution | `uv run ordivon-security-research-corpus ...` + [`docs/RESEARCH-CORPUS-P0.md`](docs/RESEARCH-CORPUS-P0.md) |
| reproduce a specific C1/AF/AE/EC/AC/IF result | read that experiment's canonical document from the authority map |

Research phase identifiers preserve provenance. They are not prerequisites for understanding the current constitutional model.

## Boundary

Security permits strong autonomous experimentation **because** the experiment owns its sovereignty, truth, consequence, and recovery boundaries. It does not make unrelated systems legitimate targets, and it does not make a safer profile into a universal ban on stronger authorized worlds.

The goal is not to keep Agents weak. It is to make stronger adversarial Agents experimentally legible: what they knew, what they wanted, what they were allowed to do, what physically happened, what the world became, and which uncertainty still remains.


## Owner environment

Use `scripts/owner-environment test`; use `cold-start` for fresh-environment proof and the explicit `*-cage` modes for the optional CAGE dependency profile.
