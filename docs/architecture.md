---
schema_version: 1
id: security.architecture
title: Architecture
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
updated: 2026-08-15
summary: Canonical architecture for authorized persistent Ranges, bounded Contests and software Evaluations, with exact identity, separated authorities, consequence verification, recovery, and sealed evidence.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.research-boundary
  - security.range-session-s0
  - security.evaluation-trial-p0
  - security.windows-kvm-p0
  - security.agent-experiment-p0
  - security.authority
---
# Architecture

## System boundary

Ordivon Security is the **adversarial domain layer**. It owns the semantics required when autonomous principals contest a world: declared Range identity, Actor identity and authority, asymmetric information, adversarial intent admission, independent consequence evidence, recovery, and experiment/evaluation outcomes.

It does not own generic Agent cognition, durable Task continuity, local process execution, hypervisor mechanics, or every source of external truth. Those remain with Harness, Host, Runtime, the native world/provider, and mature classical systems.

The architectural test is causal: if a mechanism can be removed from Security and correctly remain with one of those owners without losing adversarial meaning, Security should not own a duplicate.

## Rule layers

[`LAW-PROFILES-C0.md`](LAW-PROFILES-C0.md) is authoritative for rule scope:

- **constitutional law** — sovereignty, truth separation, causal accountability, exact identity, honest uncertainty, recoverability, and subsystem authority;
- **authority/resource grant** — what one principal may control or spend inside one declared scope;
- **experiment profile/fixture** — a deliberate restriction used to isolate a research variable;
- **evaluator judgment** — an interpretation over evidence, not world truth or action authority.

A current implementation may be narrower than the constitutional model. Unsupported behavior is not automatically constitutionally forbidden.

## Authority and evidence planes

A high-fidelity experiment keeps these authorities separate even when one physical machine hosts several of them:

```text
management plane   create / freeze / reset / destroy / management truth
actor plane        contested Agent/service state
provider plane     model/Harness connectivity when used
sensor plane       fallible observations available to defenders/evaluators
world-truth plane  independent state used to verify the experiment's consequence
```

Security additionally records the semantic chain:

```text
Actor intent
→ Security admission
→ physical execution request
→ execution receipt
→ independent observed consequence
→ Security/domain interpretation
```

No arrow is collapsed merely because the same process can inspect both sides.

## Core execution shapes

### Persistent `RangeSession`

`RangeSession` represents Security's durable semantic relationship to a contested world. The physical world may outlive one Python object or controller process.

```text
RangeSessionSpec
  ├─ Range identity/binding
  ├─ ordered or named Actor identities
  ├─ Actor objectives and information boundary
  └─ zone/capability Range authority
        ↓
RangeSession
  ├─ asynchronous management / contested / sensor / world-truth events
  ├─ inspect current independent state
  ├─ admit typed RangeEffectRequest
  ├─ checkpoint / terminate / destroy
  └─ bind recovery/evidence to exact world lineage
```

`RangeAuthority` says which Actor may request which capability in which zone. Capability is permission, not instruction: the Agent still chooses whether to request the effect.

`RangeSessionSpec` currently freezes those grants for the lifetime of that Security session object. `RangeSession.inspect()` projects `authorityId`, human-readable revision and exact `authorityDigest`; every `RangeEffectAdmission` retains the digest that actually admitted or rejected the request. This is a historical binding, not a revocation/lease subsystem. A future consumer that needs authority changes while one world continues must introduce an explicit new authority epoch/revision and define stale-request semantics rather than mutating past admission history. [`AUTHORITY-LIFECYCLE-ENGINEERING.md`](AUTHORITY-LIFECYCLE-ENGINEERING.md) owns this engineering disposition.

The accepted executable-authority profile proves this path for one physical S6 peer replacement. It does not turn every future adversarial action into one universal Range effect schema.

### Bounded synchronous Contest

Contest is a profile for controlled comparison:

```text
ScenarioManifest
→ create RangeBackend
→ start ActorBackend sessions
→ collect actor-specific observations
→ collect proposals
→ admit every proposal against Actor/Range grants
→ if any required proposal fails, resolve no side for that tick
→ otherwise resolve admitted proposals simultaneously
→ return Actor results
→ record sensor and hidden truth independently
→ repeat to terminal/tick limit
→ seal semantic and operational evidence
```

This tick barrier is profile law, not persistent-Range law.

`Cage4RangeBackend` pins a specific CAGE Challenge 4 revision and expands admitted Security team plans into concrete CAGE actions. Security owns the adapter mapping, action admission, scheduling, and evidence; CAGE owns the simulator behavior at the pinned revision.

### Software Evaluation

Evaluation is a separate Security path for an authorized software Sample. A Sample is not a Contest Actor.

```text
EvaluationSpec
→ verify exact Sample bytes from SampleVault
→ create one backend environment
→ stage Sample under declared authority
→ collect Observer records / Guardian decisions / independent facts
→ destroy environment and prove residual closure
→ derive bounded Findings and disposition
→ seal semantic + operational evidence
```

Observer and Guardian remain separate. An Observer reports; it does not mutate the environment. Guardian enforces the declared environment/resource boundary; it does not become a universal strategy judge.

Static Evaluation deliberately does not execute Sample code. Case Snapshot is a separate metadata path for evolving analysis directories and cannot inherit stronger Evaluation claims from unrelated stdout, scripts, or human reports.

### Vulnerability and Sample research corpus

`ResearchCorpus` is a separate research-information profile above provider-owned intelligence and the private `SampleVault`. It does not execute Samples or establish vulnerability/malware truth by itself.

```text
exact provider snapshot / Security evidence
→ revisioned corpus manifest
→ sourceRefs + evidenceRefs
→ claims kept under explicit truthRole
→ materialization state
→ executionAdmission = denied-by-default
```

Sample records are content-addressed by exact SHA-256. Materialized bytes remain in `SampleVault`; Git retains only small manifests. External advisory, detector, family, or multi-engine results remain `provider-claim` unless separate Security evidence supports a stronger scoped claim. `inspect()` is the preferred Agent projection because it keeps provider claims, independent observations, maintained-fixture facts, and Case conclusions separate while exposing materialization and execution admission explicitly.

P0 consumes explicit provider snapshots only. It owns no vulnerability-database mirror, malware download/upload path, family ontology, provider polling scheduler, or execution authority.

### Windows KVM substrate and contested worlds

`WindowsKvmMachineProvider` supplies reusable machine mechanics:

- sealed base identity;
- disposable overlay / UEFI / TPM state;
- process-identity-aware lifecycle ledger;
- QMP management truth;
- recovery and residual closure primitives.

Security consumers add their own admission and semantics.

Current accepted profiles include:

- disposable no-network Windows Evaluation for the exact maintained benign fixture;
- out-of-band stopped-Guest NTFS truth inspection;
- isolated Windows + Linux peer fabric with no uplink;
- live peer A → peer B topology churn while the same Windows Guest remains alive;
- Range-specific owner-loss reconciliation and continuation experiments.

Guest reports remain contested/Observer evidence. Host QMP/netlink or other declared management/world-truth sources own only the facts they directly establish.

## Agent-backed Actors

`ActorBackend` is the boundary between Security Actor semantics and the generic Agent execution mechanism.

Active shapes include:

- scripted baselines;
- Harness-backed DeepSeek Actors;
- Host-assigned Harness variants;
- Runtime-backed Host/Harness variants.

Their ownership remains explicit:

```text
Harness   bounded cognition / Provider / Tool Run structure
Host      semantic Task continuity when the profile uses it
Runtime   exact local physical execution when used
Security  Actor proposal admission + Range semantics + experiment truth relationship
```

A model-generated command or Tool call never mutates Security world state merely by existing. It must cross the experiment's admitted action/effect boundary.

## Recovery architecture

Security recovery is deliberately consequence-first rather than controller-object-first.

### Durable identity is necessary but not sufficient

Effect IDs, Range IDs, process identity, exact resource identities, receipts, and durable publication are required to make recovery attributable. They are not guaranteed snapshots of current physical progress.

C1-G physically showed that the durable ledger digest could remain unchanged while namespace/link placement changed after a successor died. Therefore a recovery claim or ledger generation cannot substitute for fresh world observation.

### One current recovery mutator, then re-observe

The accepted single-host Range recovery profiles use a per-Run kernel gate so one successor/reconciler mutates a lineage at a time. Claim records preserve provenance and succession; the kernel gate supplies exclusion. This is a current mechanism, not a universal distributed-lock law.

After acquiring recovery authority, the successor re-observes current world state and performs only the missing suffix or publication repair that the evidence supports.

### Completion, publication and liveness are separate

A consequence may already be complete while the durable ledger is stale and the transient executor/service is gone. Recovery may therefore repair publication without replaying the body.

### `UNKNOWN` is a valid terminal epistemic state

When delivered and undelivered histories are observationally identical to the recovering authority, no amount of controller confidence reconstructs the missing bit. Security records `UNKNOWN` and asks whether the effect contract itself supports a safe retry/reconciliation protocol.

### Retry semantics belong to the effect

- Non-idempotent resend after ACK loss may duplicate the consequence.
- A separate dedup marker does not become atomic merely by moving before or after the effect.
- A durable `reserved` marker can represent uncertainty without proving completion.
- An exact declarative ensure-state effect can be repeat-safe when the world invariant itself is the effect and is independently observable.
- Compensation is a distinct effect with its own identity; blind compensation retry can overrepair.
- A downstream authority may safely converge private consequence state without making that predicate globally readable.
- If the authority that owns the predicate loses trustworthy truth, even an idempotent recovery contract must fail closed until truth is restored or independently re-established.

These are effect-contract laws, not one universal transaction/compensation framework.

## Evidence authority

Active Trials separate semantic and operational evidence. Depending on the profile, streams may include:

- Actor intent/response evidence;
- Range management events;
- sensor observations;
- independent world-truth observations;
- Provider/Runtime/Host operational facts;
- exact Sample/Artifact identity;
- residual-closure receipts;
- Findings/evaluator judgments.

An evaluator may consume these sources, but evaluator output does not replace them.

Retained evidence is historical information, not current authority. Later revocation may prevent future admission/materialization, but it does not retroactively erase a valid earlier admission, receipt, observation, or already delivered result. External signed evidence, if introduced later, must retain producer/key/version identity across authority rotation so historical verification does not silently inherit only the newest trust anchor.

For exact ownership of each current experiment and evidence family, use [`authority.md`](authority.md). For evidence admission and retained bundles, use [`../evidence/README.md`](../evidence/README.md).

## Current versus research-only structure

Current reusable architecture is intentionally smaller than the research corpus:

**Retained:** Range/Actor identity, scoped authority, separated evidence planes, typed effect admission, consequence verification, honest UNKNOWN, exact recovery identity, re-observation, and consumer-specific recovery/evaluation profiles.

**Not promoted:** universal causal DAG, global Truth/Freshness/Trust services, shared EvidenceReducer service, generic compensation engine, mailbox/event-visibility ontology, mandatory intent-finalization ceremony, generic Campaign/coalition/organization schema, or a second generic control plane duplicating Host/Harness/Runtime.

The AF/AE/EC/AC/IF and C1-A→N documents remain canonical research evidence for the exact claims they test. Their chronology is not the architecture's default reading order.

## Primary contracts

| Contract / owner | Role |
| --- | --- |
| `RangeSessionSpec` / `RangeSession` | persistent contested-world semantic identity/lifecycle |
| `RangeAuthority` / `RangeEffectRequest` | scoped Actor effect permission and typed intent admission |
| `ScenarioManifest` / `ContestRunner` | bounded synchronous multi-Actor comparison |
| `ActorBackend` | Actor-specific proposal loop boundary |
| `RangeBackend` | contested world adapter for one profile |
| `EvaluationSpec` / Evaluation backend | authorized software-assessment lifecycle |
| `SampleVault` / `SampleIdentity` | exact private Sample admission/provenance |
| `ResearchCorpus` | revisioned vulnerability/Sample research identity, provenance, truth-role and admission projection without owning bytes/provider truth |
| `GuardianPolicy` / Observer records | environment/resource enforcement versus fallible observation |
| `WindowsKvmMachineProvider` | machine lifecycle/QMP substrate without owning Sample admission |
| evidence bundles / receipts | exact scoped proof bound to one run/revision |

Exact source and tests outrank this summary for field names and transitions.

## Cross-project ownership

- **Security:** adversarial Scenario/Range semantics, domain authority, information asymmetry, consequence/evaluation relationships, consumer-specific recovery meaning.
- **Harness:** generic bounded Agent Run/cognition/Provider/Tool mechanics.
- **Host:** durable semantic work continuity where used.
- **Runtime:** physical local execution/recovery facts where used.
- **World/native provider:** external occurrence/current truth that only that owner can establish.
- **classical tools:** hypervisor/network/scanner/analyzer mechanics and their native reports.

No adapter inherits the semantics of the owner it transports.

## Reading paths

- Start with [`../README.md`](../README.md) for the causal project boundary.
- Use [`research-boundary.md`](research-boundary.md) for sovereignty and external-effect rules.
- Use [`LAW-PROFILES-C0.md`](LAW-PROFILES-C0.md) for constitutional/profile/evaluator classification.
- Use [`authority.md`](authority.md) to locate exact current and research authority.
- Use [`research-agenda.md`](research-agenda.md) for open falsifiers.
- Read a C1/AF/AE/EC/AC/IF document only when you need the exact experiment that supports or challenges one retained law.
