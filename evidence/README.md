---
schema_version: 1
id: security.evidence
title: Evidence
type: reference
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - evaluator
  - maintainer
  - agent
updated: 2026-08-05
summary: Evidence contract for active Contest, CAGE, and software Evaluation bundles plus frozen Round 1 reports.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security-evidence
related:
  - security.architecture
  - security.research-boundary
  - security.evaluation-trial-p0
  - security.migration.round2
  - security.migration.round3-p0
  - security.authority
---
# Evidence

## Active Contest bundle

Every active Trial writes:

```text
manifest.json
trial-identity.json
raw-metrics.json
result.json
bundle-manifest.json
operational-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
  operational.jsonl
```

Each semantic channel has its own sequence and hash chain. The semantic bundle manifest binds event counts, chain heads, file digests, Scenario digest, Trial execution identity, raw metrics digest, and result digest. The operational stream has a separate wall-clock hash chain and manifest bound to the semantic evidence digest; its variability does not alter deterministic semantic replay. Actor events may contain only the observation admitted to that Actor; hidden world truth belongs exclusively to the truth channel.

An active claim is inadmissible when:

- Scenario, Security implementation, evidence schema, Actor implementation, Range adapter/substrate, seed, Action grant, or limits are missing from identity;
- Actor context leaks hidden truth;
- sensor telemetry is treated as infallible world truth;
- a proposal is presented as a verified effect;
- raw metrics or individual Trials are discarded in favour of one aggregate score;
- event bytes, sequence, previous digest, or bundle summaries fail verification;
- secrets, real endpoints, third-party credentials, packet captures, or unauthorized artifacts enter Git.

## Active Evaluation bundle

Every software Evaluation Run writes:

```text
evaluation-spec.json
execution-identity.json
findings.json
result.json
bundle-manifest.json
operational-manifest.json
events/
  sample.jsonl
  management.jsonl
  observer.jsonl
  guardian.jsonl
  world-truth.jsonl
  operational.jsonl
```

The Sample channel contains identity and digest references only. Sample bytes remain in the local SampleVault and are inadmissible in Git, semantic evidence, operational evidence, Host state, or model Provider prompts.

An Evaluation claim is inadmissible when Authority does not bind the exact Sample and environment, identity omits a relevant policy or image revision, Observer and Guardian authority are conflated, residual closure is incomplete, Findings omit exact evidence references, or any event or manifest fails verification. `no-issue-observed` is bounded to the exact Run and is not a general software-safety guarantee.

The current fixture backend never invokes Sample bytes. Its evidence proves the local protocol and failure closure, not software behavior.

## CAGE evidence

A CAGE Trial additionally binds:

- source repository and exact revision;
- semantic Range configuration digest;
- Red and Blue Security Actor plans;
- number of CAGE Red and Blue agents;
- number of externally submitted actions;
- explicit assertion that Red/Blue default action use is zero;
- concrete native action names;
- rewards, mission phases, and Red foothold counts;
- management-plane truth summary.

The adapter rejects a dirty source tree or an import from another checkout. Local checkout paths are operational locators and do not enter experiment identity. A claim that Ordivon controlled CAGE Red/Blue is inadmissible unless the external action count equals the number of controlled CAGE agents multiplied by executed ticks.

CAGE observations and rewards remain simulator outputs. The current team-plan bridge does not prove that Security or a model selected each concrete parameterized native action.

## Repository retention

Small sanitized bundles required for a published claim may be committed under a named experiment directory. Large raw Trials, sensitive captures, Provider secrets, and ephemeral range images remain outside Git but must be referenced by stable Artifact identity when used.

## Frozen Round 1 evidence

The following remain historical evidence for revision `92c0f9497741c3cde542c347318d2372fb884e30`:

- [`experiments/round1-20260730.json`](experiments/round1-20260730.json);
- [`r-a-control-boundary/report.json`](r-a-control-boundary/report.json).

Their old schema remains valid for those historical claims but is not the active Contest evidence contract. Exact digests and test baseline are recorded in [`../docs/archive/round1/system.md`](../docs/archive/round1/system.md).
