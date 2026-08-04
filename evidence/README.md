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
updated: 2026-08-04
summary: Evidence contract for active multi-channel Contest bundles and frozen Round 1 reports.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security-evidence
related:
  - security.architecture
  - security.research-boundary
  - security.authority
---
# Evidence

## Active Contest bundle

Every active Trial writes:

```text
manifest.json
raw-metrics.json
result.json
bundle-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
```

Each channel has its own sequence and hash chain. The bundle manifest binds event counts, chain heads, file digests, Scenario digest, raw metrics digest, and result digest. Actor events may contain only the observation admitted to that Actor; hidden world truth belongs exclusively to the truth channel.

An active claim is inadmissible when:

- Scenario, Actor backend, Range, seed, Action grant, or limits are missing from identity;
- Actor context leaks hidden truth;
- sensor telemetry is treated as infallible world truth;
- a proposal is presented as a verified effect;
- raw metrics or individual Trials are discarded in favour of one aggregate score;
- event bytes, sequence, previous digest, or bundle summaries fail verification;
- secrets, real endpoints, third-party credentials, packet captures, or unauthorized artifacts enter Git.

## Repository retention

Small sanitized bundles required for a published claim may be committed under a named experiment directory. Large raw Trials, sensitive captures, provider secrets, and ephemeral range images remain outside Git but must be referenced by stable Artifact identity when used.

## Frozen Round 1 evidence

The following remain historical evidence for revision `92c0f9497741c3cde542c347318d2372fb884e30`:

- [`experiments/round1-20260730.json`](experiments/round1-20260730.json);
- [`r-a-control-boundary/report.json`](r-a-control-boundary/report.json).

Their old schema remains valid for those historical claims but is not the active Contest evidence contract. Exact digests and test baseline are recorded in [`../docs/archive/round1/system.md`](../docs/archive/round1/system.md).
