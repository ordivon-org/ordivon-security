---
schema_version: 1
id: security.evaluation-trial-p0
title: Evaluation Trial P0
type: architecture
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - builder
  - evaluator
  - operator
  - agent
updated: 2026-08-05
summary: Local non-executing foundation for authorized software Evaluation Trials, Sample identity, authority, environment binding, Observer and Guardian separation, residual closure, and sealed evidence.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security-evaluation
related:
  - security.start
  - security.architecture
  - security.research-boundary
  - security.evidence
  - security.authority
---
# Evaluation Trial P0

## Purpose

Evaluation Trial is the Security-owned protocol for determining what one exact software Sample did under one exact authorized environment and which conclusions are supported by retained evidence.

P0 prepares the local control and evidence infrastructure without executing unknown software. It deliberately stops before KVM, CAPE, hostile-code isolation, controlled egress, Guest monitoring, or real malware analysis.

## Ownership

Security owns:

- Sample, Authority, Environment, Evaluation Spec, Run, Finding, and disposition identities;
- admission and authorization checks;
- Observer and Guardian evidence separation;
- backend execution identity;
- residual-closure requirements;
- semantic and operational evidence sealing;
- the limits of the final conclusion.

Security does not own a hypervisor, container engine, operating-system monitor, network IDS, malware scanner, Provider runtime, or general workflow system.

Current Ordivon Runtime is not used to execute unknown software. Its `contained_local` profile reduces ambient authority for ordinary engineering workloads but does not claim hostile-code isolation, controlled egress, or disposable-machine semantics.

## P0 contracts

### `SampleIdentity`

Binds the SHA-256 digest, byte length, media type, and optional original name. The identity is derived from the complete Sample digest.

### `SampleVault`

Stores Sample bytes outside Git in a content-addressed local filesystem. It:

- writes files and manifests with owner-only permissions;
- verifies the complete digest and byte length on import and every resolve;
- rejects symlink imports;
- exposes only identity and a local path to an admitted backend;
- never places Sample bytes in semantic or operational evidence;
- emits an explicit purge receipt.

The P0 Vault is local infrastructure, not a secret broker, encrypted malware repository, multi-user service, or evidence database.

### `AuthorityManifest`

Binds one Sample digest to the operator, authorization basis, permitted environments, permitted and prohibited actions, maximum runtime, and network permission. An Evaluation Spec cannot broaden this authority.

### `GuardianPolicy`

Declares hard limits and boundary-termination conditions. P0 supports only `deny-all` and `simulated-only` network modes. The policy is part of Environment and Run identity.

### `ObservationPlan`

Declares which channels are expected, whether memory capture is requested, and the maximum event size. Observation records may classify behavior but do not themselves enforce the boundary.

### `EnvironmentIdentity`

Binds Provider, Provider revision, image, configuration, Guardian policy, and Observation plan. Machine-local Vault and output paths are excluded.

### `EvaluationSpec`

Combines the Sample, Authority, Environment, Guardian, Observation plan, requested actions, and metadata. Construction fails when:

- Authority references another Sample;
- the environment is not permitted;
- requested actions are not authorized;
- a requested action is prohibited;
- Guardian runtime exceeds Authority;
- Environment policy digests differ;
- network use is requested without permission.

### `EvaluationRangeBackend`

The backend boundary is intentionally narrow:

```text
create → stage → execute → destroy
```

Every backend exposes exact implementation and configuration identity. `destroy` must return a `ResidualClosureReceipt`; a Run with incomplete closure is invalid even when execution otherwise succeeded.

### `FixtureEvaluationBackend`

The first backend is deterministic and local. It verifies staged bytes and emits configured fixture observations, Guardian decisions, facts, and metrics, but never executes the Sample. Its execution identity states `sampleExecution: false`.

This backend exists to test the protocol before a hostile-code isolation provider is admitted.

## Observer and Guardian separation

P0 preserves two distinct authorities:

```text
Observer
  records and classifies behavior
  cannot alter the environment

Guardian
  enforces hard execution boundaries
  may terminate on a declared condition
```

A suspicious Observer event can create a Finding without terminating the Run. A Guardian termination remains explicit and does not automatically invent a malware Finding.

## Evidence

Every Evaluation Run writes:

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

Each semantic channel has its own sequence, previous digest, event digest, file digest, count, and chain head. Operational timing is independently chained and bound to the semantic bundle without changing semantic identity.

Sample bytes are not evidence content. Evidence contains only Sample identity and digest references.

## Findings and disposition

P0 includes deterministic rules for a small set of behavior records such as credential access, persistence, process injection, undeclared network communication, privilege expansion, destructive behavior, control tampering, and stability failure.

These rules produce evidence-bound Findings but do not claim final attribution. The current dispositions are:

- `confirmed-harmful-behavior`;
- `high-risk-capability`;
- `engineering-security-defect`;
- `suspicious-inconclusive`;
- `no-issue-observed`;
- `invalid-trial`.

P0 does not automatically emit `confirmed-harmful-behavior`; that conclusion requires a later explicit verdict policy and stronger evidence.

`no-issue-observed` means only that no admitted P0 rule found an issue in that exact Run. It is not a general safety claim.

## Local dry run

```bash
printf 'owned evaluation fixture\n' > /tmp/ordivon-evaluation-fixture.bin

uv run ordivon-security-evaluation-dry-run \
  --sample /tmp/ordivon-evaluation-fixture.bin \
  --vault /tmp/ordivon-evaluation-vault \
  --output /tmp/ordivon-evaluation-evidence
```

The command imports and verifies Sample bytes, runs the non-executing fixture backend, proves residual closure, seals both evidence bundles, and prints the Result. It does not invoke or load the Sample as executable code.

## P0 acceptance

The unit suite proves:

- Vault import, resolve, tamper rejection, and purge receipt;
- Sample bytes do not enter any evidence file;
- environment changes alter identity;
- unauthorized network mode is rejected;
- Observer findings do not become Guardian actions;
- Guardian termination does not invent a Finding;
- backend failure still invokes destruction and seals an invalid Trial;
- incomplete residual closure invalidates success;
- semantic evidence tampering is detected;
- operational evidence is independently verifiable.

## Next gate

P0-B may add one external hostile-code isolation provider only after its local owner can prove:

1. clean disposable machine creation from an exact image;
2. management-plane separation;
3. deny-all egress before Sample staging;
4. bounded execution and forced termination;
5. independent evidence export;
6. destruction and residual closure;
7. no Sample or credential leakage into Git, Runtime logs, Host state, or model Provider prompts.

The first real backend should remain an integration behind `EvaluationRangeBackend`; it must not turn Security or Runtime into a hypervisor or malware-sandbox implementation.
