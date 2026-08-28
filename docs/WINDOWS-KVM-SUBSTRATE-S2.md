---
schema_version: 1
id: security.windows-kvm-substrate-s2
title: Windows KVM Machine Substrate S2
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
summary: Machine-level Windows KVM Provider separated from Evaluation admission so disposable lifecycle, external topology truth, recovery primitives, and residual closure can be reused by future adversarial Ranges.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.range-session-s0
  - security.synchronous-contest-s1
  - security.windows-kvm-p0
  - security.windows-kvm-recovery-p0.1
  - security.persistent-range-recovery-s6r
  - security.architecture
---
# Windows KVM Machine Substrate S2

## Purpose

S2 separates **machine authority** from **software Evaluation admission**. The existing Windows Evaluation path previously owned both QEMU/KVM lifecycle mechanics and exact Sample/fixture policy. `WindowsKvmMachineProvider` now owns only reusable machine facts and effects; `WindowsKvmEvaluationBackend` remains the adapter that applies Evaluation-specific admission and Guardian semantics.

## Machine authority

`WindowsKvmMachineProvider` owns:

- sealed Windows base-image identity and digest verification;
- disposable qcow2 overlay creation;
- per-machine UEFI variable copies;
- disposable swtpm state and process identity;
- root-owned lifecycle ledgers;
- QEMU process launch plus QEMU/swtpm PID and process-start-time identity;
- QMP status and PCI topology inspection;
- machine shutdown/termination primitives;
- run-directory and ledger residual closure;
- low-level process and ledger helpers shared by hard-failure reconciliation.
- exact PID/start-time liveness observation through the Provider-owned `process_identity_alive()` primitive, shared by Evaluation and Range reconciliation rather than reimplemented per profile.

Its execution identity contains no Sample digest, fixture attestation, Evaluation action, or Guardian decision. Network policy is deliberately represented as `caller-supplied-qemu-topology`: the substrate can observe topology, but does not authorize one.

## Evaluation adapter

`WindowsKvmEvaluationBackend` still owns:

- exact Sample and maintained-fixture admission;
- `EvaluationSpec`, Authority, Environment, Guardian, and Observation bindings;
- the accepted deny-all QEMU topology and writable Evaluation Run disk;
- Sample staging and Guest Runner protocol;
- runtime bounds and Guardian interpretation of Provider topology;
- Guest-result extraction, Evaluation Artifacts, Findings, and result semantics.

The accepted P0 Evaluation scope therefore does not expand. Unknown Samples and third-party installers remain outside the admitted execution path.

## Reuse boundary

```text
WindowsKvmMachineProvider
  ├─ base / overlay / UEFI / TPM
  ├─ root-owned ledger
  ├─ process identity
  ├─ QMP topology truth
  ├─ terminate / destroy / recovery primitives
  │
  ├──── WindowsKvmEvaluationBackend
  │       └─ exact Sample + Guardian policy
  │
  └──── future AdversarialWindowsRange
          └─ sacrificial Guest + Range-local topology
```

Future War Range code must define its own Range authority, network topology, Actor access, and contested-world semantics. It must not inherit Evaluation's exact-fixture gate or Guest-process restrictions merely because both use the same machine Provider.

## S2 acceptance

S2 proves that:

- machine creation, ledger persistence, QMP topology, and destruction work without an `EvaluationSpec`;
- Provider identity contains no Evaluation Sample or fixture admission fields;
- a generic Range machine identity can use the same root-owned ledger and obtain clean residual closure;
- existing Windows Evaluation behavior remains compatible through a thin adapter;
- normal closure and policy-specific crash reconcilers can reuse the same low-level process/ledger truth primitives;
- existing Evaluation P0 tests and the full Security unit suite remain green.

S2 does **not** claim that every Provider consumer automatically has hard-failure reconciliation. P0.1 later accepts the Evaluation-specific reconciler; S6-R separately accepts the exact S5/S6 fabric-Range reconciliation policy on the same machine/process/ledger primitives. S2 also does not create a sacrificial War Range, enable Internet egress, execute an unknown Sample, run Case A, or prove that management truth survives a fully compromised Guest.
