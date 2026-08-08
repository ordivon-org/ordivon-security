---
schema_version: 1
id: security.world-entity-migration-recovery
title: World Entity Migration Recovery Boundary
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - agent
updated: 2026-08-08
summary: Deterministic current-law baseline for World Entity KVM materialization: fresh execution and stable historical receipts remain supported, while every unpublished native state is observation-only UNKNOWN and no successor rewrites predecessor owner authority.
evidence_status: deterministic
readiness: EXPERIMENTAL
applies_to:
  - world-entity-migration
  - windows-kvm
related:
  - security.mid-successor-recovery-c1g
  - security.successor-ownership-c1e
  - security.partial-materialization-c1c
  - security.law-profiles-c0
---
# World Entity Migration Recovery Boundary

## Question

The earlier W2 Entity experiment proved that Security can materialize an opaque World Entity continuity payload as a contained Windows KVM carrier. Its recovery implementation also allowed a fresh controller to claim an existing machine state and rewrote `ownerPid` / `ownerStartTime` to that controller.

C1-E through C1-G later established a stronger recovery law for persistent physical worlds: predecessor ownership is historical provenance, current recovery authority is a separate fact, and a durable ledger generation does not by itself reveal current physical progress.

The integration question is therefore narrower than "can the old Entity branch still merge?":

> Can the useful Entity materialization semantics survive after removing owner takeover and blind continuation from unpublished native state?

## Baseline

The current experimental destination keeps the original source binding, continuity carrier, no-network topology check, and historical materialization receipt. It changes recovery semantics to the following table.

| Observed state | Result | Mutation during recovery |
|---|---|---|
| no Run and no ledger | `not_committed` | none |
| retained exact materialization receipt | `materialized` | none |
| exact stable `migration-running-contained` ledger | reconstruct historical `materialized` receipt | receipt persistence only |
| Run without ledger | `unknown` | none |
| `migration-staged` ledger | `unknown` | none |
| `swtpm-started` ledger | `unknown` | none |
| `executing` ledger | `unknown` | none |
| launch evidence not represented by a stable publication | `unknown` | none |

A new `materialize` request follows the same rule. If an exact unpublished ledger already exists, it does not resume that native Run and does not start another body.

## Falsifier result

The deterministic fault model constructs an `executing` Entity ledger whose predecessor owner is deliberately fixed to another PID/start-time pair. Reconciliation then asserts all of the following simultaneously:

```text
status = UNKNOWN
ledger bytes unchanged
ownerPid unchanged
ownerStartTime unchanged
Provider persist calls unchanged
QMP inspect calls unchanged
```

A second test retains only a `migration-staged` pre-body fence and retries `materialize`. The destination returns `UNKNOWN` and starts neither swtpm nor QEMU.

These checks directly reject the previous recovery behavior in which a successor could call `claim_existing_state`, rewrite Provider ownership, and continue an `executing` Run.

## What remains valid from the earlier Entity experiment

The following semantics survive unchanged:

- migration identity binds one exact Entity, source World, destination World, source-departure digest, and continuity-payload digest;
- the continuity payload remains opaque to Security and is staged on a removable FAT carrier;
- Guest self-report is not destination materialization authority;
- the KVM carrier is launched without a network device;
- an exact stable materialization publication can reconstruct a lost historical receipt without launching a second body;
- changed source departure, continuity payload, environment generation, or materialization identity fails closed.

The execution identity is revision `2` and explicitly declares:

```text
recoveryMode = observe-only-no-owner-rewrite
unpublishedNativeState = unknown
```

## What this does not prove

This is not yet physical crash-recovery acceptance and does not promote Entity Migration to the World production contract surface. In particular, it does not prove:

- safe successor continuation after controller death;
- cleanup or retry authorization for a retained pre-body fence;
- completed-but-unpublished native materialization detection;
- current Entity presence from a historical materialization receipt;
- authenticated source-World authority beyond the current caller trust boundary;
- distributed recovery or multi-host arbitration.

## Next pressure

The next experiment should kill a real Entity materialization controller at distinct native windows, especially after QEMU exists but before `migration-running-contained` publication. A fresh controller should first re-observe the physical carrier and must not mutate merely because the inherited ledger is exact.

The useful falsifier is the C1-G boundary applied to Entity migration:

```text
completed but unpublished
vs
still partial
```

Only if independent observation can distinguish those states should successor continuation or cleanup be introduced. If it cannot, the missing evidence should be identified before adding a generic recovery framework.
