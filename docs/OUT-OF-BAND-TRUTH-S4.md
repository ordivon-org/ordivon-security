---
schema_version: 1
id: security.out-of-band-truth-s4
title: Out-of-band Disk Truth S4
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
summary: First accepted world-truth path for the sacrificial Windows Range, reconstructing selected persistent filesystem state from the stopped disposable overlay without trusting Guest reports.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.sacrificial-node-s3
  - security.windows-kvm-substrate-s2
  - security.architecture
---
# Out-of-band Disk Truth S4

## Graduation question

> When Guest sensors disappear or lie, can Security reconstruct important world facts without promoting the Guest back to authority?

S4 answers **yes for a deliberately small post-run disk-state subset** of the maintained S3 challenge. It does not claim complete Guest introspection.

## Why S4 exists

S3 proved that QMP/process/ledger/closure authority survives Guest-side observer and bootstrap loss, but persistence and log-deletion facts still came from `guest-claim-not-world-truth`.

S4 removes that dependency for selected persistent filesystem facts. After QEMU exits and before the disposable overlay is destroyed, the Host reads the Windows filesystem through a separate read-only path.

## Out-of-band reader

`WindowsOfflineNtfsInspector` uses mature host facilities rather than a new disk or EDR stack:

```text
stopped qcow2 backing-chain view
        ↓
qemu-nbd --read-only
        ↓
verify kernel NBD ro=1
        ↓
partx partition discovery
        ↓
ntfsls identifies the Windows partition
        ↓
ntfscat bounded exact-file reads
        ↓
SHA-256 / presence / absence / bounded text checks
        ↓
NBD disconnect verified before Range closure
```

The inspector never mounts the filesystem writable and never asks the Guest to report these facts.

## Range evidence separation

S4 adds one Range event plane because a real producer now exists:

```text
management   lifecycle / containment / closure
contested    Guest claims
world-truth  independent Host observations of world state
```

It does **not** pre-create sensor, Actor-belief, or shared-information schemas. Those remain future consumers, not current abstractions.

The S4 physical run therefore records:

```text
guest.sacrificial-canary-claim  → contested
world.disk-state-observed       → world-truth
```

## Accepted facts

The accepted run first verifies that the sealed base image contains none of the S3 synthetic objects. After the Guest-originated QMP reset and final machine exit, the Host independently observes:

- `/ProgramData/Ordivon/S3/s3-canary.exe` exists and its digest equals the exact maintained canary;
- `/Windows/System32/Tasks/OrdivonS3CanaryPersistence` exists;
- the task contains the persisted-canary executable path and a separate `--persisted` argument;
- `persistence-fired.marker` exists with the exact maintained content digest;
- `synthetic-log-deleted.marker` exists with the exact maintained content digest;
- `synthetic-guest.log` is absent;
- QMP independently observed the Guest reset;
- QEMU/swtpm, the disposable run directory, and the root-owned ledger still close with zero residual objects.

The Guest result is retained only as challenge-completeness evidence. None of the disk-state acceptance facts depend on it.

## Real failure and correction

The first S4 physical run correctly failed one disk-truth gate even though every file-presence/digest fact was already visible externally. The implementation assumed Task Scheduler would store the executable and its argument as one continuous XML string.

A read of the existing sealed `OrdivonGuestRunner` task showed the actual representation:

```text
<Command>...</Command>
<Arguments>...</Arguments>
```

S4 therefore changed the external check to require the persisted executable and `--persisted` argument independently. The acceptance gate was not weakened; the representation assumption was corrected. The next physical run passed all facts.

The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-s4-out-of-band-truth-0f9d35a.json`](../evidence/acceptance/windows-kvm-s4-out-of-band-truth-0f9d35a.json).

## What S4 proves

For the maintained single-node challenge, Security can now distinguish:

```text
Guest says persistence exists          → contested claim
Host reads exact persisted bytes       → world truth
Guest says a log was deleted           → contested claim
Host observes exact deletion marker
and target log absence                 → world truth
```

This is the first physical Range path where a meaningful Guest-state conclusion survives removal of Guest reporting authority.

## What S4 does not prove

S4 does not provide:

- live filesystem or memory introspection while the machine is running;
- complete filesystem diff or attribution of which process caused a change;
- Registry, service, process, credential, or memory truth in general;
- network truth or packet capture;
- multiple nodes or lateral movement;
- unknown or third-party malware execution;
- autonomous Agents or evaluator warfare.

Those omissions were intentional. S4 had no contested network, so building network telemetry there would have manufactured a consumer. The next pressure was therefore to introduce real contested networking while keeping topology, containment, lifecycle, and observation authority outside the Guest. Post-S4 physical probes later narrowed that question further: S5 first tested one real Windows Guest plus one lightweight peer rather than assuming several full VMs were required.
