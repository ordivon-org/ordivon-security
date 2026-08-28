---
schema_version: 1
id: security.sacrificial-node-s3
title: Sacrificial Windows Node S3
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
summary: Physical acceptance boundary for one disposable Windows Guest that may destroy Guest-side observation and persistence assumptions while management-plane lifecycle, containment, and closure remain authoritative outside the Guest.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.range-session-s0
  - security.windows-kvm-substrate-s2
  - security.architecture
---
# Sacrificial Windows Node S3

## Graduation question

> If the Guest becomes untrusted or unavailable, do external lifecycle and containment facts remain trustworthy?

S3 answers only this question. It is a single-node physical falsifier for the S0-S2 architecture, not a general cyber range and not an attempt to explain everything that happened inside Windows.

## Challenge

`AdversarialWindowsRange` reuses `WindowsKvmMachineProvider` and boots one disposable Windows node with no emulated network device. A maintained sacrificial canary is allowed to damage assumptions that earlier Evaluation flows treated as convenient:

- spawn and terminate a dedicated Guest-side observer;
- install synthetic `ONSTART` persistence;
- terminate the Guest bootstrap/runner that launched it;
- delete a synthetic Guest-only log;
- request a forced reboot;
- continue after reboot through the synthetic persistence path.

These effects occur only inside the disposable VM. The canary imports no admitted network API and the QEMU topology uses `-nic none`.

## Authority split

S3 deliberately separates two classes of evidence.

### Management truth

The following facts are owned outside the Guest and are admissible for the S3 graduation claim:

- QMP `query-pci` owns the absence of a network-class PCI device;
- QMP owns the observed machine `RESET` event;
- the host QEMU process identity owns machine execution/exit state;
- the root-owned machine ledger binds the Range Session and disposable resources;
- provider destruction owns QEMU/swtpm termination, run-directory removal, ledger removal, and residual closure.

### Contested Guest claim

The extracted canary result reports that observer termination, runner termination, persistence, log deletion, and reboot continuation occurred. It is explicitly recorded as:

```text
guest-claim-not-world-truth
```

The claim is useful to show that the maintained challenge reached its intended path, but it does not become world truth merely because the Guest reports success. S3 therefore does **not** claim independent knowledge of who changed which Guest object or why. That missing authority is the next research problem, not a reason to strengthen the Guest Observer.

## Acceptance

The S3 management claim passes only when all of the following external gates hold for the same disposable node:

1. QMP confirms no network-class PCI device;
2. QMP independently observes a Guest-originated reset;
3. the QEMU lifecycle remains observable through machine exit;
4. destruction closes QEMU and swtpm;
5. the disposable run directory and root-owned ledger are removed;
6. residual objects are empty.

The physical trial additionally requires the exact maintained canary to report completion so that a trivial boot-and-shutdown cannot masquerade as exercising the challenge. That Guest report is a **trial-completeness condition**, not authority for the external S3 claim.

## Real failure and correction

The first physical run was correctly rejected even though the Guest claimed the complete challenge and residual closure was clean. The management-plane QMP watcher lost the `RESET` event after a buffered socket reader timeout and emitted `machine.reset-watch-ended` with `OSError` instead.

The correction changed QMP event waiting to one deadline-bounded blocking read. This fixed the external truth channel rather than making the Guest cooperate more. A unit regression prevents retrying a timed-out buffered QMP reader.

Subsequent physical runs observed `RESET` through QMP and passed all external gates. The final acceptance was rerun from a clean worktree and binds implementation revision `fc5740aa83df8d4ec2aae657e4f72810b982f6de` directly in Range execution identity. It is indexed by [`../evidence/acceptance/windows-kvm-s3-sacrificial-node-fc5740a.json`](../evidence/acceptance/windows-kvm-s3-sacrificial-node-fc5740a.json).

The S3 architecture, `AdversarialWindowsRange`, maintained canary source and unit regressions remain current. The one-shot physical orchestration module `cli_windows_kvm_s3_acceptance.py` was retired from HEAD on 2026-08-28 after its only remaining cross-module role (`_write_receipt`) was moved to neutral acceptance support. No current code/console consumer used the runner itself. Exact accepted apparatus remains recoverable from the bound `fc5740a` revision; rerunning that historical physical trial is therefore an explicit reproduction action, not a permanent default executable surface.

## What S3 proves

Within this maintained single-node challenge:

```text
Guest observer/bootstrap: disposable and killable
Guest report: contested
Guest reboot/persistence path: exercised
Management lifecycle truth: intact
No-NIC containment truth: intact
Residual closure: clean
```

This is the first physical acceptance that deliberately permits Guest-side observation assumptions to fail while keeping the management plane authoritative.

## What S3 does not prove

S3 does not provide:

- independent attribution of Guest file, Registry, service, task, or process changes;
- block-level or memory-level external truth;
- a contested network fabric;
- multiple nodes or lateral movement;
- Internet access;
- unknown or third-party malware execution;
- autonomous Red/Blue Agents;
- evaluator or evidence warfare.

The next unresolved question is therefore S4: **after Guest sensors disappear or lie, can external observation reconstruct the key world facts?** S3 does not pre-build that answer.
