---
schema_version: 1
id: security.windows-kvm-p0
title: Windows KVM Provider P0
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
summary: Candidate disposable Windows Evaluation Provider using QEMU/KVM, exact sealed images, management-plane no-network verification, benign-fixture-only admission, evidence export, and residual closure.
evidence_status: partially_verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security-windows-kvm
related:
  - security.start
  - security.architecture
  - security.evaluation-trial-p0
  - security.case-snapshot-p0
  - security.evidence
  - security.authority
---
# Windows KVM Provider P0

## Status

The Provider implementation and its local KVM topology have passed unit, type,
package, and management-plane topology checks. It remains a **candidate** until
both of these real gates succeed from a clean Security revision:

1. build and seal one exact Windows base image;
2. complete one disposable Run using only the Ordivon-maintained benign fixture.

No unknown Sample is admitted by P0. The retained DaVinci Case and every other
third-party executable remain outside this Provider until a later explicit gate.

## Why this Provider exists

Static Evaluation can establish file identity, archive structure, scanner output,
and other data-plane observations. It cannot establish what software actually
does after execution. A prior Wine harness run also showed why executing directly
on the WSL host is insufficient: the output lacked an independent machine
identity, management-plane network facts, disposable state, and residual closure.

The Provider supplies the missing execution conditions without making Security a
new hypervisor implementation. QEMU/KVM owns machine virtualization; Windows owns
Guest semantics; Security owns admission, exact identity, management-plane
checks, evidence interpretation, and Run closure.

## Local provider selection

The actual host was audited before implementation:

- Windows 11 Home does not expose Windows Sandbox;
- the complete Hyper-V VM management stack is absent;
- WSL exposes `/dev/kvm` with KVM API version 12;
- irqchip, PIT, HPET, irqfd, ioeventfd, and AMD-V are available;
- local storage and memory are sufficient for one bounded VM.

The selected topology is therefore:

```text
Windows host
  └─ WSL
      └─ QEMU/KVM management plane
          └─ disposable Windows 11 Enterprise Evaluation VM
```

## Exact source and base-image identity

The base builder consumes the Microsoft Windows 11 Enterprise Evaluation 25H2
x64 en-US ISO. Source identity binds the complete local SHA-256 and byte length.
The HTTP ETag is retained separately and is not misrepresented as a content
SHA-256.

The installed image is sealed by binding:

- source ISO digest;
- qcow2 base-image digest;
- UEFI variable-store digest;
- OVMF code digest;
- Guest runner digest;
- Windows build reported from inside the Guest;
- machine, CPU, TPM, and no-network topology.

The resulting semantic digest becomes `EnvironmentIdentity.image_digest`.

## Base Builder

The build CLI is:

```bash
uv run ordivon-security-windows-kvm-build \
  --source-iso /var/lib/ordivon/security/providers/windows-kvm/sources/windows-11-enterprise-eval-25h2-x64-en-us.iso \
  --state-root /var/lib/ordivon/security/providers/windows-kvm
```

It:

1. verifies all local dependencies and source bytes;
2. overlays an unattended answer file and `$OEM$` resources onto the official ISO;
3. creates a new qcow2 disk and private UEFI variable store;
4. creates a disposable software TPM 2.0 state;
5. starts QEMU as the unprivileged `qemu` account;
6. configures no network device;
7. checks the QMP PCI tree and fails if a network-class device exists;
8. requires Guest `base-ready.json` evidence;
9. runs `qemu-img check`;
10. hashes and seals the base image and UEFI state;
11. retains build command and provider logs;
12. removes temporary build state after success;
13. on failure, removes the complete temporary build tree and writes a private,
    non-secret failure receipt containing only source identity, error class, and
    cleanup status.

The temporary bootstrap password is generated per build, retained only in the
private build workspace and autoinstall ISO, and removed with that workspace. The
bootstrap account is disabled before the base-ready receipt is written.

## Disposable Run topology

Each Evaluation Run creates:

```text
sealed base qcow2 (read-only)
  └─ disposable qcow2 overlay

sealed base UEFI variables
  └─ disposable UEFI variables copy

new disposable TPM state
new FAT run/result disk
new QMP Unix socket
new QEMU and swtpm processes
```

The VM command uses:

- QEMU `q35` with KVM and SMM;
- host CPU exposure;
- fixed vCPU and memory bounds;
- OVMF UEFI;
- TPM 2.0 through `swtpm`;
- an IDE/SATA qcow2 system disk;
- one USB FAT run disk;
- a virtual RNG;
- `-nodefaults` and `-nic none`;
- no display, serial console, monitor, shared folder, clipboard, or host port.

QEMU and swtpm run as the existing unprivileged `qemu` service account, not as
root. Root owns the sealed images and Provider authority; the `qemu` group receives
only traversal and read access needed by the process.

## Management-plane network authority

The Provider does not rely on Windows Firewall for P0 deny-all semantics. The
QEMU command creates no NIC, and after startup Security independently calls QMP
`query-pci`. Any PCI class from `0x0200` through `0x02ff` causes Guardian
termination.

Guest `Get-NetAdapter` output is retained as an Observer result. QMP remains the
network-device authority because it is outside the evaluated Guest.

This proves absence of an emulated PCI network controller in the admitted
configuration. It does not yet prove resistance to every hypervisor escape or
hardware side channel.

## Benign fixture gate

P0 admits exactly one action:

```text
execute-benign-fixture
```

The Sample must:

- use PE media type;
- match the exact `admittedSampleDigest` bound into Provider execution identity;
- carry metadata `fixtureId = ordivon-benign-v1`;
- match the exact fixture compilation-attestation digest bound into Provider identity;
- be authorized for the exact Windows environment;
- deny network access;
- remain within memory, process, runtime, and Artifact limits.

The acceptance CLI compiles `benign_fixture.c` locally with MinGW, records source,
compiler, output, and attestation digests, rejects network-library imports, and
constructs a Provider instance that admits only that exact output digest. The fixture:

1. starts one child copy of itself;
2. waits for the child to exit;
3. writes a bounded JSON result;
4. declares `networkRequested: false`;
5. exits without persistence, Registry, service, or network actions.

```bash
uv run ordivon-security-windows-kvm-acceptance \
  --base-manifest /var/lib/ordivon/security/providers/windows-kvm/images/<base>.manifest.json \
  --state-root /var/lib/ordivon/security/providers/windows-kvm \
  --vault /var/lib/ordivon/security/vault \
  --evidence /var/lib/ordivon/security/evidence
```

The CLI exits non-zero unless the Result is `no-issue-observed`, terminal reason is
`benign-fixture-completed`, and residual closure is true.

## Evidence and authority

The management plane owns:

- QEMU and swtpm binary identity;
- sealed base and disposable overlay identity;
- QMP status and PCI topology;
- VM process lifecycle;
- timeout and forced termination;
- deletion of Run state.

The Guest runner owns only its bounded execution report. The fixture owns its own
JSON output. Neither may claim network-device absence, machine destruction, or
residual closure.

The Run may retain these Artifacts:

- Guest execution result;
- benign fixture result;
- Guest runner log;
- QEMU stdout and stderr.

Sample bytes remain in SampleVault and the temporary FAT Run disk; they are not
written into semantic or operational Evidence.

## Residual closure

`destroy` verifies or enforces:

- QEMU process exit;
- swtpm process exit;
- deletion of overlay disk;
- deletion of disposable UEFI state;
- deletion of TPM state;
- deletion of FAT run disk;
- deletion of QMP and TPM sockets;
- deletion of the complete Run directory.

A PID is terminated only when `/proc/<pid>/cmdline` still identifies the expected
QEMU or swtpm process. PID reuse cannot authorize killing an unrelated process.
Any remaining process or path makes the Trial invalid.

## Current verified scope

Before real base-image admission, the repository tests already prove:

- exact base-manifest digest validation and tamper rejection;
- install and runtime QEMU arguments contain `-nic none` and no `-netdev`;
- a real KVM/QMP topology starts and reports no network PCI class;
- QMP network-class detection terminates on an injected Ethernet-class record;
- only the exact benign action, compiled Sample digest, and compilation attestation are admitted;
- network authority, wrong media type, wrong image, and process-limit drift fail closed;
- complete Run-directory deletion is required;
- all Guest resources are included in the package;
- the benign fixture source and PE imports contain no admitted network API.

## Admission decision

The Provider is admitted only after a clean-revision base build and benign Run
produce retained receipts proving:

1. source and base image identity;
2. QMP-confirmed no-network topology;
3. exact fixture Sample and execution result;
4. bounded runtime;
5. independently verified Evaluation Evidence;
6. QEMU, swtpm, sockets, overlay, TPM state, and Run directory removed;
7. no unknown Sample executed.

Until then, this document describes a tested **candidate**, not a production
sandbox and not authorization to run the retained DaVinci Case.
