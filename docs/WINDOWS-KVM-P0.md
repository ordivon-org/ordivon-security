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
updated: 2026-08-06
summary: P0-admitted disposable Windows Evaluation Provider using QEMU/KVM, exact sealed images, management-plane no-network verification, benign-fixture-only admission, evidence export, and residual closure.
evidence_status: verified
readiness: READY
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

Windows KVM Provider P0 is **admitted for one exact bounded action**:

```text
execute-benign-fixture
```

The admission is bound to:

- sealed environment image digest
  `sha256:58d02c9d7b800b8f63ecabe451843c5d06725077f540ecffc99e24549f9412c1`;
- Windows build `10.0.26200.0`;
- implementation revision `5c6a854` for disposable Run execution and closure;
- the locally compiled `ordivon-benign-v1` fixture and its exact compilation
  attestation;
- 5120 MiB RAM, 4 vCPUs, deny-all networking, and QMP verification of zero
  emulated network devices.

The retained receipts prove all P0 gates:

1. the exact Windows base image was built, emitted Guest-ready evidence, shut
   down automatically, passed `qemu-img check`, and was sealed;
2. the exact benign fixture completed with `no-issue-observed` and complete
   residual closure;
3. a wrong Sample digest and an unknown action were rejected before a Run
   directory, QEMU process, or swtpm process was created;
4. a 20-second Guardian runtime bound terminated the Run and removed all
   disposable state;
5. an external Ordivon Runtime cancellation produced an invalid Trial, while
   still closing QEMU, swtpm, the Run directory, and the compiled fixture.

The sanitized public acceptance index is [`../evidence/acceptance/windows-kvm-p0-5c6a854.json`](../evidence/acceptance/windows-kvm-p0-5c6a854.json). The complete private admission and diagnostic-cleanup receipts remain under the local Provider receipt root. Raw failed-VM disks, FAT configuration/result media, temporary unattend state, registry hives, UEFI/TPM state, and cancellation overlays were removed after bounded root-cause summaries were retained.

This is a **limited P0 admission**, not a general-purpose malware sandbox. No
unknown Sample, third-party installer, or retained 目标产品B Case is admitted.

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

- QEMU `q35` with KVM, SMM disabled, and Secure Boot disabled for the audited nested environment;
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

Each QEMU and swtpm process is bound at launch to its PID and Linux process
start-time from `/proc/<pid>/stat`. The command line remains a secondary identity
check while it is available. A reused PID with a different start-time is never
signalled. A matching process that is already exiting or in zombie state is
waited for or reaped before closure is decided. Runtime `SIGTERM` and `SIGINT`
are translated into controlled Evaluation cancellation so `destroy` and CLI
fixture cleanup still run. Any remaining process or path makes the Trial
invalid.

## Current verified scope

Real execution from the admitted local configuration proves:

- the original Microsoft UDF installation media and sealed qcow2/UEFI identities
  are bound into the base manifest;
- Windows build `10.0.26200.0` completes unattended setup with 5120 MiB RAM and
  four vCPUs;
- QMP reports no PCI network-class device during base construction, benign
  execution, timeout termination, and cancellation testing;
- the exact locally compiled benign fixture starts one child process, waits for
  it, returns exit code zero, declares `networkRequested: false`, and emits
  bounded Guest evidence;
- Guest-side hidden pseudo-adapters may be enumerated as `Not Present`; they do
  not override the management-plane QMP network authority;
- wrong Sample identity and unknown action fail before VM creation;
- Guardian timeout closes QEMU, swtpm, overlay, UEFI copy, TPM state, Run disk,
  sockets, and the Run directory;
- Runtime cancellation is recorded as an invalid Trial and still produces clean
  residual closure;
- PID reuse protection remains active through PID plus process start-time
  identity.

Repository gates at admission included 17 Windows KVM tests, 75 passing tests in
the full suite, four environment-dependent skips, Ruff, Mypy, and PowerShell AST
validation.

## Admission decision

**Admitted: Windows KVM Provider P0, exact benign-fixture scope only.**

The admission permits only:

```text
fixtureId: ordivon-benign-v1
action: execute-benign-fixture
network: deny-all
```

It does not authorize:

- arbitrary PE execution;
- third-party installers;
- internet-connected detonation;
- production secrets or user data;
- the retained 目标产品B  Case;
- claims of resistance to hypervisor escape, hardware side channels, or every
  Windows kernel attack.

Any broader Sample class requires a separate Provider profile, admission schema,
resource model, evidence plan, and real acceptance gate. The planned 
work therefore belongs to a later P1 large-Sample path and cannot reuse this P0
admission by changing a size limit or bypassing the fixture identity checks.
