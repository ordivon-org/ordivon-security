# Provider-First Security — PF0

Status: project responsibility audit — 2026-08-14

## Boundary

Security should own adversarial semantics and evidence, not generic virtualization or security-product mechanisms.

This is consistent with `CHARTER.md`: hypervisors, network emulators, scanners, EDR/SIEM, databases, C2 systems, and vulnerability databases remain external owners. Security binds their capabilities and evidence when useful.

## Current high-pressure mechanism

The largest provider-ownership pressure is the Windows KVM apparatus. Selected current modules include:

- `providers/windows_kvm.py` — 1079 LOC;
- `range/windows_fabric.py` — 939 LOC;
- `evaluation/windows_kvm.py` — 855 LOC;
- `evaluation/windows_kvm_build.py` — 791 LOC;
- `evaluation/windows_kvm_p1_derived_base.py` — 642 LOC;
- `range/windows_sacrificial.py` — 618 LOC.

LOC is not a deletion target. The responsibility split is.

## RETAIN / INNOVATE

Security keeps responsibilities that survive every VM/provider substitution:

- adversarial authority and explicit action scope;
- partial-information and epistemic state;
- contest/scenario semantics;
- independent consequence evidence;
- ambiguity and `UNKNOWN` preservation;
- fault injection and recovery experiments;
- evaluator/sensor integrity;
- exact experiment identity and evidence lineage;
- guest claims versus independent sensor truth;
- checkpoint and historical acceptance evidence.

Historical acceptance runners are research apparatus. Replacing the physical VM owner does not erase the conclusions they established.

## DELEGATE candidates

### Generic VM lifecycle

Candidate owner: **libvirt**.

Potentially displaced responsibilities include:

- generic domain create/start/stop/destroy mechanics;
- generic QEMU monitor/session lifecycle;
- standard domain/network/storage/snapshot representation;
- provider-native VM event observation.

Security must still bind exact provider identity and independent experiment evidence.

### Reproducible image construction

Candidate owner: **Packer QEMU builder**.

Potentially displaced responsibilities include generic boot/install/provision/shutdown image-build procedure. Security retains source authority, sample/media admission, immutable evidence, and experiment-specific sealing claims.

### Filesystem/image manipulation

Candidate family: libguestfs or another mature image-inspection owner, but only after a measured need. Do not introduce it merely to make the stack symmetrical.

## Local substrate evidence

Current WSL substrate observation:

```text
qemu-system-x86_64  11.0.3
qemu-img            11.0.3
swtpm                0.10.1

virsh                absent
virt-install         absent
libguestfs tools     absent
packer               absent
vagrant              absent
libvirt services     inactive/absent
```

Therefore PF0 does **not** authorize immediate replacement. Current custom QEMU ownership partly fills a real local substrate gap.

## PF1 decision rule

Before installing libvirt or Packer, measure displacement potential against current responsibilities:

```text
current Security mechanism
→ provider-native equivalent exists?
→ does it preserve exact experiment authority/evidence?
→ how much current mechanism disappears?
→ how thick is the residual adapter?
→ what new service/config/migration cost appears?
```

Adopt only if total owned mechanism decreases materially.

## Desired target shape

```text
Security contest / range semantics
        ↓
exact provider binding + evidence adapter
        ↓
libvirt / Packer / QEMU / other specialist owner
```

Not:

```text
Security
→ reimplements another hypervisor control plane
```

## Freeze

Until PF1 comparison is complete:

- do not add new generic VM lifecycle features;
- do not add another image-builder framework inside Security;
- do not add generic scanners/sensors that mature external tools already own;
- correctness fixes and experiment-specific evidence work remain allowed.
