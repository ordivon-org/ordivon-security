# TS9 — Virtualization displacement assessment

TS9 asks a deletion question, not a tooling popularity question: **would libvirt or Packer let Security delete mechanical virtualization code without losing the evidence and recovery laws its Windows KVM world already proved?**

The deterministic assessment is `scripts/assess_virtualization_displacement.py`. It measures the current provider/build/range sources and keeps three responsibilities separate:

1. generic VM/image mechanics;
2. Security-owned admission/evidence/reconciliation semantics;
3. external challenger supply/runtime authority.

## Result

- **libvirt: defer, do not acquire now.** It is a legitimate generic domain-lifecycle abstraction and can provide QEMU-specific monitor access, but the current Security value is concentrated in exact QMP observations, QEMU/swtpm process identity, root-owned ledgers, controller-loss recovery and residual closure. A libvirt daemon/domain model would currently add another state owner before it deletes those semantics.
- **Packer: retain as a targeted base-image challenger.** Its QEMU builder aligns with the ISO/UEFI/TPM/boot/install/shutdown image-building responsibility. It does not align with live Range authority or recovery. Re-run the treatment when the Windows base must be rebuilt for a materially new observer/controller generation; compare resulting image bytes, build evidence, maintenance surface and removable plumbing before promotion.

No package is installed by TS9. Absence of `virsh`, `virt-install` and `packer` is retained as current substrate fact rather than treated as a defect. Acquisition belongs to a future exact treatment once a reconsideration trigger fires.

The retained law is: **mature provider mechanics should displace local plumbing only when they delete more state/authority surface than they introduce.** Feature overlap alone is insufficient.
