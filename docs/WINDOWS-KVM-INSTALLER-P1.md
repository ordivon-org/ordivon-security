---
schema_version: 1
id: security.windows-kvm-installer-p1
title: Windows KVM Installer Evaluation P1
type: specification
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - maintainer
  - evaluator
  - researcher
  - agent
updated: 2026-08-06
summary: Separate large-Sample Windows installer profile using exact Case identity and a QEMU-read-only NTFS input disk.
evidence_status: partial
readiness: CANDIDATE
applies_to:
  - ordivon-security-evaluation
related:
  - security.windows-kvm-p0
  - security.windows-kvm-recovery-p0.1
  - security.case-snapshot-p0
  - security.authority
---
# Windows KVM Installer Evaluation P1

P1 is a separate profile. It does not widen `execute-benign-fixture` and cannot reuse the P0 Authority.

The first implemented gate is media preparation only:

1. bind an exact Case, archive SHA-256, byte length, logical name, deny-all network mode, no-restart policy, and observation profile;
2. create an NTFS image sized from the exact source length;
3. copy the archive into the image;
4. stream the embedded file back through `ntfscat` and verify its SHA-256 and length;
5. verify the source did not change during preparation;
6. bind the exact Security source identity and SHA-256 identities of `mkntfs`, `ntfscp`, and `ntfscat`;
7. seal a private manifest with the preparation identity digest, media digest, and QEMU attachment arguments;
8. require `readonly=on`, `removable=on`, and serial `ORDIVON_P1`.

The retained 目标产品B profile at `research/cases/windows-kvm-p1-caseb-studio.json` authorizes only `prepare-authorized-windows-installer-media`. The real media gate passed from revision `bcac3cc`: the exact 7,428,655,207-byte archive was embedded in an 8 GiB NTFS image, streamed back with the same SHA-256, and bound to a QEMU-read-only topology. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-caseb-media-bcac3cc.json`](../evidence/acceptance/windows-kvm-p1-caseb-media-bcac3cc.json).

`executionAuthorized` remains false, so neither the archive nor any contained installer may be attached to a Guest or executed yet.

Later execution requires a new admitted Guest observation protocol, an exact installer path and arguments, pre/post system snapshots, real residual closure, and a separate acceptance decision.
