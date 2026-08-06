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

The retained 目标产品B profile at `research/cases/windows-kvm-p1-caseb-studio.json` authorizes only `prepare-authorized-windows-installer-media`. The current media gate passed from revision `136a8a7`: the exact 7,428,655,207-byte archive was embedded in an 8 GiB NTFS image, streamed back with the same SHA-256, bound to a QEMU-read-only topology, and tied to the Security revision plus SHA-256 identities for `mkntfs`, `ntfscp`, and `ntfscat`. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-caseb-media-136a8a7.json`](../evidence/acceptance/windows-kvm-p1-caseb-media-136a8a7.json). The earlier `bcac3cc` media is retained only as a superseded pre-provenance record.

`executionAuthorized` remains false, so neither the archive nor any contained installer may be attached to a Guest or executed yet.

Later execution requires a new admitted Guest observation protocol, an exact installer path and arguments, pre/post system snapshots, real residual closure, and a separate acceptance decision.

## Static entry decision

The retained static decision at [`../research/cases/windows-kvm-p1-caseb-static-entry.json`](../research/cases/windows-kvm-p1-caseb-static-entry.json) rejects generation of an executable profile for the current Case. It binds the archive, wrapper, outer MSI, nested GetintoWAY MSI, embedded downloader script, replacement `intl.dll`, and main `Resolve.exe` identities.

The decisive evidence is the nested MSI first-install chain:

- `AI_DATA_SETTER` at sequence 6401;
- `PowerShellScriptInline` at sequence 6402;
- download from `corehubpro.com` through BITS or `System.Net.WebClient`;
- extraction of the downloaded ZIP;
- highest-privilege `OneDriveStandaloneUpdate####` scheduled-task creation;
- execution of every EXE found in the downloaded archive.

The exact runtime edge from the wrapper or outer MSI to the nested MSI is not yet fully traced. That uncertainty does not weaken the rejection decision: the distributed package contains the malicious installer and the current profile remains non-executable. The independent static gate passed from revision `91f08e0`; its sanitized index is [`../evidence/acceptance/windows-kvm-p1-caseb-static-91f08e0.json`](../evidence/acceptance/windows-kvm-p1-caseb-static-91f08e0.json).

## Observation contract

Future third-party installer execution requires the canonical profile at [`../research/profiles/windows-kvm-installer-observation-p1.json`](../research/profiles/windows-kvm-installer-observation-p1.json). It requires pre/post snapshots for files, Registry, services, drivers, scheduled tasks, BITS jobs, startup entries, installed products, users/groups, certificates, Defender, and Event Logs. It also requires a complete process tree, PowerShell script-block evidence, MSI and Task Scheduler events, QMP topology authority, host media identity, and residual closure.

The observation contract is evidence infrastructure only. It does not change `executionAuthorized`, bind an installer path, attach the current media, or start Windows.
