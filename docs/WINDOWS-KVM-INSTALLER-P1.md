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

The retained DaVinci profile at `research/cases/windows-kvm-p1-davinci-resolve-studio-21.0.3.7.json` authorizes only `prepare-authorized-windows-installer-media`. The current media gate passed from revision `136a8a7`: the exact 7,428,655,207-byte archive was embedded in an 8 GiB NTFS image, streamed back with the same SHA-256, bound to a QEMU-read-only topology, and tied to the Security revision plus SHA-256 identities for `mkntfs`, `ntfscp`, and `ntfscat`. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-davinci-media-136a8a7.json`](../evidence/acceptance/windows-kvm-p1-davinci-media-136a8a7.json). The earlier `bcac3cc` media is retained only as a superseded pre-provenance record.

`executionAuthorized` remains false, so neither the archive nor any contained installer may be attached to a Guest or executed yet.

Later execution requires a new admitted Guest observation protocol, an exact installer path and arguments, pre/post system snapshots, real residual closure, and a separate acceptance decision.

## Static entry decision

The retained static decision at [`../research/cases/windows-kvm-p1-davinci-static-entry.json`](../research/cases/windows-kvm-p1-davinci-static-entry.json) rejects generation of an executable profile for the current Case. It binds the archive, wrapper, outer MSI, nested GetintoWAY MSI, embedded downloader script, replacement `intl.dll`, and main `Resolve.exe` identities.

The decisive evidence is the nested MSI first-install chain:

- `AI_DATA_SETTER` at sequence 6401;
- `PowerShellScriptInline` at sequence 6402;
- download from `corehubpro.com` through BITS or `System.Net.WebClient`;
- extraction of the downloaded ZIP;
- highest-privilege `OneDriveStandaloneUpdate####` scheduled-task creation;
- execution of every EXE found in the downloaded archive.

The exact runtime edge from the wrapper or outer MSI to the nested MSI is not yet fully traced. That uncertainty does not weaken the rejection decision: the distributed package contains the malicious installer and the current profile remains non-executable. The independent static gate passed from revision `91f08e0`; its sanitized index is [`../evidence/acceptance/windows-kvm-p1-davinci-static-91f08e0.json`](../evidence/acceptance/windows-kvm-p1-davinci-static-91f08e0.json).

## Observation contract

Future third-party installer execution requires the canonical profile at [`../research/profiles/windows-kvm-installer-observation-p1.json`](../research/profiles/windows-kvm-installer-observation-p1.json). It requires pre/post snapshots for files, Registry, services, drivers, scheduled tasks, BITS jobs, startup entries, installed products, users/groups, certificates, Defender, and Event Logs. It also requires a complete process tree, PowerShell script-block evidence, MSI and Task Scheduler events, QMP topology authority, host media identity, and residual closure.

The observation contract is evidence infrastructure only. It does not change `executionAuthorized`, bind an installer path, attach the current media, or start Windows.

## DaVinci Case closeout

The current DaVinci package is closed as **rejected**, not promoted to an execution Trial. Independent table-level verification reproduced the wrapper identity, the original and replacement `intl.dll` entries, the nested GetintoWAY MSI, first-install sequences 6401 and 6402, the external downloader, BITS/WebClient transports, highest-privilege scheduled-task creation, and recursive execution of downloaded EXE files.

The final sanitized Case index is [`../evidence/acceptance/windows-kvm-p1-davinci-case-closeout-bf272ab.json`](../evidence/acceptance/windows-kvm-p1-davinci-case-closeout-bf272ab.json). The prepared 8 GiB NTFS image was deleted after its manifest, content identity, preparation provenance, media acceptance, static rejection, and removal receipt were retained. No QEMU, Windows Guest, archive, MSI, DLL, or installer execution was used for this decision.

This closes the **ordinary installation admission** for the current DaVinci package. It does not erase the package or prohibit a separately authorized isolated research Trial. Product admission and research admission are different authorities.

## Isolated research admission

The separate contract at [`../research/cases/windows-kvm-p1-davinci-isolated-research-trial.json`](../research/cases/windows-kvm-p1-davinci-isolated-research-trial.json) retains the static product rejection while admitting staged research. Its first action is `verify-read-only-sample-media`:

1. rebuild the exact provenance-bound NTFS media;
2. attach it to a disposable Windows Guest with QEMU `readonly=on` and `removable=on`;
3. execute only the locally compiled `ordivon-readonly-media-verifier-v1`;
4. stream and SHA-256 the exact 7,428,655,207-byte archive from Windows;
5. require a failed write probe with Windows write-protect or access-denied semantics;
6. require QMP authority showing no network-class device;
7. record that no contained EXE, MSI, DLL, script, or archive entry was executed;
8. require complete residual closure.

The new `ordivon-security-windows-kvm-p1-readback` command implements this first research Gate. It does not reverse the package rejection and does not yet admit third-party execution. Later Gates may execute the original package or a backdoor-removed derived Case only after the generic installer observer is implemented and independently admitted.

P1 itself remains a candidate infrastructure track: the read-only media verification backend is implemented, while generic third-party installer execution and full Guest observation remain pending.
