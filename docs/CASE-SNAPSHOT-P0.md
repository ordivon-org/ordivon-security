---
schema_version: 1
id: security.case-snapshot-p0
title: Case Snapshot P0
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
summary: Read-only quarantine audit and digest-bound Case snapshots for evolving local analysis material, including explicit uncontrolled-execution status and evidence limitations.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security-case-snapshot
related:
  - security.start
  - security.architecture
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.evidence
  - security.authority
---
# Case Snapshot P0

## Purpose

A software-analysis Case usually continues changing after the first Evaluation
Run. Analysts add reports, extracted files, scripts, test harnesses, logs, and
notes. A sealed Evaluation Bundle remains valid for the exact material admitted
into that Run, but it does not silently expand to cover later Case changes.

Case Snapshot P0 provides two local controls:

1. a read-only quarantine audit;
2. a digest-bound metadata snapshot of the complete current Case tree.

A Case Snapshot is not an Evaluation Run and does not create world truth,
Guardian authority, residual closure, or behavioral Findings.

## Why this gate became necessary

A retained local Case was updated after its first Static Evaluation. Later work
loaded one extracted DLL through Wine on the WSL host and ran a small malformed-
input harness. That execution occurred outside an admitted disposable-machine
backend.

The retained output proves only that the DLL was loaded by the harness and the
process completed. It does not independently prove arbitrary-path module
loading, successful memory patch application, network behavior, persistence,
Registry effects, or complete residual closure. No independent process, memory,
network, or management-plane Observer was present.

The Case must therefore be marked:

```text
external-uncontrolled-execution
```

Its reports and logs remain useful historical material, but they cannot be
promoted to Evaluation world truth.

## Execution status

Every snapshot declares one of three statuses.

### `static-only`

The retained Case material has not been executed by the snapshot operation. This
status does not prove that no execution ever occurred elsewhere; the operator is
responsible for the declaration.

### `external-uncontrolled-execution`

Some Case component was executed outside an admitted Evaluation backend. This
status requires at least one explicit limitation. Typical limitations name:

- the uncontrolled host or compatibility layer;
- missing network, process, memory, Registry, or filesystem observers;
- missing deny-all egress evidence;
- missing machine destruction or residual-closure evidence;
- claims that are not supported by retained raw output.

This status never becomes `controlled-trial` merely because stdout, stderr, or a
human report exists.

### `controlled-trial`

The Case is linked to at least one source `evaluation-run:*` identity produced by
an admitted backend. The Case Snapshot still does not replace that Run; it only
links the evolving directory state to the retained Evaluation identity.

## Quarantine audit

`audit_quarantine_tree` walks the Case without changing it. It records:

- directory and regular-file counts;
- total regular-file bytes;
- directories not set to `0700`;
- files not set to `0600`;
- files carrying any executable bit;
- symbolic links;
- special files;
- exact Security source identity;
- whether the current tree is compliant.

The CLI can write a private, non-overwriting audit receipt:

```bash
uv run ordivon-security-audit-quarantine \
  --root /path/to/quarantine/case \
  --receipt /var/lib/ordivon/security/receipts/case-audit.json \
  --fail-on-violation
```

Exit status `2` means the audit completed but found a policy violation.

A successful `ordivon-security-harden-quarantine` run is a point-in-time
normalization, not a persistent sandbox. Later tools may create new files with
`0644` or directories with `0755`, or restore executable bits. Operators should
use `umask 077`, audit after every tool phase, and harden again only after the
read-only drift receipt is retained.

## Case snapshot

`create_case_snapshot` rejects symbolic links and special entries, then:

1. captures the complete initial tree identity;
2. hashes every regular file with streaming SHA-256;
3. verifies each file did not change while being read;
4. captures the complete final tree identity;
5. fails closed if paths, type, inode, size, mode, or modification time changed;
6. writes a private atomic bundle outside the Case root.

The bundle contains no Sample or Artifact bytes:

```text
case-manifest.json
snapshot-receipt.json
```

The manifest binds:

- Case identity;
- execution status;
- linked Evaluation Run identities;
- explicit limitations;
- Security source revision;
- directory, file, entry, and total-byte counts;
- quarantine-policy summary;
- every relative path;
- entry type and permission mode;
- every regular file's byte length and SHA-256.

The receipt contains the machine-local root path and wall-clock record time. Root
path and record time do not alter the semantic manifest digest, so an identical
Case tree can be moved without changing snapshot identity.

## CLI

Example for a Case with an uncontrolled historical Wine run:

```bash
uv run ordivon-security-case-snapshot \
  --root /path/to/quarantine/case \
  --output /var/lib/ordivon/security/case-snapshots/case-v1 \
  --case-id case:software-assessment \
  --execution-status external-uncontrolled-execution \
  --source-run evaluation-run:static-reference \
  --limitation "A component was loaded through Wine outside an admitted backend." \
  --limitation "Retained output does not prove memory patch or network effects."
```

`verify_case_snapshot` validates bundle structure, permissions, canonical digest,
execution-state rules, counts, entry ordering, file identities, and quarantine
summary.

`verify_case_snapshot_against_root` additionally re-hashes the complete current
Case and fails when it differs from the retained snapshot.

## Authority boundaries

| Object | What it may establish |
|---|---|
| Quarantine audit | current permission, link, and special-file state |
| Case Snapshot | exact Case directory metadata and file digests |
| Imported report | what the retained report bytes state |
| External uncontrolled output | historical output from an uncontrolled host |
| Evaluation Bundle | admitted Observer, Guardian, truth, closure, and Result claims |

A human report cannot promote an external uncontrolled execution to a controlled
Trial. A Case Snapshot cannot establish intent or runtime behavior. A clean
quarantine audit cannot establish that Sample execution is safe.

## P0 acceptance

The test suite proves:

- audit is read-only and records permission drift;
- audit receipts are private and cannot be overwritten;
- hardening followed by audit becomes compliant;
- uncontrolled execution requires explicit limitations;
- semantic snapshot digest excludes absolute root and file modification time;
- content, mode, path, and tree changes alter or invalidate the snapshot;
- Sample bytes are not copied into the snapshot bundle;
- policy drift is retained without claiming control;
- symbolic links are rejected;
- manifest tampering is detected;
- snapshot bundles and files remain private.

## Next gate

The next work order is:

1. retain a read-only audit receipt for the current Case drift;
2. normalize permissions and create one exact Case Snapshot;
3. treat the historical Wine run as uncontrolled material only;
4. admit a real disposable Windows provider before any further unknown-component
   execution;
5. then add complete Authenticode and safe archive-expansion adapters when they
   improve a measured evidence gap.

Windows Sandbox or Hyper-V availability has not yet been established by the
current WSL control path. No dynamic backend should be claimed until the provider
can be queried, configured, and destroyed through an independently verified
management plane.
