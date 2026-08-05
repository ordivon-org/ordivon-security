---
schema_version: 1
id: security.static-evaluation-p0
title: Static Evaluation P0
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
summary: Local observe-only static Evaluation with a streaming SampleVault, exact analyzer identity, bound native-report Artifacts, quarantine hardening, and no Sample execution.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security-static-evaluation
related:
  - security.start
  - security.architecture
  - security.evaluation-trial-p0
  - security.evidence
  - security.authority
---
# Static Evaluation P0

## Purpose

Static Evaluation P0 turns classical non-executing analysis into an authorized
Evaluation Trial. It binds one exact Sample, analyzer implementations and
configuration, native reports, Observer records, Guardian policy, residual
closure, Findings, and a sealed Evidence Bundle.

It does **not** load, install, invoke, emulate, or dynamically execute Sample
bytes. It is not a malware sandbox, reverse-engineering suite, antivirus engine,
or Authenticode trust service. The admitted analyzers still parse attacker-
controlled bytes with the local operator account; P0 does not claim that 7-Zip,
ClamAV, or another parser is isolated from parser vulnerabilities.

## Active flow

```text
Sample path
  → streaming SampleVault import
  → exact EvaluationSpec and Authority
  → LocalStaticEvaluationBackend
  → admitted StaticAnalyzer adapters
  → Observer records + native report Artifacts
  → static-only Guardian receipt
  → work-directory destruction
  → Findings + sealed Evidence Bundle
```

`LocalStaticEvaluationBackend` reuses the existing
`create → stage → execute → destroy` Evaluation backend contract. In this
profile, `execute` means “invoke admitted analyzers against bytes as data.” The
backend execution identity and world facts both declare
`sampleExecution: false`.

## SampleVault revision 2

The local Vault now:

- streams path imports instead of calling `read_bytes()`;
- hashes while copying into a private `0700` staging directory;
- writes Sample objects and manifests as `0600`;
- flushes the staged Sample and manifest before an atomic directory rename;
- rejects symbolic links and non-regular import paths;
- supports per-Sample and total Vault byte limits;
- verifies the complete digest and byte length on every resolve;
- removes abandoned staging entries through an explicit recovery receipt;
- preserves content-addressed identity for repeated imports;
- emits purge receipts without placing Sample bytes in evidence.

The Vault remains local, single-operator infrastructure. It is not encrypted at
rest, multi-user, remotely accessible, or a general evidence database.

## Static analyzers

### `FileIdentityAnalyzer`

Recomputes complete SHA-256 and byte length from the Vault object. It proves only
that the analyzer received the admitted bytes.

### `ArchiveInventoryAnalyzer`

Runs 7-Zip listing mode:

```text
7z l -slt -- <sample>
```

It does not extract archive entries. It records archive type, entry count,
absolute paths, and parent-traversal paths. The complete normalized listing is a
bound native-report Artifact.

### `ClamAvAnalyzer`

Runs ClamAV against the exact Vault object and binds:

- executable digest and version output;
- arguments and timeout;
- exit code;
- matched signatures;
- complete normalized report Artifact.

A ClamAV match is an Observer result. It can support a bounded
`antivirus-signature-detection` Finding, but it is not independent proof that a
behavior executed or caused harm.

Large compressed files may exceed ClamAV archive-scanning limits. In that case,
a prior tree scan may be imported, but the Trial must state that it is historical
report evidence rather than a scan performed by the current Run.

### Imported reports

`ImportedReportAnalyzer` binds a pre-existing report by complete digest and byte
length. It does not reinterpret the report. Association between an imported
report and the admitted Sample is an operator assertion unless the report itself
independently binds the Sample digest.

`ClamAvReportAnalyzer` additionally parses a historical ClamAV summary and its
`FOUND` records.

`AuthenticodeReportAnalyzer` parses the retained custom digest-consistency
summary. Its authority class is explicitly:

```text
custom-digest-consistency-check
```

It does not claim Windows `WinVerifyTrust`, certificate-chain validation,
revocation checking, timestamp policy, or Code Signing EKU validation.

## Observer, Guardian, truth, and Artifact authority

| Record | Authority in Static P0 |
|---|---|
| Analyzer report | what that exact tool or imported report stated |
| Observer event | normalized claim derived from one report |
| Guardian event | static-only policy was admitted; no dynamic isolation claim |
| World truth | analyzers completed, Sample was not executed, and work state was removed |
| Native-report Artifact | exact retained bytes of the report, bound by digest |
| Finding | deterministic relation from an admitted Observer event to a bounded class |

Static P0 cannot establish runtime process, Registry, memory, network, persistence,
credential-access, or destructive effects.

## Evidence schema revision 2

Evaluation evidence retains the existing channels and adds bound native-report
Artifacts:

```text
evaluation-spec.json
execution-identity.json
findings.json
result.json
bundle-manifest.json
operational-manifest.json
artifacts/
  000-<digest>.bin
  ...
events/
  sample.jsonl
  management.jsonl
  observer.jsonl
  guardian.jsonl
  world-truth.jsonl
  operational.jsonl
```

The manifest binds each Artifact's:

- identity;
- kind;
- digest;
- byte length;
- media type;
- logical name;
- relative evidence path.

Artifact bytes are copied into private staging before backend destruction, then
sealed into evidence. The total copied bytes must remain within
`GuardianPolicy.max_artifact_bytes`. Artifact tampering invalidates verification.

Sample bytes remain outside the Evidence Bundle.

## CLI

Minimal identity-only Trial:

```bash
uv run ordivon-security-static-evaluation \
  --sample /path/to/owned-sample.bin \
  --vault /var/lib/ordivon/security/vault \
  --output /var/lib/ordivon/security/evidence
```

Archive inventory and current ClamAV scan:

```bash
uv run ordivon-security-static-evaluation \
  --sample /path/to/owned-sample.7z \
  --media-type application/x-7z-compressed \
  --authorization-basis "Owned local copy submitted for static analysis" \
  --vault /var/lib/ordivon/security/vault \
  --output /var/lib/ordivon/security/evidence \
  --archive-inventory \
  --clamav
```

Import retained reports without claiming they were rerun:

```bash
uv run ordivon-security-static-evaluation \
  --sample /path/to/owned-sample.7z \
  --media-type application/x-7z-compressed \
  --authorization-basis "Owned local copy submitted for static analysis" \
  --vault /var/lib/ordivon/security/vault \
  --output /var/lib/ordivon/security/evidence \
  --archive-inventory \
  --clamav-report /path/to/clamscan_tree.log \
  --authenticode-report /path/to/authverify_final_results.txt \
  --report /path/to/extract.log
```

## Quarantine hardening

Existing operator-owned quarantine trees can be normalized without reading or
executing file content:

```bash
uv run ordivon-security-harden-quarantine \
  --root /path/to/quarantine/case \
  --receipt /path/to/quarantine/receipts/case-hardening.json
```

The command first walks the complete tree and rejects symbolic links or special
files. Only after a successful preflight does it set directories to `0700` and
regular files to `0600`.

## P0 acceptance

The test suite proves:

- streamed import across small chunks;
- per-Sample and total Vault quota rejection;
- symlink rejection and abandoned-import recovery;
- private Sample, Artifact, evidence, and quarantine modes;
- static backend identity and `sampleExecution: false` facts;
- bound report copying before backend work-directory destruction;
- Artifact byte-limit failure with residual closure;
- Artifact tamper detection;
- historical ClamAV report Findings with explicit limitations;
- custom Authenticode summary limitations;
- archive path-traversal detection without extraction;
- Sample bytes absent from every evidence file.

## Next gate

Static P0 is complete when a real retained Sample can be imported through the
streaming Vault and its existing static reports can be sealed from a clean
Security revision.

The following remain outside this gate:

- Windows `WinVerifyTrust` or an equivalent complete signature-verification
  provider;
- YARA, capa, FLOSS, Ghidra, and Volatility adapters;
- safe archive extraction as a first-class provider;
- disposable VM creation;
- Guest monitoring and network simulation;
- dynamic Sample execution;
- behavioral or malicious-intent attribution.
