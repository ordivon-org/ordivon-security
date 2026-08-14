---
schema_version: 1
id: security.research-corpus-p0
title: Vulnerability and Sample Research Corpus P0
type: architecture
profile: research
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
updated: 2026-08-14
summary: Accepted revisioned Security research catalog for exact vulnerability and software-sample identities, provider/evidence provenance, claim truth-role separation, private SampleVault materialization, and denied-by-default execution admission.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security
related:
  - security.classical-capability-basis-ca0
  - security.vulnerability-evidence-ca2
  - security.defensive-observation-response-ca4
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.authority
---
# Vulnerability and Sample Research Corpus P0

## Problem

CA0–CA7 established a classical capability world without turning ATT&CK, malware families, scanners or provider products into Security's ontology. That left one practical consumer pressure: repeated research needs to remember exact vulnerability opportunities and exact software Samples across experiments without making either of two category errors:

```text
external vulnerability/sample intelligence != independent Security world truth
possession of Sample bytes != permission to execute them
```

P0 therefore adds a **research corpus**, not a vulnerability database clone and not a malware zoo.

The corpus owns the relationship among exact identity, provider/case provenance, scoped claims, evidence, materialization state and execution admission. External systems retain their native data/mechanics; `SampleVault` retains private Sample bytes.

## Architecture

```text
OSV / NVD / CISA KEV           MalwareBazaar / VirusTotal
Security CA2 / CA4 / Cases     operator-local exact Sample
          │                                  │
          └──── exact snapshot/evidence ─────┘
                          ↓
                    ResearchCorpus
          ├─ revisioned canonical manifest
          ├─ exact content / target identity
          ├─ sourceRefs + snapshot digest/currentness
          ├─ claims + truthRole + evidenceRefs
          ├─ materialization state
          └─ executionAdmission = denied-by-default
                          │
                optional exact materialization
                          ↓
                    private SampleVault
```

The corpus stores no Sample bytes. A local import first goes through `SampleVault`; the corpus stores only the resulting `SampleIdentity` and source/evidence relationship.

## Record identities

There are two P0 record kinds.

### Sample

A Sample record is content-addressed:

```text
recordId = sample:<SHA-256>
sample.sha256 = sha256:<same 64 hex>
```

The validator rejects any mismatch. A `sample-vault` record must also bind the same `vaultSampleId`.

Materialization is explicit:

- `metadata-only` — only exact metadata/provider/case identity is locally cataloged;
- `sample-vault` — exact bytes exist in the private local SampleVault;
- `maintained-source-fixture` — the artifact is an Ordivon-maintained fixture represented by maintained source/evidence rather than a private third-party blob.

Every Sample record has:

```text
executionAdmission = denied-by-default
```

This field cannot be changed to `allowed` through the corpus schema. A later exact Range/Evaluation authority must independently admit execution.

### Vulnerability

A vulnerability record binds either:

- one or more exact owned target revisions with digests; or
- at least one exact external provider source reference.

An advisory record may therefore describe an external candidate opportunity without claiming that any current owned target is vulnerable or exploitable.

## Claims are not scalar truth labels

P0 intentionally rejects fields such as:

```text
malicious = true
exploitable = true
safe = true
```

as universal Security truth.

A claim instead records `predicate`, `value`, `assertedBy`, `evidenceRefs`, and one explicit epistemic role:

| `truthRole` | Meaning |
| --- | --- |
| `provider-claim` | a provider/advisory/detector statement owned by that provider |
| `independent-observation` | a bounded Security observation backed by explicit evidence |
| `maintained-fixture-fact` | a fact Security owns about an Ordivon-maintained test fixture |
| `case-conclusion` | a scoped conclusion already established by a named Security Case |

The Agent-facing `inspect` projection groups claims by this role. An empty `independent-observation` bucket means **no independent observation is present**, not that the opposite fact has been observed.

## Revision and integrity model

`ResearchCorpus` uses a local revisioned canonical-manifest store.

For every record:

```text
canonical record bytes
→ SHA-256 record digest
→ deterministic record-id directory
→ digest-named immutable revision
→ current head
→ registration receipt
```

P0 verifies both current heads and all retained historical revisions. Head filename, record kind, revision path and canonical digest must agree. A head cannot redirect to an arbitrary relative path. Corpus directories are `0700`; manifest/receipt files are written atomically and become `0600`.

P0 is local single-writer research infrastructure. It does not yet claim concurrent multi-writer transaction semantics.

## Provider-first ingestion

The first provider normalizers consume exact JSON snapshots from:

- OSV;
- NVD;
- CISA Known Exploited Vulnerabilities;
- MalwareBazaar;
- VirusTotal.

P0 performs **no provider network fetch itself**. It accepts an explicit snapshot and preserves a canonical snapshot digest plus provider record identity/currentness fields where supplied.

For NVD/CISA envelopes containing multiple vulnerabilities, P0 requires selection of one exact provider record. This prevents the convenience command from silently becoming a database mirror.

MalwareBazaar/VirusTotal ingestion is metadata-only. Provider family labels, engine statistics or corpus membership remain `provider-claim`; P0 implements no sample download or public upload path.

## Initial seed set

P0 begins with three evidence-backed records rather than a large taxonomy.

### CA2 owned vulnerability

`vuln:ordivon-ca2-owned-stack-overflow-v1` binds the exact vulnerable, guarded-safe and fixed C target revisions from CA2. It deliberately contains both:

- the Clang static finding as `provider-claim`; and
- the exact-input replay result as `independent-observation`.

This preserves CA2's central result that a static finding is not current exploitability truth.

### EICAR maintained test fixture

`sample:(哈希略)...651fd0f` records the exact harmless EICAR fixture used by CA4. `real-malware=false` is a maintained-fixture fact, while `Eicar-Test-Signature` remains a ClamAV provider claim.

### 目标产品B retained Case identity

`sample:(哈希略)...c2c0d2e` records the exact 7.4 GiB 目标产品B archive identity as `metadata-only`. Existing static malicious-chain and ordinary-execution-rejection conclusions remain `case-conclusion` claims. The archive bytes are not copied into Git or this corpus, and corpus registration does not admit execution.

## Clean-source acceptance

Implementation revision:

```text
9fa5a7f162234cf8f656bf5bf9e79a9d7716014d
```

Clean Runtime acceptance Job:

```text
job-019fff4a-67e5-7ab2-b857-3f640bfa93d2
```

The fresh detached source passed:

- 399/399 unit tests;
- full-repository Ruff `E9,F` checks;
- registration of all three maintained seeds;
- import of one benign owned synthetic Sample through `SampleVault`;
- full head + historical-revision verification;
- Agent-facing inspection of the CA2, EICAR and 目标产品B records;
- a Git corpus-byte boundary check showing the largest tracked corpus file was only the 4,016-byte README and no declared Sample-binary extension was tracked.

The acceptance projection proved:

```text
headCount = 4
revisionCount = 4
sampleCount = 3
vulnerabilityCount = 1
all Sample executionAdmission = denied-by-default
CA2 provider-claim count = 1
CA2 independent-observation count = 1
EICAR real-malware claim = false
目标产品B materialization = metadata-only
目标产品B independent-observation count = 0
```

The fourth head is the temporary benign owned Sample used only to prove private SampleVault materialization and default-denied admission.

## What P0 establishes

### P0-L1 — catalog identity is not capability

Knowing that a vulnerability record or Sample exists expands the Agent's information, not its action authority.

### P0-L2 — possession is not execution admission

Materialized bytes in SampleVault remain inert research material until a separately scoped experiment admits them.

### P0-L3 — external classifications retain their owner

OSV/NVD/KEV/MalwareBazaar/VirusTotal/AV claims may inform prioritization or later investigation. They do not become independent Security truth merely because the corpus stores them.

### P0-L4 — evidence strength may coexist for one object

One vulnerability or Sample can carry several conflicting or differently scoped claims. The corpus preserves those claims and their evidence roles instead of forcing one label.

### P0-L5 — Security should own the research relationship, not provider mechanics

Exact identity, provenance, evidence, admission and Agent interpretation are Security concerns. Provider databases, scanning engines, malware analysis, file distribution and update streams remain external owners.

## Non-goals and reopen conditions

P0 does not implement:

- malware acquisition/download automation;
- public sample distribution;
- automatic VirusTotal or other third-party uploads;
- vulnerability-database mirroring;
- a malware family or ATT&CK ontology;
- a universal maliciousness/exploitability score;
- execution authority;
- polling/continuous provider synchronization;
- multi-writer transactions;
- autonomous triage policy.

Add synchronization only when a consumer demonstrates that explicit snapshots create material stale-data friction. Add richer Sample behavior evidence only when a real analysis consumer requires it. Physical third-party malware execution remains a separately authorized Range experiment and does not inherit authority from this corpus.

K1 later admits only a read-only candidate-vs-head comparison surface; see [`RESEARCH-CORPUS-K1-CURRENTNESS.md`](RESEARCH-CORPUS-K1-CURRENTNESS.md). It still does not admit automatic polling or mirroring.
