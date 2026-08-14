# Security Research Corpus

This directory contains **small, Git-safe research manifests**, not malware bytes and not a clone of an external vulnerability database.

`ResearchCorpus` is the Security-owned catalog/admission/query layer above two different external owners:

- vulnerability intelligence and sample-intelligence providers own their native records, classifications and update streams;
- `SampleVault` owns private materialized Sample bytes by exact content identity.

The corpus owns only the relationship between exact identities, source snapshots, scoped claims, evidence references and materialization/admission state.

## Stable boundaries

```text
provider record / case evidence
        ↓ exact snapshot identity
corpus record
        ├─ content or target identity
        ├─ sourceRefs
        ├─ claims grouped by truthRole
        ├─ evidenceRefs
        └─ materialization / execution-admission state
```

For Sample records:

```text
recordId = sample:<exact SHA-256>
```

and `executionAdmission` is always `denied-by-default`. Registering metadata, importing bytes into `SampleVault`, or receiving a provider malware classification never grants execution authority. A later Range/Evaluation experiment must independently admit exact bytes, environment and consequence scope.

Claims deliberately retain their epistemic owner:

- `provider-claim` — external/provider classification or advisory statement;
- `independent-observation` — bounded Security observation backed by explicit evidence;
- `maintained-fixture-fact` — fact about an Ordivon-maintained test fixture;
- `case-conclusion` — scoped conclusion of an existing Security Case.

Absence of an `independent-observation` claim is not a negative observation.

## Initial records

- `seed-ca2-vulnerability.json` — the exact CA2 owned vulnerable/guarded/fixed C revisions and their static-versus-replay evidence;
- `seed-eicar-sample.json` — the harmless maintained EICAR test fixture and its ClamAV provider classification boundary;
- `seed-caseb-sample.json` — metadata-only identity for the retained 目标产品B case archive and existing case conclusions. The 7.4 GiB archive is not copied here.
- `seed-caseb-sample-postedge.json` — a post-P0 revision of the same exact 目标产品B Sample identity that adds the recovered bounded C/D case conclusions without changing materialization or execution admission.

`providers.json` records the first external provider roles. OSV, NVD and CISA KEV remain vulnerability-intelligence owners. MalwareBazaar and VirusTotal remain sample-intelligence owners. P0 accepts explicit exact snapshots only; it performs no automatic synchronization, upload, download or bulk mirroring.

## CLI

```text
uv run ordivon-security-research-corpus verify --root <corpus-root>
uv run ordivon-security-research-corpus list --root <corpus-root>
uv run ordivon-security-research-corpus show --root <corpus-root> --record-id <id>
uv run ordivon-security-research-corpus inspect --root <corpus-root> --record-id <id>
uv run ordivon-security-research-corpus query --root <corpus-root> <needle>
uv run ordivon-security-research-corpus register-manifest --root <corpus-root> --manifest <json>
uv run ordivon-security-research-corpus register-provider-snapshot --root <corpus-root> --provider <provider> --snapshot <json> [--record-id <provider-record-id>]
uv run ordivon-security-research-corpus compare-provider-snapshot --root <corpus-root> --provider <provider> --snapshot <json> [--record-id <provider-record-id>]
uv run ordivon-security-research-corpus import-local-sample --root <corpus-root> --vault <vault-root> --path <local-file>
```

`inspect` is the preferred Agent-facing semantic projection because it separates claims by `truthRole` and exposes Sample materialization and execution admission explicitly. `query` is only a discovery convenience over manifest text.

## P0 non-goals

P0 deliberately does not provide:

- a malware downloader or public malware zoo;
- automatic sample upload to third-party services;
- a CVE/NVD/OSV/KEV mirror;
- a malware-family ontology;
- a scalar `malicious=true` or `exploitable=true` truth field;
- execution authority;
- multi-writer transaction/locking semantics;
- provider polling/currentness scheduling.

Those responsibilities require separate evidence or consumers before they can be admitted.
