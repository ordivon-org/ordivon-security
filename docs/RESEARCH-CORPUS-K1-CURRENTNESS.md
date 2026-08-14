---
schema_version: 1
id: security.research-corpus-k1-currentness
title: Research Corpus K1 — On-demand Provider Currentness
type: experiment
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-14
summary: Consumer-driven currentness experiment accepting read-only exact candidate-vs-head comparison while rejecting automatic provider polling, mirroring and global freshness labels.
evidence_status: verified
readiness: ACCEPTED
---
# Research Corpus K1 — On-demand Provider Currentness

## Pressure

ResearchCorpus P0 deliberately accepted explicit provider snapshots but no synchronization scheduler. K1 asked whether an ordinary consumer can detect that the provider evidence it is reasoning from has changed **without** turning Security into an OSV/NVD/KEV mirror.

The required distinction is:

```text
provider snapshot changed
!= target applicability changed
!= exploitability changed
!= execution authority changed
```

## Accepted mechanism

`ResearchCorpus.compare_candidate()` and the CLI command:

```text
ordivon-security-research-corpus compare-provider-snapshot
```

normalize one explicitly supplied candidate snapshot and compare it with the current corpus head for the same record identity.

The projection reports:

- current and candidate canonical record digests;
- changed/unchanged/not-registered status;
- per-provider current/candidate snapshot digests;
- per-provider `providerModified` values;
- source add/remove state;
- an explicit `mutationPerformed=false` boundary.

It **does not** advance the head. A caller must separately run `register-provider-snapshot` after review to create a new corpus revision.

## Controlled stale/current falsifier

K1 freezes two OSV-shaped records for one synthetic advisory identity `CVE-K1-0001`. The old snapshot has providerModified `2026-01-01`; the candidate has `2026-08-14` plus a changed provider snapshot identity.

The clean dogfood proved:

```text
register old
→ compare candidate
→ status=changed
→ head is byte-for-byte unchanged
→ mutationPerformed=false
→ explicit register candidate
→ revisionCount=2
```

This establishes a real need for a **comparison surface**, not for automatic synchronization.

## External currentness pressure

During K1, two official OSV surfaces for `CVE-2024-3094` exposed different `modified` values in the available observations:

- official API locator `https://api.osv.dev/v1/vulns/CVE-2024-3094`: `2026-04-10T05:12:24.048240Z` in the observed API response;
- official vulnerability page `https://osv.dev/vulnerability/CVE-2024-3094`: `2026-07-15T01:49:07.156785507Z` in the observed page/search projection.

K1 stores this only as `research/corpus/k1/osv-cve-2024-3094-surface-observation.json`. It is **not** registered as exact provider response bytes. The direct generic container network path also failed DNS resolution, so K1 does not pretend that a new Security-owned fetch path was proven.

The useful result is narrower: currentness must bind **provider + record + exact source/surface snapshot identity**. A scalar `fresh=true`, TTL, or provider-wide generation would erase the very disagreement the consumer needs to see.

## Clean-source acceptance

Implementation revision:

```text
e64926aee86ff98357b970b3ef55de8ea5612043
```

Runtime acceptance Job:

```text
job-019fffac-7516-7cc2-96ef-ac5fbcdbeb1f
```

It passed:

- 404/404 unit tests;
- repository Ruff `E9,F` checks;
- the stale/current CLI dogfood;
- proof that comparison does not mutate the corpus head.

## Retained laws

1. **Currentness is source-relative.** A provider name alone is insufficient; exact record/snapshot/surface identity matters.
2. **Changed provider evidence triggers review, not a world-state promotion.** It does not prove target applicability or exploitability changed.
3. **Comparison and mutation remain separate actions.** A read-only currentness check cannot silently create a new corpus revision.
4. **No scheduler is earned.** K1 shows demand for on-demand comparison, not for background polling or bulk mirroring.
5. **Transport ownership stays outside ResearchCorpus.** The caller/provider-resource owner supplies the exact snapshot; Corpus owns normalization, comparison, provenance and revision semantics.

## Reopen conditions

Reopen synchronization only if repeated ordinary consumers demonstrate measurable stale-evidence failures that cannot be handled by explicit per-record revalidation. Even then, prefer the smallest owner-native fetch/revalidation path before any mirror or standing daemon.
