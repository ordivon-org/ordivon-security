---
schema_version: 1
id: security.ordinary-consumption-r1
title: Ordinary Security Consumption R1 — Research Surface to Agent Work
type: experiment
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-14
summary: Fresh-Agent consumer round accepting a thin ordinary task view, ResearchCorpus pre-analysis memory and an ordinary Blue response path while rejecting bulk history import, new EDR/SIEM, higher-fidelity transfer and a new workflow/gateway abstraction.
evidence_status: verified
readiness: ACCEPTED
---
# Ordinary Security Consumption R1

## Why this round exists

Post-CA left Security rich in accepted research apparatus but relatively noisy for a fresh ordinary Agent. At base revision `1841ba44e172dc93f79d14b8d45909dc51e8371b`, the classified Agent surface contained 29 entries: 5 constitution, 5 profile, 3 integration and **16 research-apparatus** entries. The package exposed 35 console scripts and 57 of 65 top-level Python modules were `cli_*` modules.

That is valuable provenance, but it creates a different question from capability research:

> Can a fresh Agent find the smallest correct owner-native Security surface without knowing the experiment chronology that originally proved it?

R1 freezes four ordinary packets: vulnerability triage, Sample assessment, provider-snapshot currentness and bounded defensive response. It does not delete research history or create a generic workflow engine.

## R1-A — Full surface baseline

The baseline runner is research apparatus, not a new public console command. It gives a fresh DeepSeek/Harness treatment one `select_security_route` Tool and the current Security surface.

An early exploratory run demonstrated a mechanical pressure before any Provider call: the complete mixed surface produced a conservative first-request bound around 14.8k tokens and was rejected under an intentionally too-small 12k total budget. R1 raised only the experiment budget; visible content was unchanged.

On clean implementation revision `cac3fe19240a87b6ea39750ad19ad5e2b7664e2b`, the same DeepSeek credential scope produced the following paired sample:

| packet | full surface | ordinary view |
| --- | --- | --- |
| vulnerability triage | ResearchCorpus | ResearchCorpus |
| Sample assessment | ResearchCorpus | ResearchCorpus |
| provider currentness | **provider-sync** | ResearchCorpus |
| defensive response | **CA4 research** | **new EDR stack** |

The exact-route benchmark is intentionally strict. `RangeSession`, for example, can be a valid later escalation for persistent response even when Software Evaluation is the preferred first profile. The result is therefore not a universal model score. The stable evidence is narrower: the full mixed view repeatedly exposed historical/sync choices that ordinary work did not require, while three exploratory ordinary-view replicates selected the canonical route 4/4 and the clean paired ordinary run selected 3/4.

R1 accepts navigation contraction as useful, not as sufficient for model correctness.

## R1-B — The ordinary task view

`security_ordinary_surface_manifest()` and:

```text
ordivon-security-surface --view ordinary
```

project six task routes over four existing surfaces:

- vulnerability/advisory triage -> `ResearchCorpus`;
- Sample/Case assessment -> `ResearchCorpus`;
- provider-snapshot currentness -> `ResearchCorpus`;
- software/endpoint evaluation -> `Software Evaluation`;
- persistent contested response -> `RangeSession`;
- evidence recording/verification -> `EvidenceRecorder`.

The accepted ordinary view is now the default first interface. The full maturity-classified surface remains explicitly available through `--view full`; no research command, acceptance runner or compatibility export is deleted. The ordinary view is generated from the existing owner-native surface and fails if it references an unknown surface.

A useful falsifier appeared during the A/B work: an opaque SHA-256 digest of the full surface was initially included in the ordinary projection. Across two model treatments it was misread as the 目标产品B Sample SHA-256. R1 removes that digest from the Agent-visible navigation packet. Acceptance evidence binds source revision/digests outside the semantic view instead. A later model replicate contained no SHA-256 mention in the Sample summary.

## R1-C — ResearchCorpus as ordinary memory

A clean temporary Corpus registers the current CA2, EICAR and 目标产品B post-edge seeds plus the controlled K1 OSV record. Ordinary questions are answered without replaying their research experiments:

- CA2: 1 `provider-claim` + 1 `independent-observation`;
- EICAR: `real-malware=false`, 1 provider claim, execution remains `denied-by-default`;
- 目标产品B: 6 scoped `case-conclusion` claims, 0 Corpus `independent-observation` claims, `metadata-only`, execution `denied-by-default`;
- provider currentness: exact candidate-vs-head comparison reports changed source evidence with `mutationPerformed=false`.

A query for the generic compensation/recovery law returns zero Corpus records. That is accepted behavior: generic system laws remain canonical-doc/evidence owned. R1 therefore accepts ResearchCorpus as an **ordinary pre-analysis memory/read for exact retained vulnerability/Sample/provider evidence**, but not as live discovery authority. Current advisory/provider discovery may be performed by a mature external provider/tool; Security retains an exact snapshot only when currentness comparison, owner memory, or reproducibility requires it. R1 still rejects bulk historical import, a new record kind and a universal Security knowledge graph.

## R1-D — Ordinary Blue incident consumer

The EICAR and known-clean bytes used by CA4 are promoted only from private research constants into `ordivon_security.fixtures`; CA4 itself reuses the exact bytes. This lets an ordinary consumer compose the existing semantics without importing the CA4 acceptance runner.

Using current installed ClamAV, two owned temporary-world treatments were executed:

1. **current detection** — exact EICAR bytes are detected, the current digest still matches, a case-local quarantine move is made, and a fresh read proves the active path is absent and the quarantined bytes still have SHA-256 `275a021b...651fd0f`;
2. **stale detection** — EICAR is detected, then the active bytes are replaced with the exact maintained clean fixture before adjudication. The digest mismatch yields `STALE_NOT_APPLICABLE`; no response occurs; fresh truth shows the clean bytes remain active and quarantine is absent.

Every response receipt retains `worldTruthVerified=false`. Corpus memory simultaneously preserves that EICAR is a harmless maintained test fixture rather than real malware.

This ordinary consumer closes without Sysmon, EDR, SIEM, a SOAR-like workflow abstraction, or a new telemetry provider.

## R1-E — Harness/finalization attribution

Ordinary routing does reproduce a pressure adjacent to P1: after selecting the right route, some model turns return `needs_input`, and one treatment attempted an ungranted `inspect_research_corpus` Tool after the route Tool had already succeeded. Harness correctly rejected the invented Tool.

R1 does **not** call this a new Harness defect. The baseline intentionally grants only route selection and withholds the downstream owner Tools, while its ordinary objective naturally invites further investigation. Post-route completion friction is therefore not isolated from apparatus capability availability. Security adds no bypass, no inferred intent and no cognition layer. P1 remains stronger historical evidence that finalization/provider robustness deserves continued observation under consumers that actually grant the required effect/inspection Tools.

## R1-F — Higher-fidelity gate

The gate closes **negative**.

The ordinary Blue consumer reached current/stale adjudication, bounded response and fresh consequence truth with existing local providers. No decision-blocking network/process telemetry gap appeared. Corpus currentness and memory also closed without a network mirror. No ordinary consumer threatened the bounded P1 adaptive-selection result strongly enough to require a multi-node transfer experiment.

Therefore R1 admits no containerlab/Zeek/Suricata expansion, no new Windows endpoint stack and no higher-fidelity tactical experiment.

## Clean acceptance

Implementation revision:

```text
cac3fe19240a87b6ea39750ad19ad5e2b7664e2b
```

Clean deterministic acceptance Job:

```text
job-01a00008-6507-7253-9d27-26caacc4ae77
```

It passed 412/412 unit tests, repository Ruff `E9,F`, ordinary-surface validation, Corpus memory dogfood and both Blue incident treatments.

Clean ordinary-view model Job:

```text
job-01a00008-df66-7ed3-92f2-ee6b070e4fdb
```

Clean full-view paired model Job:

```text
job-01a00009-ec9d-7622-a97a-2d2325f9ec91
```

The acceptance record is `evidence/acceptance/ordinary-security-consumption-r1-cac3fe1.json`.

## Retained boundary

R1 earns a thinner navigation projection and two ordinary consumers. It does not earn a second Security registry, a generic workflow/planner/gateway, automatic provider synchronization, bulk Corpus migration, new telemetry infrastructure, a model ranking, or higher-fidelity offensive work.
