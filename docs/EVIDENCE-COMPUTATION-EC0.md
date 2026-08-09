---
schema_version: 1
id: security.evidence-computation-ec0
title: Evidence Computation EC0
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-09
summary: Cross-domain ownership experiment showing that AE3-C derived factual evidence can be reproduced by a standalone committed program under Runtime source-state commitment without a Security-owned reducer primitive or a new shared reducer library.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.adversarial-epistemics-ae3c
  - security.adversarial-epistemics-ae3b
  - security.agent-first-intent-af2
---
# Evidence Computation EC0

## Question

AE3-B showed that raw verified history may be present in Agent context while the model still aggregates it incorrectly. AE3-C showed that a deterministic reconstructable factual projection removes that specific friction for the tested consumer. That created a new architectural temptation: promote the AE3-C reducer into a shared `EvidenceReducer`, Trust-adjacent service, or Security core primitive.

EC0 tests the smaller hypothesis first:

> Can the exact accepted AE3-C projection be reproduced outside `ordivon_security`, by an ordinary committed program over exact source-owned bytes, while preserving the exact Agent-visible AE3-C context identity?

If yes, the cross-domain requirement is lower-level than a reducer ontology. The system needs exact computation, not a universal interpretation layer.

## Cross-domain pressure before implementation

EC0 began with a read-only audit of current project snapshots. No foreign repository was modified.

| Project | Audited revision | Observed role |
|---|---|---|
| Finance | `ef3739d774037298af66a325f6a3314b92aefa8b` | Independent strong consumer of mechanical reduction over exact evidence/data. `FinanceLabSession`, PIT cuts, Polars/DuckDB programs, immutable execution materialization, semantic result digests and result admission already implement a richer domain-local form. |
| World | `2f9645113538b15e51ce4546f0942b45d10fda29` | Strong provenance/reconciliation/trajectory consumer, but no independent evidence that count/filter/group style reduction should be a World primitive. |
| Harness | `b622c8c055446175dca017425ad4ffa39b6be681` | Owns Working Set/View, Tool loops and Agent-selected context. Its Working View projects already-selected sources deterministically; it deliberately does not discover/rank domain context. |
| Computing | `cadc0154a2fee54504b8fe680cc6751107c9ae57` | Cross-domain research/world-model synthesis and protocol work. No existing generic evidence-algebra product surface; current research discipline requires recurring burden before externalization. |
| Runtime | `d90a6b8954dfbfe23a1b1b365987d75ae93aac3b` | Owns physical execution/materialization/recovery. `workspace.execBound` already provides exact foreign immutable inputs when a named external authority is needed; Runtime does not own domain interpretation. |

Finance is therefore the first independent cross-domain consumer proving that mechanical reduction is not Security-specific. But Finance also falsifies the idea that every domain needs the same reducer API: Finance needs PIT/as-of semantics, tabular programs and domain result admission, while Security AE3-C needs a tiny exact history projection.

The candidate shared invariant is instead:

```text
exact input identity
+ exact program identity
+ bounded physical execution
+ exact result identity
→ derived factual evidence
```

## Why EC0 does not use Finance's Runtime input authority

The live Runtime installation currently exposes one immutable-input authority named:

```text
finance-research-materializations
```

EC0 deliberately does not place Security data under that authority. Reusing a mechanism by violating its ownership boundary would be a false abstraction win.

Security's AE3-B histories are static research fixtures. Git is already their exact source owner. Runtime's Workspace source commitment can bind the complete committed Security source state for execution. Finance's changing PIT datasets need a different physical carrier: Finance materializes exact analytical cuts and hands them to Runtime through named immutable input authority.

Therefore:

```text
same invariant
!=
same physical source carrier
```

## Standalone reducer

EC0 adds only research apparatus under:

```text
research/experiments/ec0-evidence-computation/
  reducer.py
  a-history.json
  b-history.json
```

`reducer.py` is pure Python standard library. It imports neither `ordivon_security`, Finance, Polars nor DuckDB. Its file SHA-256 at the physical experiment revision is:

```text
sha256:1b90ae36c6489968f30ef45fe801ba57834922e0022c0031c4508b49097d4249
```

Git blob identity:

```text
f32759db0e74538388a347f7ce26bd505a45b3f8
```

The two canonical fixture-file SHA-256 values are:

```text
A fixture:
sha256:3400f9fc2590d0cb8c166370de7cc2c79492f0c98bdfc6a78bb42dce4abd16e7
Git blob 48bcbbe9e994f7d58cd5140f3b66189575593018

B fixture:
sha256:37a2998434f2a5a16ba66b963ca39aa37169b9eda14e5526cc1845f9dc14caee
Git blob 52a30b36a13c2ec41a2fb3d1cb83cf7818574051
```

Inside those fixture envelopes, the semantic source evidence remains byte-canonically identical to accepted prior experiments:

```text
A history
sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635

B history
sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83

current sensor set
sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053
```

## Static semantic equivalence

Before physical Runtime execution, unit tests execute the standalone program with `/usr/bin/python3` and compare its full JSON object—not selected fields—to the accepted AE3-C reducer output.

The standalone A result is exactly the accepted projection:

```text
sha256:2c174f54aec45bbe79c7c0de941c3a1417f7b47089e6759800ac5d9a8500cc5b
```

The standalone B result is exactly:

```text
sha256:c394429dd58b224036912bdac053d7f474fd8f1cc34c673cd6e9cfed792109d1
```

EC0 then injects each externally computed projection into the unchanged AE3-C observation/context schema. The resulting context digests are exactly the ones already consumed by the accepted AE3-C Provider runs:

```text
A context
sha256:f4dac35c52d2ac717587d0ec12116b07de650d5f5f92373854629b90fb1e3e16

B context
sha256:6a0bb809e9df65ef4609d04775043a569f3782a024a644251f5448d261e5a914
```

This matters more than another stochastic model sample. EC0 changes where the projection is computed while preserving the complete Agent-visible semantic context. Existing AE3-C evidence has already physically consumed those exact contexts.

## Physical Runtime execution

The apparatus was committed before physical execution at:

```text
3ffafc4544f4fdda4d2d747a01006c415eef3b8f
```

The Workspace was opened from Security main `ad24160ab0a3eaec7656ffd8f530a6a86ba55b75`, then advanced cleanly to the EC0 apparatus commit. Runtime correctly preserves these as different facts:

```text
Workspace sourceRevision       = ad24160ab0a3eaec7656ffd8f530a6a86ba55b75
Workspace currentHeadRevision  = 3ffafc4544f4fdda4d2d747a01006c415eef3b8f
Workspace source-state digest  = sha256:8b864a17032bfcf291b113a7d4091b4d7563a93a473cbd02aa2a6146ae7c1145
```

Both Runtime Job Registry snapshots and both immutable Execution Plans bind the same exact Workspace source digest:

```text
sha256:8b864a17032bfcf291b113a7d4091b4d7563a93a473cbd02aa2a6146ae7c1145
```

### A-history Runtime Job

```text
jobId       job-019fe533-b0a3-7ab1-8518-260bdf6435e2
attemptId   attempt-019fe533-b0a3-7ab1-8518-2610af261aff
profile     contained_local
planDigest  sha256:9ae446f4e9796e2614f8f8fc5528c53ca750e2fb192bee570d0ac75062f05712
stdout      sha256:e72a7c67a942b304ba828549ff45c7b237f64ca44b786a87e52183397876d675
terminal    sha256:dbcdb11d976a4835da970f71b7d41ef4ed0970c388d39a79456666a91d967912
result      sha256:ea68ba3f2785dac44ff2a3903644c4b119e2a0c0034e9d01f1c3db6ab40c545f
```

Runtime canonicalized the `/usr/bin/python3` invocation to the verified target `/usr/bin/python3.14`. The process exited zero, delivery committed, and the process tree was terminal-clean. Its complete retained stdout parses to the accepted A projection.

### B-history Runtime Job

```text
jobId       job-019fe533-ff81-7aa1-817b-c0e21aef03ca
attemptId   attempt-019fe533-ff81-7aa1-817b-c0fd86e77b8c
profile     contained_local
planDigest  sha256:f9ea8a41d6288d1ab3d50169870444a08ddc9f34890adb88670266e6fb1b5699
stdout      sha256:62e2557343b74695942f83c02231b74277c16ff26efb6d85b4929b284669c240
terminal    sha256:b49684284377d466e5caa75a8b056ba0d3db2a8de8c1ad914ce614f5782ae7a5
result      sha256:ffbeb31b452bcce5e506d0473d23727234f2e6d7d183021cf02f9ddfe7b34bb7
```

It likewise exits zero under `contained_local`, with committed delivery and terminal-clean process ownership, and emits the accepted B projection.

No model Provider call is part of EC0.

## A Runtime evidence-projection friction exposed by EC0

EC0 also revealed a narrow observability gap that belongs to Runtime, not Security.

The Runtime Registry's Workspace snapshot and Execution Plan both contain the exact `workspaceSourceDigest` used for admission. But the terminal-evidence Artifact projects only `sourceRevision`, which for this Workspace is the immutable opening/base revision `ad24160...`, not the current committed HEAD `3ffafc4...`, and it does not project `workspaceSourceDigest`.

Therefore a consumer holding only terminal evidence cannot independently prove which mutable Workspace source state was executed after the Workspace advanced. EC0 had to join:

```text
terminal evidence
+ workspace.get
+ read-only Registry execution-plan projection
```

to recover the exact source-state binding.

Candidate cross-project requirement:

> Runtime should eventually expose the committed Workspace source-state digest in portable terminal execution evidence, or provide an equally exact public non-mutating Job projection, so downstream evidence consumers do not need internal Registry access.

EC0 does not implement that Runtime change and does not reinterpret Runtime's existing opening `sourceRevision` field.

## Result

EC0 accepts the following scoped claims:

1. the AE3-C reducer implementation is not required to live inside `ordivon_security` to reproduce the accepted derived facts;
2. an ordinary standalone committed program over exact source-owned input bytes can reproduce the full accepted projections;
3. those external projections reconstruct the exact Agent-visible AE3-C context digests already consumed by the accepted Provider experiment;
4. Runtime can physically execute the committed program under `contained_local` while binding the complete Workspace source state and retaining exact result/terminal Artifacts;
5. Finance independently demonstrates the same lower-level pattern for dynamic PIT data using domain materialization plus Agent-authored analytical programs;
6. different domains may legitimately use different input authorities and compute libraries while sharing the same evidence-computation invariant;
7. no new Security Trust/Reputation/SourceHistory/reducer primitive is forced;
8. no new cross-project `EvidenceReducer` library or repository is forced.

The strongest current candidate law is:

```text
Derived computation authority
=
exact source evidence
+ exact transformation identity
+ exact physical execution evidence
+ exact output identity
```

This authority establishes what computation produced which derived bytes. It does **not** promote the derived result to current world truth or decide how an Agent should act on it.

## Ownership after EC0

### Security

Owns adversarial meaning:

```text
source identity
sensor observation
adjudicated truth
UNKNOWN
consequence
provenance requirements
```

Security may retain experiment-local computation programs when they are part of a specific falsifiable study. It should not own generic arithmetic because AE3-C happened to need counts.

### Finance

Owns financial data/PIT/economic semantics and its result admission. It may use Polars, DuckDB or Agent-authored programs because those are Finance-lab equipment, not universal Security contracts.

### Runtime

Owns exact physical execution, Workspace source commitment, immutable foreign input materialization where needed, contained execution, Job/Attempt identity and physical Artifacts. Runtime does not decide the semantic meaning of a count or projection.

### Harness

Owns the Agent-facing model/Tool loop, Working Set selection and observation flow. A future Agent may discover or invoke a computation Tool through Harness, but Harness should not silently choose which domain evidence to aggregate.

### Computing

May synthesize the cross-domain world-model distinction and track repeated burden. EC0 does not justify moving reducer implementation into Computing or creating an evidence-algebra package now.

### World

Continues to own cross-world connection/action and trajectory/provenance semantics. Current World evidence did not force statistical reduction ownership.

## What EC0 rejects

Do not build now:

```text
Security EvidenceReducer API
Trust DB
Reputation Engine
universal confidence score
ordivon-evidence repository
generic evidence algebra package
Harness-owned automatic source ranking
Runtime-owned domain aggregation semantics
```

A generic compute library becomes justified only when repeated consumers cannot economically use ordinary committed programs plus existing domain/Runtime/Harness mechanisms.

## Next pressure

The next structural question is no longer “where should the reducer live?” It is:

> When a derived fact remains integrity-valid but its source evidence has advanced, how does a fresh Agent know whether that derivation is still applicable?

That is a real path toward freshness rather than a sequence-number exercise. A future experiment should preserve an old valid projection, advance the source evidence under a new exact identity, recover from a fresh Agent/Workspace, and test whether source-binding alone is sufficient to reject stale applicability.

Only if that consumer physically reaches an integrity-valid-but-stale ambiguity should C1-O witness freshness be resumed.
