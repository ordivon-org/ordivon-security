---
schema_version: 1
id: security.evidence
title: Evidence
type: reference
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - evaluator
  - maintainer
  - agent
updated: 2026-08-07
summary: Evidence contract for active Contest, CAGE, software Evaluation, static native-report Artifacts, Case Snapshots, P0-admitted benign-only Windows KVM Runs, and frozen Round 1 reports.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security-evidence
related:
  - security.architecture
  - security.research-boundary
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.case-snapshot-p0
  - security.windows-kvm-p0
  - security.agent-experiment-p0
  - security.migration.round2
  - security.migration.round3-p0
  - security.authority
---
# Evidence

## Active Contest bundle

Every active Trial writes:

```text
manifest.json
trial-identity.json
raw-metrics.json
result.json
bundle-manifest.json
operational-manifest.json
events/
  actor.jsonl
  range-management.jsonl
  sensor.jsonl
  world-truth.jsonl
  operational.jsonl
```

Each semantic channel has its own sequence and hash chain. The semantic bundle manifest binds event counts, chain heads, file digests, Scenario digest, Trial execution identity, raw metrics digest, and result digest. The operational stream has a separate wall-clock hash chain and manifest bound to the semantic evidence digest; its variability does not alter deterministic semantic replay. Actor events may contain only the observation admitted to that Actor; hidden world truth belongs exclusively to the truth channel.

An active claim is inadmissible when:

- Scenario, Security implementation, evidence schema, Actor implementation, Range adapter/substrate, seed, Action grant, or limits are missing from identity;
- Actor context leaks hidden truth;
- sensor telemetry is treated as infallible world truth;
- a proposal is presented as a verified effect;
- raw metrics or individual Trials are discarded in favour of one aggregate score;
- event bytes, sequence, previous digest, or bundle summaries fail verification;
- secrets, real endpoints, third-party credentials, packet captures, or unauthorized artifacts enter Git.

## Active Evaluation bundle

Every software Evaluation Run writes:

```text
evaluation-spec.json
execution-identity.json
findings.json
result.json
bundle-manifest.json
operational-manifest.json
artifacts/                 # optional schema-v2 native reports
events/
  sample.jsonl
  management.jsonl
  observer.jsonl
  guardian.jsonl
  world-truth.jsonl
  operational.jsonl
```

The Sample channel contains identity and digest references only. Sample bytes remain in the local SampleVault and are inadmissible in Git, semantic evidence, operational evidence, Host state, or model Provider prompts. Evaluation Evidence schema revision 2 may retain native analyzer reports under `artifacts/`; each entry binds identity, kind, digest, byte length, media type, logical name, and relative path.

An Evaluation claim is inadmissible when Authority does not bind the exact Sample and environment, identity omits a relevant policy or image revision, Observer and Guardian authority are conflated, residual closure is incomplete, Findings omit exact evidence references, or any event or manifest fails verification. `no-issue-observed` is bounded to the exact Run and is not a general software-safety guarantee.

The fixture backend never invokes Sample bytes. The static backend permits admitted analyzers to read bytes as data but never loads, installs, or invokes the Sample. A static antivirus match is an Observer result, not independent proof of runtime behavior. Imported reports must state that they were produced before the current Trial and remain bounded by their retained bytes and limitations. Artifact tampering invalidates verification.

A P0-admitted Windows KVM Run additionally binds the sealed base image, disposable overlay configuration, UEFI and TPM identity, QEMU and swtpm binaries, management-plane QMP status, and no-network PCI result. Guest and fixture results may be retained as Artifacts, but they cannot establish QEMU topology or residual closure. The Run is inadmissible when any network-class PCI device appears, the exact benign fixture contract differs, Guest result identity differs, QEMU or swtpm remains alive, or the disposable Run directory survives destruction. P0 admits only the exact maintained benign fixture; no unknown Sample or third-party installer is admissible.

The sanitized Windows KVM P0 acceptance index is retained at [`acceptance/windows-kvm-p0-5c6a854.json`](acceptance/windows-kvm-p0-5c6a854.json). It binds the sealed environment identity, six passed gates, private receipt digests, exact admission scope, diagnostic cleanup outcome, and explicit limitations without exposing Sample bytes, temporary installation secrets, or machine-local paths.

The S3 sacrificial-node acceptance index is retained at [`acceptance/windows-kvm-s3-sacrificial-node-fc5740a.json`](acceptance/windows-kvm-s3-sacrificial-node-fc5740a.json). It binds the committed Range implementation, the first failed QMP-reset falsifier, the final private physical-receipt digest, external no-NIC/reset/lifecycle/closure gates, and the explicit rule that the canary result is a contested Guest claim used only to establish trial completeness.

The S4 out-of-band truth acceptance index is retained at [`acceptance/windows-kvm-s4-out-of-band-truth-0f9d35a.json`](acceptance/windows-kvm-s4-out-of-band-truth-0f9d35a.json). It binds the first failed representation falsifier, the accepted physical-receipt digest, exact Security source identity, read-only qemu-nbd/NTFS tool identities, selected post-run file presence/digests/absence, and the separation between contested Guest claims and `world-truth` observations. It does not claim live introspection, process attribution, complete filesystem truth, or network truth.

The S5 isolated-fabric acceptance index is retained at [`acceptance/windows-kvm-s5-isolated-fabric-c1cef7a.json`](acceptance/windows-kvm-s5-isolated-fabric-c1cef7a.json). It binds the exact committed Range implementation, final private physical-receipt digest, retained failed falsifiers, one Windows/full-VM plus one lightweight netns peer materialization, no-uplink/no-L3 Host topology facts, exact one-NIC QMP evidence, the external packet-sensor pcap digest, the contested Guest connectivity claim, and complete machine plus network-namespace residual closure. Packet capture remains a fallible `sensor` observation rather than `world-truth`.

P0.1 reconciliation receipts bind the scanned state root, each ledger decision, exact process-identity closure, Run-directory and ledger deletion, skipped active owners, and any attention-required diagnostics. They do not convert a crashed Run into valid Evaluation evidence. P1 media manifests bind the installer profile digest, exact source identity, NTFS image digest, embedded-file verification, and read-only attachment topology; they explicitly state `prepared-not-executable` and cannot establish runtime behavior.

The sanitized R4-A materializer-canary index is retained at [`acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json`](acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json). It binds a committed implementation revision, a private receipt digest, pre-extraction archive validation, a complete tree digest, `noexec` NTFS population, read-only remount verification, source immutability, and residual closure. The canary used only maintained benign data: it does not admit QEMU attachment, a Controller, Case A execution, or Case B.

## Active Case Snapshot bundle

An evolving local Case may be retained as:

```text
case-manifest.json
snapshot-receipt.json
```

The manifest binds relative paths, types, modes, file byte lengths and SHA-256 identities, execution status, explicit limitations, linked Evaluation Run identities, quarantine-policy summary, and Security source revision. The receipt retains the machine-local root and record time without changing semantic snapshot identity.

A Case Snapshot is not Evaluation Evidence. `external-uncontrolled-execution` material may prove that a command produced retained bytes, but it does not establish an admitted environment, deny-all egress, independent observation, Guardian enforcement, machine destruction, residual closure, or behavioral truth. A human summary cannot promote such material into `controlled-trial`.

## Agent experiment acceptance

The sanitized acceptance indexes are retained at:

- [`acceptance/deepseek-cage-p0a-seed1-run4.json`](acceptance/deepseek-cage-p0a-seed1-run4.json);
- [`acceptance/deepseek-cage-p0b-seed1-run2.json`](acceptance/deepseek-cage-p0b-seed1-run2.json);
- [`acceptance/deepseek-cage-p0bc-c170e6d-seed1.json`](acceptance/deepseek-cage-p0bc-c170e6d-seed1.json).

They bind the accepted Trial and evidence digests, exact Provider/Harness/Host/
Runtime/Security identities, credential scopes, budgets, proposal summaries, raw
metrics, negative predecessor Trials, acceptance claims, and limitations. The historical
P0-B index binds both Host Task heads, lifecycle object digests, private state modes,
completion decisions, and the absence of Runtime Job references. The controlled
P0-B/P0-C index additionally binds the shared Harness revision, full Host storage
and Harness-extension history validation, the isolated Runtime-consumption variable,
P0-C Job/Attempt and Artifact identities, exact replay, unique recovery lookup,
four typed foreign references, and terminal process-tree cleanup.

The indexes are not replacements for the complete private Trial bundles. A claim
is admissible only when the private semantic and operational bundles independently
verify to the recorded digests. The indexes contain no API key, Bearer token,
secret path, or complete model transcript.

## CAGE evidence

A CAGE Trial additionally binds:

- source repository and exact revision;
- semantic Range configuration digest;
- Red and Blue Security Actor plans;
- number of CAGE Red and Blue agents;
- number of externally submitted actions;
- explicit assertion that Red/Blue default action use is zero;
- concrete native action names;
- rewards, mission phases, and Red foothold counts;
- management-plane truth summary.

The adapter rejects a dirty source tree or an import from another checkout. Local checkout paths are operational locators and do not enter experiment identity. A claim that Ordivon controlled CAGE Red/Blue is inadmissible unless the external action count equals the number of controlled CAGE agents multiplied by executed ticks.

CAGE observations and rewards remain simulator outputs. The current team-plan bridge does not prove that Security or a model selected each concrete parameterized native action.

## Repository retention

Small sanitized bundles required for a published claim may be committed under a named experiment directory. Large raw Trials, sensitive captures, Provider secrets, and ephemeral range images remain outside Git but must be referenced by stable Artifact identity when used.

## Frozen Round 1 evidence

The following remain historical evidence for revision `92c0f9497741c3cde542c347318d2372fb884e30`:

- [`experiments/round1-20260730.json`](experiments/round1-20260730.json);
- [`r-a-control-boundary/report.json`](r-a-control-boundary/report.json).

Their old schema remains valid for those historical claims but is not the active Contest evidence contract. Exact digests and test baseline are recorded in [`../docs/archive/round1/system.md`](../docs/archive/round1/system.md).
