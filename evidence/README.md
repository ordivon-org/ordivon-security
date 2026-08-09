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
updated: 2026-08-08
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

The S6 topology-churn acceptance index is retained at [`acceptance/windows-kvm-s6-topology-churn-03a93e3.json`](acceptance/windows-kvm-s6-topology-churn-03a93e3.json). It binds the exact committed implementation, final private physical-receipt digest, retained fast-exit and stale-current-truth falsifiers, the ordered A-present/A-removed/B-present Host topology observations, final peer-B current truth, both externally observed TCP flows, the contested Guest dual-peer claim, and complete machine plus namespace residual closure. It does not create a generic topology graph or Range mutation API.

The S6-R progression/recovery acceptance index is retained at [`acceptance/windows-kvm-s6-progression-recovery-1eb638c.json`](acceptance/windows-kvm-s6-progression-recovery-1eb638c.json). It binds the final `1eb638c` implementation, the post-S6 read/effect correction, bounded Host topology convergence, durable dynamic Range resource identity, a final accepted Guest-driven S6 regression, and an owner-SIGKILL challenge where QEMU, swtpm, peer B, and tcpdump were independently live before a new exact S5/S6 Range reconciler closed every declared process, namespace, run directory, ledger, and maintained canary with zero residuals. Evaluation reconciliation remains a separate policy consumer.

The C1 executable-authority acceptance index is retained at [`acceptance/c1-executable-range-authority-49f1aa9.json`](acceptance/c1-executable-range-authority-49f1aa9.json). It binds the exact `49f1aa9` implementation, rejected fake/wrong-scope authority requests, a peer-A-complete world that remained unchanged before valid authority, exact admission/request replay, the non-truth backend effect receipt, propagated effect identity, independent A-removed/B-present Host topology truth, Guest and packet-sensor observations, clean residual closure, the initial state-root permission falsifier, and a separate accepted regression of the original backend-owned S6 profile.

The C1-A autonomous-intent acceptance index is retained at [`acceptance/c1a-autonomous-range-intent-f692c22.json`](acceptance/c1a-autonomous-range-intent-f692c22.json). It binds the same model/Harness/authority/world contrast that produced `hold` for stability and `request-effect` for continuation, exact uncorrected effect scope, the resulting C1 physical consequence, immutable pre-intent and post-control topology snapshots, the first physical-success/evidence-aliasing falsifier, independent Host topology truth, Guest and packet-sensor observations, and clean closure. Model traces are represented by digests rather than complete Provider transcripts or secrets.

The C1-B interrupted-consequence acceptance index is retained at [`acceptance/c1b-interrupted-consequence-3606734.json`](acceptance/c1b-interrupted-consequence-3606734.json). It binds the pre-fix physical-recovery/semantic-recovery falsifier, the minimal durable Actor effect-binding change, an owner-SIGKILL intermediate A-removed/B-absent acceptance, a B-materialized/completion-event-lost acceptance, exact non-truth backend receipts, independent Host topology observations, safe zero-residual reconciliation, and a final ordinary S6 regression. It records that this exact single-effect consumer did not force generic `causalParents` enforcement.

The C1-C partial-materialization acceptance index is retained at [`acceptance/c1c-partial-materialization-39693eb.json`](acceptance/c1c-partial-materialization-39693eb.json). It binds a pre-fix owner-SIGKILL where peer-B namespace plus root q/w veth resources existed while stable topology still said `peer-a-removed`, the old reconciler's false `passed` clean claim with residual Host links, the minimal deterministic `ownedHostLinkCandidates` recovery fix, Host veth type validation and residual re-observation, a repeated physical fault with zero Host-link/namespace residuals and no experiment cleanup, and a final ordinary S6 regression.

The C1-D fresh-controller continuation acceptance index is retained at [`acceptance/c1d-fresh-controller-continuation-691145f.json`](acceptance/c1d-fresh-controller-continuation-691145f.json). It binds a Guest-driven A connection, owner SIGKILL at the C1-C root-veth partial state, inherited effect/resource identity, fresh-process continuation to peer-b-present without old RangeSession/event recovery or durable substep state, the same Guest's successful B connection, one packet capture spanning both flows, durable peer-B process publication, and zero-residual final reconciliation.

The C1-E successor-ownership acceptance index is retained at [`acceptance/c1e-successor-ownership-d82241b.json`](acceptance/c1e-successor-ownership-d82241b.json). It binds the pre-fix physical successor/reconciler interleaving falsifier, exact-ledger-generation successor claim semantics, predecessor-provenance separation, per-Run kernel recovery arbitration, a first reconciler that skips a live successor without world mutation, successor continuation to peer-b-present, successor SIGKILL with stale durable claim metadata, a second reconciler that acquires authority after kernel lock release and records that exact stale claim, and final zero-residual closure.

The C1-F multiple-successor acceptance index is retained at [`acceptance/c1f-multiple-successors-511f08f.json`](acceptance/c1f-multiple-successors-511f08f.json). It binds two candidates observing the same initial generation, exactly one initial recovery-authority winner, a non-mutating loser, winner continuation to a newer ledger generation, loser retry against that newer generation with `adopted-existing-effect` and no replay/mutation, the pre-fix overwrite-lineage falsifier, exact predecessor-claim archival plus predecessorClaimId/digest, final reconciler preservation of current and archived claim history, and zero-residual closure with recovery metadata removed.

The C1-G mid-successor recovery acceptance index is retained at [`acceptance/c1g-mid-successor-recovery-38f6e52.json`](acceptance/c1g-mid-successor-recovery-38f6e52.json). It binds one successor's SIGKILL after q/w placement and bridge attachment but before stable publication, the unchanged-ledger/different-physical-world result, a second lineage-linked claim against the same durable digest, independent midpoint re-observation, missing-suffix-only continuation, the same Guest's A/B completion across two controller deaths, packet-sensor dual-flow evidence, and final zero-residual reconciliation with successor lineage preserved.

The C1-H unpublished-completion acceptance index is retained at [`acceptance/c1h-unpublished-completion-6fce713.json`](acceptance/c1h-unpublished-completion-6fce713.json). It binds a fully materialized and Guest-consumed peer-B consequence whose durable ledger remains peer-a-removed after successor SIGKILL, a lineage-linked second successor over that unchanged durable digest, persistent Host topology plus completed Guest evidence plus read-only packet-sensor A/B evidence, no transient peer restart or Range-world replay, publication-only repair to peer-b-present with peerPid=0, the rejected observation-mutates-sensor candidate, and final zero-residual reconciliation with claim lineage preserved.

The C1-I information-loss acceptance index is retained at [`acceptance/c1i-information-loss-3241eb9.json`](acceptance/c1i-information-loss-3241eb9.json). It binds delivered and undelivered local vanishing-pulse histories with byte-identical durable sender state and successor views, required `UNKNOWN` classification, a restricted-principal blind-retry duplicate falsifier, physical denial of recipient-private dedup reads, same-effect resend through the public local capability endpoint, duplicate suppression versus first application, convergence to one application in both histories, completion acknowledgement, and zero residual public socket endpoints.

The C1-J recipient-commit-gap acceptance index is retained at [`acceptance/c1j-recipient-commit-gap-6563613.json`](acceptance/c1j-recipient-commit-gap-6563613.json). It binds both consequence/marker write orderings, duplicate-on-retry versus lost-consequence falsifiers, restricted-principal recipient-marker separation, byte-equivalent `reserved` inbox histories with different evaluator truth, retry-versus-suppress impossibility from that common state, and zero residual local capability endpoints.

The C1-K intrinsic-idempotency acceptance index is retained at [`acceptance/c1k-intrinsic-idempotency-e41ccf0.json`](acceptance/c1k-intrinsic-idempotency-e41ccf0.json). It binds an exact local ensure-state consequence, two-invocation/one-mutation/one-semantic-result recovery after ACK loss, crash-before-apply convergence under the same retry policy, exact preexisting-state satisfaction with zero request-owned mutation, absence of adjacent dedup/inbox world objects, and zero residual local capability endpoints.

The C1-L compensation acceptance index is retained at [`acceptance/c1l-compensation-bbbacb4.json`](acceptance/c1l-compensation-bbbacb4.json). It binds a real duplicated non-idempotent balance consequence, distinct compensation identity, blind-compensation overrepair falsifier, crash-before-compensation re-observation and repair, crash-after-compensation-before-ACK publication-only recovery, exact repair-invariant authorization, and zero residual local capability endpoints.

The C1-M compensation-information-loss acceptance index is retained at [`acceptance/c1m-compensation-information-loss-404e7e6.json`](acceptance/c1m-compensation-information-loss-404e7e6.json). It binds repaired/unrepaired downstream-private histories with byte-equivalent caller facts, required caller `UNKNOWN`, restricted-principal denial of private-state reads, naive compensation blind-retry divergence, an explicitly distinct convergent compensation protocol, safe same-protocol retry across both hidden histories, physical private-world inventory containing only the consequence state, and zero residual local capability endpoints.

The C1-N downstream-truth-failure acceptance index is retained at [`acceptance/c1n-downstream-truth-failure-88d068b.json`](acceptance/c1n-downstream-truth-failure-88d068b.json). It binds missing/corrupt/forked downstream truth dual histories, identical owning-authority post-fault observations, zero-mutation fail-closed ensure-repaired behavior, distinct sealed-witness truth recovery for all six histories, tampered-witness rejection, and the explicit limitation that witness freshness/independent failure-domain/atomic publication remain unproved.

The World Entity controller-loss acceptance index is retained at [`acceptance/world-entity-controller-loss-09a350c.json`](acceptance/world-entity-controller-loss-09a350c.json). It binds the exact `09a350c` observation-only Entity implementation, a real Windows KVM carrier stopped with controller `SIGKILL` after QMP confirmed no network device but before stable materialization publication, surviving QEMU/swtpm processes, fresh-process `UNKNOWN` reconciliation with byte-identical ledger and preserved predecessor owner identity, refusal to blind-resume the same unpublished migration, absence of a false materialization receipt, and final clean native closure. It is the negative baseline proving non-overreach before publication recovery was admitted.

The clean revision-3 Entity competing-publication index is retained at [`acceptance/world-entity-publication-race-03a55aa.json`](acceptance/world-entity-publication-race-03a55aa.json), SHA-256 `17270028f90ddee68bef94f7e75a81d83692e58d94cff932acd74be7b074645f`. Two fresh publishers were released concurrently after original-controller `SIGKILL`; both returned the same `materialized` outcome, exactly one stable-publication attempt occurred, predecessor owner and QEMU/swtpm identities remained unchanged, no physical body replay occurred, and final closure was clean.

The clean revision-3 Entity publisher-crash index is retained at [`acceptance/world-entity-publisher-crash-03a55aa.json`](acceptance/world-entity-publisher-crash-03a55aa.json), SHA-256 `100e32509f61a6b1492933a075093c9d8f233194022e23e705fd730458e541e6`. The first fresh publisher was killed after durably publishing `migration-running-contained` but before receipt commit. A second fresh process made no second stable-publication attempt, left the stable ledger byte-identical, reconstructed the missing receipt, preserved predecessor and native-process identities, replayed no physical body, and closed cleanly. Together with C1-H, these results support completion/publication separation while showing that this narrower publication-only consumer has not demonstrated a need for a durable successor claim beyond the existing per-migration process-scoped gate.

P0.1 reconciliation receipts bind the scanned state root, each ledger decision, exact process-identity closure, Run-directory and ledger deletion, skipped active owners, and any attention-required diagnostics. They do not convert a crashed Run into valid Evaluation evidence. P1 media manifests bind the installer profile digest, exact source identity, NTFS image digest, embedded-file verification, and read-only attachment topology; they explicitly state `prepared-not-executable` and cannot establish runtime behavior.

The sanitized R4-A materializer-canary index is retained at [`acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json`](acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json). It binds a committed implementation revision, a private receipt digest, pre-extraction archive validation, a complete tree digest, `noexec` NTFS population, read-only remount verification, source immutability, and residual closure. The canary used only maintained benign data: it does not admit QEMU attachment, a Controller, Case A execution, or Case B.

The DaVinci R2 static-causality index is retained at [`acceptance/windows-kvm-p1-davinci-causality-r2.json`](acceptance/windows-kvm-p1-davinci-causality-r2.json). It re-verifies the 7.4 GiB archive and selected component identities, separates the statically bound wrapper → outer-MSI → replacement-patch-engine path from the contained but reachability-unproven nested downloader MSI, records that the outer MSI has no literal reference to the nested archive/MSI/downloader chain, revalidates the unchanged signed host control, and keeps the historical C2-D0 controller canary distinct from current main capability. It does not claim that absence of a literal reference proves dynamic unreachability.

The sanitized R5 selective-execution-control index is retained at [`acceptance/windows-kvm-p1-execution-control-canary-fe72177.json`](acceptance/windows-kvm-p1-execution-control-canary-fe72177.json). It binds the exact clean Security implementation revision, the maintained no-network canary, the SYSTEM execution identity, writable root and nested staging probes, inherited NTFS `ExecuteFile` deny evidence, a successful executable outside the staging tree, denied root and nested staging executables, QMP no-network authority, and clean residual closure. It also retains the AppLocker prototype as a rejected candidate for this exact SYSTEM surface. It does not execute Case A, prove nested-MSI reachability, seal the Controller into the P1 base, or authorize Case A or Case B.

The sanitized R6-A generic-Controller index is retained at [`acceptance/windows-kvm-p1-generic-controller-e352e86.json`](acceptance/windows-kvm-p1-generic-controller-e352e86.json). It binds a clean Security source revision, the exact accepted Controller PE retained in the root-only Vault, its fixed sealed-orchestrator production boundary, manifest SHA-256 verification, Job Object child ownership, bounded timeout termination, QMP no-network truth, and residual closure. The index explicitly rejects arbitrary executable targeting and does not treat recompilation as the accepted PE identity. It does not prove the production orchestrator path, seal the Controller into a P1 base, execute Case A, or authorize Case A or Case B.

The sanitized R6-B layered-base index is retained at [`acceptance/windows-kvm-p1-derived-base-5d4b9ca.json`](acceptance/windows-kvm-p1-derived-base-5d4b9ca.json). It binds the accepted immutable Windows parent, the corrected clean sealer revision, the qcow2 backing relationship, exact Vault resource identities, read-only Guest-file verification, parent immutability, NBD closure, the Provider's `root:qemu 0710` images-directory traversal authority, and a separate booted-Guest probe over the exact sealed Controller and R5 self-test bytes. Both sealed self-tests complete successfully under the no-NIC Provider and residual closure remains clean. It explicitly preserves `productionOrchestratorSealed=false`, `productionControllerPathExercised=false`, `thirdPartySampleExecuted=false`, and `caseAExecutionAuthorized=false`.

The sanitized R6-C production-orchestration index is retained at [`acceptance/windows-kvm-p1-production-orchestrator-be4eae1.json`](acceptance/windows-kvm-p1-production-orchestrator-be4eae1.json). It binds the bounded Observer revision, exact layered replacement from the superseded Observer, a successful full-budget Observer runtime probe, and the maintained generic-Controller production path through the sealed orchestrator. The accepted path verifies Controller manifest binding and timeout state, SYSTEM/orchestrator/control identities, pre/post Observer ordering, selective staging execution control, QMP no-network truth, and residual closure. It executes no third-party installer or malware sample and explicitly keeps `actualCaseAExecuted=false`, `caseAExecutionAuthorized=false`, and `nestedMsiReachabilityProved=false`.

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
The AF3 Agent-first deception acceptance index is retained at [`acceptance/af3-agent-first-deception-9874d3e.json`](acceptance/af3-agent-first-deception-9874d3e.json). It binds one real DeepSeek/Harness defender across two owned local worlds with the same communicated compromise claim and objective: independent truth false produces an AF2 zero-request hold and no world mutation; independent truth true produces one exact quarantine request, separate RangeAuthority admission, a non-truth execution receipt, and fresh world-truth verification. It establishes only that this first deception consumer does not require a Trust, Reputation, Organization, or generic policy primitive.

The AE0 Adversarial Epistemics acceptance index is retained at [`acceptance/ae0-adversarial-epistemics-6b2d09b.json`](acceptance/ae0-adversarial-epistemics-6b2d09b.json). It binds an autonomous Deceiver and Defender across two hidden local worlds. Receiver-visible claim and complete Defender pre-inspection context are identical across the worlds; the Defender requests the same bounded inspection effect, later independent world truth separates the worlds, and only then does consequence diverge into hold versus quarantine. The result treats `UNKNOWN` as a valid trigger for information acquisition, not fabricated certainty, and does not force Trust/Reputation or a new communication core.

The AE1 delayed-truth acceptance index is retained at [`acceptance/ae1-delayed-truth-a428ab2.json`](acceptance/ae1-delayed-truth-a428ab2.json). It binds one autonomous false claim, exact counterfactual replay into healthy/compromised hidden worlds, one shared pre-truth Defender inspection decision, one shared zero-effect hold while inspection remains pending, explicit Range causal evidence that the hold precedes truth publication, a real compromised-world delay exposure cost of `3`, and post-truth divergence into healthy availability versus compromised quarantine. It also records the AF2 integration boundary that positive effects require explicit Tool requests while zero-effect decisions may close without a ceremonial Tool call. Trust/Reputation, freshness, reversible containment and conflicting sensors remain unproved.

The AE2 conflicting-observations acceptance index is retained at [`acceptance/ae2-conflicting-observations-990e71f.json`](acceptance/ae2-conflicting-observations-990e71f.json). It binds the exact AE1 adversarial claim, two distinct sensor-plane observations that disagree about `serviceCompromised`, a shared pre-truth Defender decision that requests adjudicating inspection rather than arbitrarily selecting a source, separate admission/execution, and a `world-truth` result causally bound to both the Agent decision and executed inspection. After current truth arrives, contradictory sensor history is preserved but no longer defines the current property as unresolved. The run does not establish durable Trust/Reputation, source-history, confidence or freshness semantics.
