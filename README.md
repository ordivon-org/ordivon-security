---
schema_version: 1
id: security.start
title: Ordivon Security
type: start
profile: organization
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
updated: 2026-08-08
summary: Canonical entry to an Agent-first adversarial-autonomy laboratory built around persistent Ranges, explicit authority, independent truth, verified consequence, recovery, scoped cyber/software profiles, and evidence-backed experiments.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.law-profiles-c0
  - security.range-session-s0
  - security.architecture
  - security.research-agenda
  - security.research-boundary
  - security.evidence
  - security.authority
---
# Ordivon Security

Ordivon Security is an **authorized adversarial-autonomy laboratory** for studying how autonomous principals act, communicate, deceive, conflict, cause consequences, and recover under bounded authority and incomplete truth. Cyber is the first high-fidelity domain; it is not the definition of the project.

The persistent execution spine is **RangeSession**: a contested world may continue changing without a global tick barrier, one Action Proposal per Actor, or a universal action menu. **Contest** remains a bounded synchronous profile for reproducible comparisons. Software Evaluation, CAGE, Windows KVM, no-uplink ranges, Guardian limits, and P0/P1 procedures are likewise scoped profiles or experimental apparatus unless a separate consumer proves a more general law.

Security distinguishes **constitutional law**, **authority/resource grants**, **experiment profiles/fixtures**, and **evaluator judgments**. The current constitutional direction is intentionally small: exact principal/Actor identity, explicit authority, separated information/truth planes, typed consequential intent, independent consequence verification, honest `UNKNOWN`, recovery authority, and evidence sufficient for later reconstruction. [`docs/LAW-PROFILES-C0.md`](docs/LAW-PROFILES-C0.md) is the canonical interpretation.

Security does not own the Agent's generic cognitive loop or the machinery beneath the world. Harness owns generic model/tool cognition mechanics; Host owns semantic Task/work continuity; Runtime owns physical execution truth; World owns external capability/consequence interfaces; mature hypervisors, cyber ranges, scanners, operating systems, and telemetry systems retain their own mechanics. Security binds these systems where adversarial semantics require authority, information boundaries, conflict, consequence, or recovery.

### Maturity map

- **Constitution / reusable substrate:** C0 law distinctions, `RangeSession`, exact `RangeAuthority` actor/zone/capability grants, separated evidence planes, independent world-truth verification, and the recovery laws repeatedly forced by C1 experiments. [`docs/AGENT-FIRST-STRUCTURE-AF1.md`](docs/AGENT-FIRST-STRUCTURE-AF1.md) records the current structural classification.
- **Profiles:** `SynchronousContestProfile`, CAGE team-plan control, software Evaluation/SampleVault/Guardian, Windows KVM ranges, and World destination adapters. A profile may be accepted and useful without defining universal Agent behavior.
- **Research apparatus:** S/C acceptance runners, P0/P1 probes, fault injectors, Host/Runtime integration variants, and physical receipts. Accepted evidence remains canonical history; the apparatus itself is not automatically a stable API.
- **Open research:** AF2 now provides a minimal zero-or-more Range-intent surface without Contest ticks; deception, trust, collusion, organization, infection and strategic conflict remain higher-order consumers; effect-contract reuse beyond current experiments, witness freshness, and stronger transaction/replication mechanisms remain open until a real consumer forces them. [`docs/AGENT-FIRST-INTENT-AF2.md`](docs/AGENT-FIRST-INTENT-AF2.md) records the AF2 boundary.

## Accepted capability and evidence inventory

The list below records accepted capabilities and experimentally established boundaries. It deliberately mixes reusable substrate with scoped profiles and research results; inclusion here does **not** assign one stability tier to every item:

- an experimental S0 `RangeSession` core for persistent contested worlds without mandatory ticks or action menus;
- an S1 `SynchronousContestProfile` that attaches bounded Contest results and sealed evidence references to a persistent Range Session without merging their execution semantics;
- a multi-Actor `ScenarioManifest`;
- actor-specific observations separated from hidden world truth;
- simultaneous Action Proposals followed by explicit admission and deterministic resolution;
- an authoritative `RangeBackend` contract;
- raw metrics before derived scores;
- four independent deterministic hash-chained evidence channels: Actor, Range management, sensor, and world truth;
- a separate operational evidence chain for wall-clock duration, Provider, retry, and lifecycle facts;
- fail-closed tick semantics for Actor failure and rejected proposals;
- Trial identity binding the Security implementation, evidence schema, Range adapter/substrate, and Actor implementations;
- deterministic replay and evidence verification;
- a small synthetic Red/Blue Range proving the core loop;
- a first-class, revision-pinned CAGE Challenge 4 Enterprise Range;
- a streaming, content-addressed local `SampleVault` with private staging, quotas, recovery, and complete digest verification;
- exact authority, environment, Guardian, Observation, and Evaluation contracts;
- a replaceable Evaluation backend, a non-executing fixture backend, and a local static-analysis backend;
- file identity, 7-Zip inventory, ClamAV, historical report, and bounded Authenticode-summary adapters;
- separate Observer, Guardian, management, Sample, truth, and operational evidence;
- native report Artifacts bound into Evaluation Evidence schema revision 2;
- read-only quarantine drift audits;
- digest-bound Case Snapshots with explicit static, uncontrolled, or controlled execution status;
- an S2 `WindowsKvmMachineProvider` substrate for sealed base identity, disposable overlay/UEFI/TPM state, root-owned lifecycle ledgers, external QMP topology truth, recovery primitives, and residual closure without Sample admission;
- an accepted S3 single-node `AdversarialWindowsRange` where the maintained Guest claim reports loss of Guest-local control/observation, persistence across reboot, and synthetic telemetry deletion while external no-NIC containment, QMP reset truth, machine lifecycle, and zero-residual closure remain authoritative;
- an accepted S4 out-of-band `world-truth` path that reads selected stopped-Guest NTFS state through read-only qemu-nbd/ntfscat, independently verifying maintained persistence/deletion facts without upgrading the Guest claim to truth;
- an accepted S5 `WindowsIsolatedFabricRange` where one full Windows KVM Guest and one lightweight Linux netns peer share an isolated no-uplink L2 fabric while QMP management, Host topology truth, external packet sensing, Guest claims, and complete machine/fabric closure remain separate authorities;
- an accepted S6 `WindowsTopologyChurnRange` where the same live Windows Guest reaches peer A, management replaces A with lightweight peer B, Host truth preserves the exact A-present/A-removed/B-present sequence and current B topology, external sensing sees both flows, and closure remains complete;
- an accepted S6-R strengthening where topology progression no longer depends on `inspect()`, changing Range resources are durably bound, and an exact S5/S6 Range reconciler closes live peer/sensor/QEMU/swtpm state plus namespaces and files after owner SIGKILL;
- an accepted C1 executable-authority profile where an S6 peer-replacement effect remains physically inert after peer A exits until one Actor request passes exact `RangeAuthority` actor/zone/capability admission; backend receipt remains non-truth and Host topology observation verifies the consequence independently;
- an accepted C1-A autonomous-intent profile where the same DeepSeek Flash/Harness Actor, visible peer-A world, and capability envelope chooses `hold` or a real C1 effect according only to its objective; the experiment also hardens Range inspection into immutable JSON snapshots so later world evolution cannot rewrite retained past observations;
- an accepted C1-B interrupted-consequence profile where owner SIGKILL at both an A-removed intermediate state and a B-materialized/response-lost state preserves exact Actor/request/admission/effect identity in the durable S6 ledger; independent Host truth classifies physical progress and prevents blind whole-effect replay while the existing reconciler still owns safe closure to zero;
- an accepted C1-C partial-materialization profile where owner loss after peer-B namespace and Host-root veth creation exposed a false reconciler clean claim; S6 now durably binds exact transient Host-link candidates, recovery independently derives and type-checks those veth identities, re-observes residuals, and only claims clean when processes, namespaces, and owned Host links are all absent;
- an accepted C1-D fresh-controller continuation profile where the Windows Guest itself consumes peer A, the original controller dies during peer-B materialization, and a fresh process continues from durable effect/resource identity plus Host placement to peer-b-present without restoring the old Range object/event stream or first closing the world;
- an accepted C1-E successor-ownership profile where an unarbitrated successor/reconciler race physically destroys a preflight-valid continuation, then an exact ledger-generation successor claim plus per-Run kernel recovery gate makes continuation and orphan reconciliation mutually exclusive without rewriting predecessor identity or requiring a wall-clock lease; successor SIGKILL releases the gate and allows clean reconciliation;
- an accepted C1-F multiple-successor profile where two successor candidates over the same exact generation produce one non-mutating loser and one winner; after the winner advances the world and dies, the loser re-observes the newer ledger generation, adopts the already-materialized consequence without replay, and links its new claim to an archived exact predecessor claim so repeated recovery succession does not erase history;
- an accepted C1-G mid-successor recovery profile where one successor changes q/w physical placement and dies before publishing a new ledger state; a second successor claims the unchanged durable ledger digest, preserves predecessor-claim lineage, re-observes the changed Host world, completes only the missing suffix, and lets the same Windows Guest finish across two controller deaths; this proves ledger digest is a durable publication fence, not a physical-world progress version;
- an accepted C1-H unpublished-completion profile where peer B is fully materialized and consumed, the one-shot service and Guest finish, and the successor dies before stable publication; a later successor combines persistent Host topology, completed Guest evidence, and read-only packet-sensor evidence to classify completed-but-unpublished and repair only durable publication without restarting the transient service or replaying the Range effect;
- an accepted C1-I information-loss profile where delivered and undelivered vanishing-pulse histories collapse to byte-identical sender ledgers and successor views, forcing `UNKNOWN`; a restricted successor's blind retry physically duplicates the delivered history, while the same exact effectId becomes retry-safe when a recipient-private durable dedup record suppresses duplicates and acknowledges both first application and replay;
- an accepted C1-J recipient-commit-gap profile where faulting both orderings between the same non-idempotent pulse and a separate durable dedup marker produces either duplicate-on-retry or lost consequence; an explicit durable `reserved` inbox then proves byte-identical recipient recovery state can still hide whether the pulse occurred, so reservation preserves `UNKNOWN` but cannot make two independent commits atomic;
- an accepted C1-K intrinsic-idempotency profile where an exact ensure-state world consequence survives ACK loss and safe retry: two physical invocations produce one request-owned mutation and one semantic consequence, crash-before-apply uses the same retry policy, and preexisting exact state requires no request-owned mutation;
- an accepted C1-L compensation profile where a non-idempotent +1 consequence duplicates to balance 2, naive blind compensation retry overcompensates to 0, while sound recovery re-observes the exact repair invariant: balance 2 authorizes one compensation to 1 and balance 1 proves already-repaired so only publication is repaired;
- an accepted C1-M compensation-information-loss profile where repaired and unrepaired downstream-private histories are byte-indistinguishable to the caller and therefore historically `UNKNOWN`; naive compensation replay is unsound, while a distinctly identified `ensure-repaired` compensation contract safely converges both hidden histories without caller read authority or a sidecar receipt;
- an accepted C1-N downstream-truth-failure profile where missing, corrupt, and forked private predicate truth make the owning `ensure-repaired` authority fail closed with zero mutation; a distinct digest-bound state witness outside that private boundary restores exact truth in the tested static faults, while tampered witness data is rejected and freshness remains unproved;
- a P0 Windows Evaluation adapter that remains restricted to the exact maintained benign fixture;
- a DeepSeek Flash `NativeHarnessActorBackend` with exact Provider, Harness, Host, Runtime, Protocol, prompt, budget, and credential-scope identity;
- a P0-A CAGE path where Harness is consumed while Host and Runtime non-consumption remain explicit experimental facts;
- an accepted P0-B CAGE path where Host owns the durable Task, compiled Context, committed Assignment, Run receipt, CompletionProposal, and CompletionDecision while Runtime remains explicitly unconsumed;
- an accepted P0-C CAGE path where the same Host-assigned Harness turn executes as one recoverable Runtime Job/Attempt with verified Artifacts and a clean terminal process tree;
- management-plane QMP network-device checks and disposable qcow2, UEFI, TPM, and FAT Run state;
- evidence-bound Findings and mandatory residual-closure receipts.

In the CAGE adapter, one Security Red Actor controls the CAGE Red team and one Security Blue Actor controls five CAGE Blue agents. Every Red and Blue CAGE action is explicitly supplied by Ordivon to the joint step; Green agents remain CAGE-controlled environmental actors. The current action surface is intentionally narrow: each side selects either the pinned native team policy or Sleep. Parameter-level model control is a later integration.

It does **not yet** provide parameterized model-built CAGE actions, arbitrary model-generated shell execution, an admitted unknown-Sample Windows Evaluation path, multi-node adversarial networking, live or complete out-of-band reconstruction of Guest-internal behavior, Ghidra, YARA, capa, Volatility, containerlab, CALDERA, Zeek, Campaign execution, or production cyber operations. The accepted P0-B/P0-C comparison is limited to one seed, one CAGE tick, and team-plan selection; it does not establish multi-tick continuity, injected cancellation recovery, strategic superiority, or production readiness. The reusable Windows KVM machine substrate does not itself authorize Sample execution. The admitted Windows Evaluation path remains restricted to the exact maintained benign fixture; unknown Samples and third-party installers remain outside that path. Static analyzers may read Sample bytes as data. A historical local Wine run remains outside the admitted Evaluation path.

## Run a local Evaluation Trial dry run

```bash
printf 'owned evaluation fixture\n' > /tmp/ordivon-evaluation-fixture.bin

uv run ordivon-security-evaluation-dry-run \
  --sample /tmp/ordivon-evaluation-fixture.bin \
  --vault /tmp/ordivon-evaluation-vault \
  --output /tmp/ordivon-evaluation-evidence
```

This path verifies Sample identity, checks local authority and environment bindings, runs the non-executing fixture backend, proves residual closure, and seals evidence. It does not load or invoke the Sample as code. See [`docs/EVALUATION-TRIAL-P0.md`](docs/EVALUATION-TRIAL-P0.md).

## Run a local Static Evaluation

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

This path streams the Sample into the private Vault, invokes only the admitted static analyzers, binds native reports as Artifacts, removes temporary analysis state, and seals the Trial. It never executes the Sample. Historical ClamAV or custom Authenticode summaries may be imported by digest with explicit limitations. See [`docs/STATIC-EVALUATION-P0.md`](docs/STATIC-EVALUATION-P0.md).

## Audit and snapshot an evolving Case

```bash
uv run ordivon-security-audit-quarantine \
  --root /path/to/quarantine/case \
  --receipt /var/lib/ordivon/security/receipts/case-audit.json \
  --fail-on-violation

uv run ordivon-security-case-snapshot \
  --root /path/to/quarantine/case \
  --output /var/lib/ordivon/security/case-snapshots/case-v1 \
  --case-id case:software-assessment \
  --execution-status external-uncontrolled-execution \
  --limitation "A component was executed outside an admitted disposable backend."
```

The audit is read-only. The snapshot binds the current directory tree, file modes, byte lengths, and complete SHA-256 identities without copying Sample bytes. It does not create Evaluation truth or retroactively control an external execution. See [`docs/CASE-SNAPSHOT-P0.md`](docs/CASE-SNAPSHOT-P0.md).

## Build and verify Windows KVM Provider P0

```bash
uv run ordivon-security-windows-kvm-build \
  --source-iso /var/lib/ordivon/security/providers/windows-kvm/sources/windows-11-enterprise-eval-25h2-x64-en-us.iso \
  --state-root /var/lib/ordivon/security/providers/windows-kvm

uv run ordivon-security-windows-kvm-acceptance \
  --base-manifest /var/lib/ordivon/security/providers/windows-kvm/images/<base>.manifest.json \
  --state-root /var/lib/ordivon/security/providers/windows-kvm \
  --vault /var/lib/ordivon/security/vault \
  --evidence /var/lib/ordivon/security/evidence
```

The first command builds a sealed Windows 11 Enterprise Evaluation base with no QEMU network device. The second compiles and executes only the Ordivon-maintained benign fixture in a disposable overlay. Neither command authorizes 目标产品B or another unknown Sample. See [`docs/WINDOWS-KVM-P0.md`](docs/WINDOWS-KVM-P0.md).

## Reconcile Windows KVM state after a hard failure

```bash
uv run ordivon-security-windows-kvm-reconcile \
  --state-root /var/lib/ordivon/security/providers/windows-kvm
```

P0.1 persists each Evaluation Run lifecycle in a root-owned `run-ledgers/` directory, independent of the disposable VM directory. Its Evaluation reconciler skips an exact live owner, closes only PID/start-time/command identities that still match QEMU or swtpm, removes verified orphan state, and emits attention-required diagnostics rather than guessing. It does not broaden P0 Sample admission. See [`docs/WINDOWS-KVM-RECOVERY-P0.1.md`](docs/WINDOWS-KVM-RECOVERY-P0.1.md).

S5/S6 fabric Ranges use a separate policy consumer over the same machine/process/ledger primitives:

```bash
uv run ordivon-security-windows-kvm-range-reconcile \
  --state-root /var/lib/ordivon/security/ranges/<exact-s5-or-s6-state-root>
```

That reconciler admits only the exact S5/S6 Range identities and deterministic namespace/resource set; it does not reinterpret Evaluation ledgers. S6-R physically verifies owner SIGKILL recovery with QEMU, swtpm, peer B, and tcpdump all still live before reconciliation. See [`docs/PERSISTENT-RANGE-RECOVERY-S6R.md`](docs/PERSISTENT-RANGE-RECOVERY-S6R.md).

## Prepare a P1 installer input disk

```bash
uv run ordivon-security-windows-kvm-p1-prepare \
  --profile research/cases/windows-kvm-p1-caseb-studio.json \
  --source quarantine/2026-08-05_目标产品B/sample.7z \
  --state-root /var/lib/ordivon/security/providers/windows-kvm
```

This command only prepares and verifies a digest-bound NTFS input image. QEMU attachment is declared read-only and removable. The retained 目标产品B profile has `executionAuthorized: false`; it does not authorize launching the archive or an installer. See [`docs/WINDOWS-KVM-INSTALLER-P1.md`](docs/WINDOWS-KVM-INSTALLER-P1.md).

R4-A can separately materialize a complete Host-extracted execution tree into another read-only NTFS candidate:

```bash
uv run ordivon-security-windows-kvm-p1-materialize-execution-media \
  --contract research/cases/windows-kvm-p1-caseb-case-a-execution.json \
  --case-manifest research/cases/windows-kvm-p1-caseb-case-a-original-repack.json \
  --transform-manifest research/cases/windows-kvm-p1-caseb-case-a-transform.json \
  --source /path/to/exact-authorized-archive.7z \
  --state-root /var/lib/ordivon/security/providers/windows-kvm
```

This command lists and validates archive paths before extraction, rejects links and special files, creates a complete digest-bound tree, and verifies it through a read-only NTFS remount. Its output remains `materialized-not-admitted`; it does not attach QEMU, start Windows, admit a Controller, or execute the installer.

P1 R0-R3 also provides manifest-verified residual reconciliation, private derived-Case materialization, a packaged Windows observer, and Case A/B/C authority records. Case A targets disposable Windows KVM and requires an environment transformation manifest. Case B and Case C target the main Windows installation: C is the read-only Free control, while B remains behind an explicit host-write Gate with automatic mutation disabled.

Capture or refresh the Free control with:

```bash
uv run ordivon-security-windows-host-p1-baseline \
  --receipt /var/lib/ordivon/security/providers/windows-host/receipts/目标产品B-free-case-c-r3.json
```

The command hashes the official `Resolve.exe` and signed `intl.dll` before and after collection and fails if either identity changes. It does not infer paid-feature state from the UI and does not modify the host.

The observer is also present in a separately sealed no-network Windows base accepted by `evidence/acceptance/windows-kvm-p1-observer-base-1367c76.json`. R4 selects one Provider-owned controller/orchestrator Runner architecture. R4-A now implements the execution contract and read-only execution-media materializer; the Controller, Case A execution, and any Case B host write remain later Gates.

## Run the deterministic Contest

Python 3.12 is the supported interpreter.

```bash
uv sync --locked
uv run ordivon-security-micro --output .artifacts/reactive --blue reactive
uv run ordivon-security-micro --output .artifacts/sleepy --blue sleepy
```

The reactive Blue baseline detects the web foothold and isolates the vault before Red pivots. The sleepy Blue baseline allows Red to establish two footholds and exfiltrate protected data.

## Run the DeepSeek Harness Actor baseline

```bash
uv run --extra cage ordivon-security-cage4-deepseek \
  --source .cache/cage4 \
  --output .artifacts/cage4-deepseek-p0a \
  --steps 1 \
  --seed 1 \
  --red-secret /root/.config/ordivon/secrets/deepseek.json \
  --blue-secret /root/.config/ordivon/secrets/deepseek1.json
```

P0-A consumes DeepSeek and Ordivon Harness. Host and Runtime are deliberately not consumed and their exact revisions plus non-consumption reasons remain in Trial identity. The first real accepted Trial completed one CAGE tick with two distinct Flash credential scopes and six explicit external Red/Blue actions. The model may select only `cage.team.native-policy` or `cage.team.sleep`; it receives no shell or Runtime Tool. This is a team-plan baseline, not a robustness or strategic-superiority claim. See [`docs/AGENT-EXPERIMENT-P0.md`](docs/AGENT-EXPERIMENT-P0.md).

To run the accepted P0-B Host variant from a fresh private state root:

```bash
uv run --extra cage ordivon-security-cage4-deepseek \
  --variant p0b \
  --source .cache/cage4 \
  --output /var/lib/ordivon/security/contests/cage4-deepseek-p0b \
  --host-state-root /var/lib/ordivon/security/host/cage4-deepseek-p0b \
  --host-state-namespace host-state:security:cage4-deepseek-p0b \
  --steps 1 \
  --seed 1 \
  --red-secret /root/.config/ordivon/secrets/deepseek.json \
  --blue-secret /root/.config/ordivon/secrets/deepseek1.json
```

P0-B uses the same Provider, Harness loop, prompt, actions, credentials, model bounds, and CAGE workload. Host compiles and stores the durable Context, then derives the model input only from the selected blocks' objective, observation, prior results, and rules; persistence envelopes and identity digests remain bound in Host and Harness evidence rather than being repeated in the prompt. Host owns the durable Task lifecycle, and Runtime remains unconsumed. The controlled Trial completed both Host Tasks at revision 5, submitted six explicit CAGE actions, used zero default Red/Blue actions, and retained no Runtime Job references. The Host state root must be absolute, empty, private, and disjoint from the Contest evidence root.

To run P0-C, add `--variant p0c`, an absolute fresh `--runtime-request-root`, and the loopback Runtime endpoint/token-file options. P0-C preserves the same semantic workload but executes each Host Assignment as one Runtime Job/Attempt. The accepted Trial verified exact request replay, unique client-request recovery lookup, stdout and terminal-evidence Artifacts, four Host/Harness foreign references, and terminal process-tree cleanup. Runtime does not decide Host completion or Security action admission. See [`evidence/acceptance/deepseek-cage-p0bc-c170e6d-seed1.json`](evidence/acceptance/deepseek-cage-p0bc-c170e6d-seed1.json).

## Run the pinned CAGE 4 Range

```bash
scripts/bootstrap_cage4.sh

uv run --extra cage ordivon-security-cage4 \
  --source .cache/cage4 \
  --output .artifacts/cage-native-native \
  --steps 3 \
  --seed 1 \
  --red native \
  --blue native
```

The bootstrap command checks out exactly:

```text
cage-challenge/cage-challenge-4
8c3c50ca54b176c2de199847944e8dcc035497e3
```

The adapter rejects revision drift, a dirty CAGE source tree, and imports from an unexpected checkout. Local source paths are operator configuration and do not alter Trial identity.

Every run writes a sealed evidence bundle:

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

The deterministic bundle and non-deterministic operational bundle verify independently. CAGE metrics additionally bind the source revision, explicit external action count, Red/Blue agent counts, native actions executed, mission phases, rewards, and Red footholds.

## Active architecture

```text
RangeSessionSpec
  → RangeSession
  → RangeSessionBackend lifecycle + asynchronous world events
  → management / contested / sensor / world-truth RangeEvent stream
  → model/Harness intent may choose non-action or submit one typed effect request
  → exact RangeAuthority admission remains Security-owned
  → backend receipt remains distinct from independently observed world consequence
  → inspect() returns retained JSON snapshots rather than live mutable references
  → admitted S6 effects persist exact request/admission/effect identity with physical phase
  → owner-loss recovery distinguishes semantic effect identity from physical cleanup
  → independent Host truth prevents blind replay when consequence already materialized
  → checkpoint / terminate / destroy

ScenarioManifest
  → ContestRunner
  → ActorBackend[]
  → ActionProposal[]
  → Range admission
  → simultaneous resolution
  → Actor result + sensor telemetry + hidden truth
  → raw metrics + sealed evidence

EvaluationSpec
  → authority and environment admission
  → SampleVault verification
  → EvaluationRangeBackend
  → Observer records + Guardian decisions + facts
  → residual closure
  → Findings + sealed evidence
```

Security owns adversarial-domain semantics: contested-Range bindings, principal information boundaries, domain effect admission, truth/uncertainty classification, recovery meaning, raw metrics, scoring, and adversarial evaluation. Campaign, coalition, organization, trust, and infection structures remain research hypotheses until experiments prove the minimum Security-owned state.

Security does not rebuild model Providers, general Agent Harnesses, process runtimes, hypervisors, container engines, C2 frameworks, scanners, SIEMs, or generic workflow systems. Host, Harness, Runtime, World, external ranges, and mature security tools retain those responsibilities.

## Native and delegated actors

The planned actor surfaces remain distinct:

- **Native Harness Actor** — Ordivon Harness owns the Agent loop and calls a model API such as DeepSeek.
- **Delegated Harness Actor** — Codex App Server, Hermes ACP, or another complete Harness owns its internal loop and is attached through a driver.
- **Scripted/RL Actor** — deterministic baselines and learned policies use the same Contest boundary.

DeepSeek is a model Provider. Codex and Hermes are complete external Harnesses; they are not equivalent Provider adapters.

## Historical Round 1

The former single-Actor experiment/evaluation framework is frozen at Git revision `92c0f9497741c3cde542c347318d2372fb884e30`. Its reports, fixture, and retained evidence remain under [`docs/archive/round1/`](docs/archive/round1/) and [`evidence/`](evidence/). They remain valid historical evidence but no longer define active APIs.

## Read next

- [`CHARTER.md`](CHARTER.md) — project purpose and ownership;
- [`docs/LAW-PROFILES-C0.md`](docs/LAW-PROFILES-C0.md) — constitutional laws, grants, experiment profiles, fixtures, and evaluator-judgment boundaries;
- [`docs/architecture.md`](docs/architecture.md) — active contracts and integrations;
- [`docs/MIGRATION-ROUND-1.md`](docs/MIGRATION-ROUND-1.md) — Contest Core replacement;
- [`docs/MIGRATION-ROUND-2.md`](docs/MIGRATION-ROUND-2.md) — first-class CAGE 4 Range;
- [`docs/MIGRATION-ROUND-3-P0.md`](docs/MIGRATION-ROUND-3-P0.md) — fail-closed model prerequisites, execution identity, and evidence separation;
- [`docs/EVALUATION-TRIAL-P0.md`](docs/EVALUATION-TRIAL-P0.md) — local Sample, authority, environment, Observer/Guardian, residual closure, and evidence contracts;
- [`docs/STATIC-EVALUATION-P0.md`](docs/STATIC-EVALUATION-P0.md) — streaming Vault, static analyzers, native report Artifacts, quarantine hardening, and limitations;
- [`docs/CASE-SNAPSHOT-P0.md`](docs/CASE-SNAPSHOT-P0.md) — read-only drift audit, evolving Case identity, uncontrolled-execution status, and snapshot verification;
- [`docs/WINDOWS-KVM-P0.md`](docs/WINDOWS-KVM-P0.md) — sealed Windows image, no-network QMP authority, benign fixture acceptance, and residual closure;
- [`docs/WINDOWS-KVM-RECOVERY-P0.1.md`](docs/WINDOWS-KVM-RECOVERY-P0.1.md) — root-owned Evaluation Run ledgers and explicit Evaluation orphan reconciliation after hard failures;
- [`docs/PERSISTENT-RANGE-RECOVERY-S6R.md`](docs/PERSISTENT-RANGE-RECOVERY-S6R.md) — read/effect separation, durable S5/S6 Range resources, and accepted owner-loss reconciliation for the S6 physical topology;
- [`docs/WINDOWS-KVM-INSTALLER-P1.md`](docs/WINDOWS-KVM-INSTALLER-P1.md) — separate large-Sample installer profile and read-only NTFS input-media gate;
- [`docs/AGENT-EXPERIMENT-P0.md`](docs/AGENT-EXPERIMENT-P0.md) — controlled Provider/Harness/Host/Runtime variants and the DeepSeek Harness baseline;
- [`docs/research-agenda.md`](docs/research-agenda.md) — research sequence and falsifiers;
- [`docs/research-boundary.md`](docs/research-boundary.md) — authorization and external-effect limits;
- [`evidence/README.md`](evidence/README.md) — active and historical evidence contracts.
