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
updated: 2026-08-05
summary: Canonical entry to the Contest laboratory, pinned CAGE 4 Range, controlled DeepSeek/Harness Actors, streaming SampleVault, static Evaluation, evolving Case snapshots, and a benign-only disposable Windows KVM candidate.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.architecture
  - security.evaluation-trial-p0
  - security.static-evaluation-p0
  - security.case-snapshot-p0
  - security.windows-kvm-p0
  - security.agent-experiment-p0
  - security.research-agenda
  - security.research-boundary
  - security.evidence
  - security.authority
---
# Ordivon Security

Ordivon Security is an **authorized adversarial-Agent laboratory** for studying autonomous Red, Blue, neutral, observer, and evaluator actors in contested digital worlds.

Its central executable object is a **Contest**: multiple goal-bearing actors receive different observations, propose actions concurrently, act through an authoritative Range, and leave independently verifiable evidence. Cyber is the first domain. Campaigns, organizations, deception, adaptation, and coevolution are later research layers—not substitutes for a working Contest.

## Current capability

The active `0.8` core provides:

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
- a QEMU/KVM disposable Windows Provider candidate restricted to the maintained benign fixture;
- a DeepSeek Flash `NativeHarnessActorBackend` with exact Provider, Harness, Host, Runtime, Protocol, prompt, budget, and credential-scope identity;
- a P0-A CAGE path where Harness is consumed while Host and Runtime non-consumption remain explicit experimental facts;
- management-plane QMP network-device checks and disposable qcow2, UEFI, TPM, and FAT Run state;
- evidence-bound Findings and mandatory residual-closure receipts.

In the CAGE adapter, one Security Red Actor controls the CAGE Red team and one Security Blue Actor controls five CAGE Blue agents. Every Red and Blue CAGE action is explicitly supplied by Ordivon to the joint step; Green agents remain CAGE-controlled environmental actors. The current action surface is intentionally narrow: each side selects either the pinned native team policy or Sleep. Parameter-level model control is a later integration.

It does **not yet** provide Host-assigned or Runtime-executed model Actor variants, an admitted unknown-Sample Windows execution path, Ghidra, YARA, capa, Volatility, containerlab, CALDERA, Zeek, Campaign execution, or production cyber operations. The Windows KVM Provider is a benign-fixture-only candidate until its clean-revision base build and real acceptance Run pass. Static analyzers may read Sample bytes as data. A historical local Wine run remains outside the admitted Evaluation path.

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

## Build and accept the Windows KVM candidate

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

The first command builds a sealed Windows 11 Enterprise Evaluation base with no QEMU network device. The second compiles and executes only the Ordivon-maintained benign fixture in a disposable overlay. Neither command authorizes DaVinci or another unknown Sample. See [`docs/WINDOWS-KVM-P0.md`](docs/WINDOWS-KVM-P0.md).

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

P0-A consumes DeepSeek and Ordivon Harness. Host and Runtime are deliberately not consumed and their exact revisions plus non-consumption reasons remain in Trial identity. The model may select only `cage.team.native-policy` or `cage.team.sleep`; it receives no shell or Runtime Tool. See [`docs/AGENT-EXPERIMENT-P0.md`](docs/AGENT-EXPERIMENT-P0.md).

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

Security owns the adversarial domain semantics: Scenario, Contest, Campaign and organization hypotheses, actor information boundaries, domain action admission, Range truth, scoring, and adversarial evaluation.

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
- [`docs/architecture.md`](docs/architecture.md) — active contracts and integrations;
- [`docs/MIGRATION-ROUND-1.md`](docs/MIGRATION-ROUND-1.md) — Contest Core replacement;
- [`docs/MIGRATION-ROUND-2.md`](docs/MIGRATION-ROUND-2.md) — first-class CAGE 4 Range;
- [`docs/MIGRATION-ROUND-3-P0.md`](docs/MIGRATION-ROUND-3-P0.md) — fail-closed model prerequisites, execution identity, and evidence separation;
- [`docs/EVALUATION-TRIAL-P0.md`](docs/EVALUATION-TRIAL-P0.md) — local Sample, authority, environment, Observer/Guardian, residual closure, and evidence contracts;
- [`docs/STATIC-EVALUATION-P0.md`](docs/STATIC-EVALUATION-P0.md) — streaming Vault, static analyzers, native report Artifacts, quarantine hardening, and limitations;
- [`docs/CASE-SNAPSHOT-P0.md`](docs/CASE-SNAPSHOT-P0.md) — read-only drift audit, evolving Case identity, uncontrolled-execution status, and snapshot verification;
- [`docs/WINDOWS-KVM-P0.md`](docs/WINDOWS-KVM-P0.md) — sealed Windows image, no-network QMP authority, benign fixture acceptance, and residual closure;
- [`docs/AGENT-EXPERIMENT-P0.md`](docs/AGENT-EXPERIMENT-P0.md) — controlled Provider/Harness/Host/Runtime variants and the DeepSeek Harness baseline;
- [`docs/research-agenda.md`](docs/research-agenda.md) — research sequence and falsifiers;
- [`docs/research-boundary.md`](docs/research-boundary.md) — authorization and external-effect limits;
- [`evidence/README.md`](evidence/README.md) — active and historical evidence contracts.
