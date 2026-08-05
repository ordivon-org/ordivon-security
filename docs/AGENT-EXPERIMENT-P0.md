---
schema_version: 1
id: security.agent-experiment-p0
title: Agent Experiment P0
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
updated: 2026-08-05
summary: Controlled model-Actor variants that separate Provider, Harness, Host, Runtime, and Security influences in adversarial Contests.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security-agent-experiments
related:
  - security.start
  - security.architecture
  - security.research-agenda
  - security.evidence
  - security.authority
---
# Agent Experiment P0

## Purpose

A model alone is not an Agent. The behavior observed in a Contest may be caused by
several independently replaceable layers:

```text
Provider model and API behavior
+ Harness loop, Tool protocol, retries, budgets, and stopping
+ Host Task, Context, Assignment, replacement, and verification
+ Runtime process, Job, Attempt, Artifact, cancellation, and recovery
+ Security observation, prompt, action catalog, admission, and Range semantics
```

Testing all layers as one opaque Agent would make failures and improvements
unattributable. P0 therefore introduces the layers incrementally while keeping the
Security workload fixed.

## Experimental variants

| Variant | Provider | Harness | Host | Runtime | Purpose |
|---|---:|---:|---:|---:|---|
| P0-A | consumed | consumed | explicitly not consumed | explicitly not consumed | establish the smallest real model Actor |
| P0-B | consumed | consumed | consumed | explicitly not consumed | measure durable Task, Context, Assignment, and replacement effects |
| P0-C | consumed | consumed | consumed | consumed | measure Runtime process durability, cancellation, and recovery effects |

A layer marked “not consumed” is not omitted from identity. Its exact source
revision, non-consumption mode, and reason remain in the Actor backend identity.
This makes the baseline falsifiable and prevents later code from silently adding a
layer while claiming the same experiment.

## Status

P0-A is accepted as the first real team-plan baseline. P0-B is accepted as the first Host-assigned baseline, and P0-C is accepted as the first Runtime-executed baseline. The final P0-B/P0-C comparison uses the same Security and Harness revisions, seed, CAGE workload, Provider configuration, budgets, and two-plan action surface; Runtime physical execution is the isolated variable. Both variants completed one tick with identical CAGE action counts. P0-C proves that Runtime can own the physical Job/Attempt/process/Artifact lifecycle without taking Security action authority or Host completion authority. It does not yet prove multi-tick continuity, injected cancellation recovery, or strategic value.

Accepted P0-A Trial:

```text
trial:2a1066d2d3953a791bfc646b
```

Identity and evidence:

```text
trial identity:
sha256:ed029472846e9d783244c121808386da2344025bc71486a54bbc3fb1bce1a0c7

semantic evidence:
sha256:5e98f1f3872ac5380cff48d5634edff5ba770ab97c91d009e4b58bf43648599d

operational evidence:
sha256:f7458b82be8f4a0161ec9647089a470e8832ccbcb8d901ecd8ccb56952369603
```

The repository retains a sanitized acceptance index at
[`../evidence/acceptance/deepseek-cage-p0a-seed1-run4.json`](../evidence/acceptance/deepseek-cage-p0a-seed1-run4.json).
The complete private Trial remains outside Git.

Accepted controlled P0-B Trial:

```text
trial:d065fc6b01a3bd9afc93a8ef
```

```text
trial identity:
sha256:b7092a2a0a7787ab8695b3e8d0f1fd30b33658225f359a329770df2f64676884

semantic evidence:
sha256:a5f4a8caf812ec68e9effc47d5d62511c34fe274b9baabcfe9666f6f99d6e29f

operational evidence:
sha256:75783e314b0ea218b5c1df4cc43a997e4ed4b4b305c53b9c4a57943ba2cb8a84
```

Accepted P0-C Trial:

```text
trial:ee3ef0fa1bf4d82aef21fceb
```

```text
trial identity:
sha256:918e6d58b4d4a62102f3e03567fd51ecf531a0947dcf7a46f9f32735f8cead88

semantic evidence:
sha256:5c12be4e7d156053bd75e740548df21b1c5b97aa755ed9c2b7cf719a6893162c

operational evidence:
sha256:748d832c81e1eba692e008026b106387276e66ebd41e6c0f6157a6637ada4078
```

The repository retains the strict comparison and sanitized Runtime lifecycle evidence at
[`../evidence/acceptance/deepseek-cage-p0bc-c170e6d-seed1.json`](../evidence/acceptance/deepseek-cage-p0bc-c170e6d-seed1.json).
The complete private Contest bundles, Host state, and Runtime Artifacts remain outside Git.

The earlier accepted P0-B Trial `trial:bf48063dd944964a28353c62` remains valid historical evidence for the original Host lifecycle claim. It is superseded only as the strict P0-B control because its older Harness revision did not event-admit the external TaskContract CAS object, preventing complete extension-history validation.

Two sealed P0-B predecessor Trials remain useful diagnostic evidence:

- `run0` proved fail-closed behavior when the full compiled Context envelope exceeded the conservative second-call token preflight;
- `run1` proved Blue could complete the corrected Host-selected semantic projection while Red stopped in `provider_state_unknown` after an ambiguous transport close, leaving its original Host Task waiting rather than replaying the Provider call.

Three P0-C predecessor Trials remain diagnostic rather than accepted:

- `run0` failed closed at the Runtime adapter boundary before model action admission;
- `run1` exposed Security's incorrect assumption that Runtime Job identities use the `job:` protocol form rather than Runtime's authoritative `job-` and `attempt-` forms;
- `run2` completed Runtime execution and one CAGE tick, but strict closeout exposed the inherited external-Assignment TaskContract event-reference gap, so it was replaced by the controlled run using Harness revision `c170e6d`.

For P0-A, three sealed predecessor Trials remain useful negative evidence:

- `run0` exposed an insufficient Tool budget and oversized raw observation;
- `run1` exposed conclusion-state and conservative token-bound failures;
- `run3` isolated an oversized per-call output bound after Context Projection.

A fourth attempt, `run2`, failed after model completion but before Trial sealing due
to a rationale post-processing limit. Its Runtime Job remains the authority for
that software exception; it is not represented as a sealed Contest Trial.

## P0-A active implementation

`NativeHarnessActorBackend` implements the Security `ActorBackend` contract. Each
Contest tick creates one bounded `DomainToolLoopRunner` run through
`DeepSeekTurnAdapter`.

Security owns:

- actor identity, side, objective, and actor-specific observation;
- the two admitted CAGE team plans;
- the prompt revision;
- Tool admission and selected plan;
- conversion to `ActionProposal`;
- Range admission and world truth;
- Contest and evidence lifecycle.

Harness owns:

- Provider request and response adaptation;
- mandatory Tool-call protocol;
- model, Tool, token, byte, retry, correction, no-progress, and wall-time budgets;
- cancellation and Provider failure classification;
- the complete Harness Trace;
- candidate-completion semantics.

Host is not consumed in P0-A because Security already owns the short-lived Contest
Actor session and no durable Goal or Task is created. Runtime is not consumed
because selecting a CAGE team plan creates a Security proposal but no physical
process or workspace effect.

## P0-B accepted implementation

`HostAssignedDeepSeekHarnessTurnDriver` wraps the P0-A model/Harness turn without
changing its Provider, action catalog, budgets, or Runtime boundary. For every
actor tick it creates a durable Host lifecycle:

```text
Security raw observation
→ deterministic Security projection
→ Host Task + TaskContract
→ Host ContextBlock selection
→ HarnessContextCompiler
→ content-addressed Context object
→ committed external Harness Assignment
→ DeepSeek/Harness model turn
→ HarnessRunReceipt
→ CompletionProposal
→ Security acceptance verifier
→ CompletionDecision
→ Security ActionProposal
```

The complete compiled Context remains content-addressed in Host storage and is bound
by the Assignment and Harness Run `contextDigest`. The model receives a deterministic
`host-selected-semantics-v1` projection containing only the selected blocks'
objective, observation, prior action results, and rules. Task/Attempt identities,
TaskContract payloads, Context manifests, and digests are not repeated in the
Provider prompt because they already remain authoritative in Host and Harness
evidence. This preserves the P0-A total-token bound while allowing Host to own
Context selection rather than merely annotating a Security-built prompt.

The Assignment is deliberately external rather than native: it carries no
`ToolGrant`, Runtime Job, Workspace, or native Run contract. Security generates a
stable Harness Run identity from the committed Assignment generation and binds it
to the Trace, Run receipt, proposal, decision, and Contest evidence. Runtime
therefore remains `consumed=false` in P0-B.

Host owns Task state and revision, TaskContract identity, selected Context,
Assignment generation, Run receipt, CompletionProposal, verification, and final
CompletionDecision. The model can only submit a candidate conclusion. Security
accepts completion only when the proposed action remains in the two-plan grant,
the source observation and Harness Trace digests match, and Runtime consumption
remains false.

Host/Protocol canonical JSON forbids floating-point values, while CAGE observations
contain rewards and related floats. The Security→Host boundary therefore replaces
each finite float with a deterministic object:

```json
{"kind":"ordivon.canonical-float","decimal":"0.5"}
```

The original actor observation digest remains bound in the Task, ContextBlock, and
completion verification. Non-finite floats fail closed. The model instruction
explicitly defines the canonical-float representation.

Each P0-B Trial uses a fresh, absolute, empty private Host state root. The root is
`0700`; the Host database and content-addressed objects are `0600`. The state root
is excluded from semantic identity, while a non-secret `host-state:` namespace is
included. Reusing an existing Task blocks Provider replay rather than silently
starting a second model call.

## P0-C accepted implementation

`RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver` preserves the P0-B semantic
workload and Host lifecycle but moves each physical Harness model turn into one
Runtime-owned Job and Attempt:

```text
Host Assignment
→ Security writes one private digest-bound worker request
→ Runtime opens the pinned Security Workspace
→ Runtime starts one trusted-local Job/Attempt
→ Harness performs the same bounded DeepSeek/tool/conclusion loop
→ Runtime seals stdout, execution result, and terminal evidence Artifacts
→ Security reads and verifies the worker result
→ Host records the Harness Run receipt and decides semantic completion
→ Security admits the resulting CAGE ActionProposal
```

The Runtime Job carries four typed foreign references: Host Task, Task Attempt,
Assignment, and Harness Run. `clientRequestId` is derived from Actor, Assignment
generation, and request digest. Repeating the exact `workspace.exec` request returns
the same Job and Attempt; `task.list` by client request uniquely recovers it after a
lost caller response. The accepted Trial also verifies the stdout and terminal-
evidence Artifact digests and a `terminal_clean` process-tree disposition.

Runtime owns Workspace, Job, Attempt, process exit, Artifact bytes, cancellation,
and physical recovery facts. It does not decide whether the Harness candidate is
semantically complete, whether the selected team plan is admissible, or whether
the CAGE world advances. Host and Security retain those authorities respectively.
The worker request spool is private and empty after successful terminal observation;
the per-turn Runtime Workspace is closed after evidence collection.

P0-C uses `trusted_local` because the worker executes pinned Ordivon code. This is
not hostile-code containment and does not authorize unknown Sample execution or
arbitrary model-generated shell commands.

## Action surface

P0-A exposes exactly one model Tool:

```text
select_team_plan(plan)
```

`plan` is restricted to:

```text
cage.team.native-policy
cage.team.sleep
```

The model cannot call shell, Runtime, filesystem, network, CAGE parameterized
actions, or arbitrary Security methods. The Range expands an admitted team plan
into concrete native CAGE actions only after both Red and Blue proposals are
collected.

This narrow surface is deliberate. It tests model interpretation, asymmetric
observation, action abstention, Provider/Harness failure, and adversarial policy
selection without conflating those questions with Tool execution reliability.

## Credential identity

The six local DeepSeek Flash files remain private `0600` secret files. Each file
has a unique non-secret `credentialScopeId`:

```text
credential-scope:deepseek:flash:0
...
credential-scope:deepseek:flash:5
```

API keys, key digests, and secret paths are not written into Trial identity or
evidence. A credential scope identifies the operational account boundary needed
to attribute throttling, availability, and retry behavior without exposing
credential material.

P0 does not rotate or pool credentials invisibly. Red and Blue bind distinct
credential scopes, and changing either scope changes Actor configuration and
Trial identity.

## Bound identity

Each model Actor binds:

### Provider

- DeepSeek provider;
- official base URL;
- requested Flash model;
- adapter revision;
- credential scope;
- timeout, response-byte, output-token, and thinking configuration;
- an accepted default output bound of 1,024 tokens for the two-plan workload.

### Harness

- exact Harness source revision;
- declared package version;
- observed runtime metadata version;
- exact Protocol source revision;
- domain-loop revision;
- fresh-per-tick session mode;
- explicit prior-result memory mode;
- all Run budgets and retry/correction bounds.

The default Run-wide token ceiling is deliberately loose at `1,000,000`. It is a runaway guard, not a spending target. Model-call count, wall time, Tool-call count, model-observation bytes, and the per-response output ceiling remain the operative controls. Individual experiments may still bind a lower value, and that exact value remains part of Actor and Trial identity.

### Host and Runtime

- exact source revision;
- consumed boolean;
- experiment mode;
- structured reason and configuration.

### Security

- exact Security implementation identity;
- Actor backend revision;
- prompt revision;
- action catalog;
- Tool and bridge identity;
- actor-specific observation boundary.

Any change produces a different Actor configuration digest and therefore a
different Contest Trial identity.

## Turn evidence

Every successful proposal binds:

- Agent stack identity digest;
- Harness Run and Assignment identities;
- complete Harness Trace digest;
- credential scope;
- requested and effective model identities;
- Harness stop code;
- usage and budget facts;
- selected action and rationale;
- for P0-B and P0-C, Host Task revision plus TaskContract, Context object, Assignment, Run receipt, CompletionProposal, and CompletionDecision digests;
- for P0-C, Runtime Job, Attempt, client-request, Workspace, source revision, stdout Artifact, terminal-evidence Artifact, Tool catalog, worker-response digest, exact replay, and recovery-lookup facts.

The complete bounded Harness Trace is retained in the Actor stop receipt and
therefore enters Contest management evidence. API keys are excluded.

## Failure semantics

The Contest fails closed when:

- Provider invocation fails or times out;
- Harness stops before candidate completion;
- no plan Tool call occurs;
- more than one plan is selected;
- the selected plan is outside the Actor grant;
- effective model identity differs from the requested model;
- Actor binding, objective, backend, or configuration drifts.

If one Actor fails, peer proposals are not executed and the Range world does not
advance for that tick.

## P0-A command

```bash
uv run --extra cage ordivon-security-cage4-deepseek \
  --source .cache/cage4 \
  --output .artifacts/cage4-deepseek-p0a \
  --steps 1 \
  --seed 1 \
  --red-secret /root/.config/ordivon/secrets/deepseek.json \
  --blue-secret /root/.config/ordivon/secrets/deepseek1.json
```

The command requires clean local Harness, Host, Runtime, and Computing source
trees. Machine-local source paths do not become semantic identity; exact revisions
do.

## P0-B command

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

The Host state root and Contest evidence root must be disjoint. The command rejects
relative, non-empty, or non-private Host state roots and keeps the machine-local
path out of semantic identity.

## Historical P0-B acceptance

The earlier P0-B Trial preserved the P0-A CAGE scenario, prompt, action catalog,
credentials, model-call and output bounds, seed, and Harness loop while adding:

- durable Host Task Contracts;
- compiled Context identity and selected semantic model input;
- committed external Harness Assignment generations;
- Harness Run receipts;
- CompletionProposals, independent verification, and CompletionDecisions;
- replay blocking for pre-existing Tasks.

Both Red and Blue Host Tasks reached `completed` at revision 5. Both completion
decisions were accepted. One CAGE tick executed with six explicit external actions,
zero default Red/Blue actions, and zero Runtime Job references. Semantic and
operational Contest evidence verified independently; Host state passed full
validation; Contest and Host files retained private `0700`/`0600` modes; and exact
credential values, secret paths, Bearer metadata, and `apiKey` fields were absent.

That historical Trial retained the `16,384` total-token ceiling to keep its
P0-A/P0-B comparison controlled. Later code raises the default ceiling to
`1,000,000`, treating it as a runaway guard rather than a cost target. This does not
rewrite the accepted Trial identity.

P0-B remains a Host-lifecycle baseline, not a proof that Host improves strategy.
Multi-tick continuity, replacement, resume, supersession, and held-out comparisons
remain open.

## P0-C command

```bash
uv run --extra cage ordivon-security-cage4-deepseek \
  --variant p0c \
  --source .cache/cage4 \
  --output /var/lib/ordivon/security/contests/cage4-deepseek-p0c \
  --host-state-root /var/lib/ordivon/security/host/cage4-deepseek-p0c \
  --host-state-namespace host-state:security:cage4-deepseek-p0c \
  --runtime-request-root /var/lib/ordivon/security/runtime-requests/cage4-deepseek-p0c \
  --runtime-endpoint http://127.0.0.1:8897/mcp \
  --runtime-token-file /etc/ordivon/ordivon-runtime.env \
  --steps 1 \
  --seed 1 \
  --red-secret /root/.config/ordivon/secrets/deepseek.json \
  --blue-secret /root/.config/ordivon/secrets/deepseek1.json
```

The Contest, Host, and Runtime request roots must be absolute, fresh, private, and
disjoint. The Runtime endpoint is restricted to loopback HTTP. Credential values
and the Runtime Bearer token never enter Trial identity or retained evidence.

## P0-B/P0-C acceptance

The final comparison uses Harness revision
`c170e6d76483dd1b0c15806837b77e08512f9b9d`, which fixes event-level admission of
the TaskContract object for external Assignments. Both variants pass full Host
storage validation and Harness-owned historical semantic validation.

Both Trials completed one tick with the same six external actions:
`DiscoverRemoteSystems`, `Monitor`, `Remove`, `Restore`, and two `Sleep` actions.
Neither used a default Red/Blue action or recorded an Actor failure. Both Red and
Blue Host Tasks completed at revision 5.

P0-B records no Runtime Job references. P0-C records exactly one succeeded Runtime
Job per Actor. Each Job is uniquely recoverable by its client request, preserves the
same Job/Attempt under exact request replay, binds four foreign references, exports
verified stdout and terminal evidence, exits with code zero, and reports a clean
terminal process tree. No accepted worker request file, per-turn Runtime Workspace,
or worker process remained after completion.

This accepts Runtime as an attributable physical execution layer for the current
model Actor. It does not show that Runtime improves CAGE strategy, and it does not
yet test in-flight cancellation, transport-loss recovery, multi-tick continuity,
parameterized actions, or arbitrary shell execution.

The next isolated experiment is P1-A: expose typed parameterized CAGE actions while
preserving the accepted P0-C execution and authority boundaries. Arbitrary shell is
not part of that experiment.

## Deletion and falsification

Delete or absorb the added layers when controlled comparisons show that they add
no meaningful validity, recovery, replacement, diagnosis, or held-out performance
for the workload. The goal is not to prove that every Ordivon layer is always
necessary; it is to know exactly when each layer earns its cost.
