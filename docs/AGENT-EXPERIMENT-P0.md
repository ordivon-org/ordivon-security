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
evidence_status: partially_verified
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

P0-A is accepted as the first real team-plan baseline. The P0-B implementation and a deterministic real-Host lifecycle smoke are complete; a sealed DeepSeek/CAGE acceptance Trial remains pending. P0-C remains open. The accepted P0-A Trial is intentionally narrow: one seed, one CAGE tick, two distinct DeepSeek Flash credential scopes, and the two-plan action surface.

Accepted Trial:

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

Three sealed predecessor Trials remain useful negative evidence:

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

## P0-B active implementation

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
- for P0-B, Host Task revision plus TaskContract, Context object, Assignment, Run receipt, CompletionProposal, and CompletionDecision digests.

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

## P0-B gate

P0-A satisfied the workload-isolation gate. The implementation now preserves the
same CAGE scenario, prompt, action catalog, credentials, model bounds, seed, and
Harness loop while adding:

- durable Host Task Contract;
- compiled Context identity;
- Harness Assignment generation;
- supersession and replay-blocking semantics;
- explicit Host verification route.

A real DeepSeek/CAGE Trial must still prove that both actors complete this lifecycle,
that Host state and evidence remain private and secret-free, and that Runtime stays
unconsumed. Only then is P0-B accepted. The primary comparison is whether Host
continuity improves validity, replaceability, diagnosis, or held-out behavior enough
to justify its cost.

## P0-C gate

P0-C may start only after P0-B. It must preserve the same semantic workload while
executing the Harness process through Runtime and binding:

- Workspace source state;
- Job and Attempt identity;
- provider-process cancellation;
- Artifact export;
- reconnect and UNKNOWN reconciliation;
- residual process closure.

Runtime must not become Security action authority or Host completion authority.

## Deletion and falsification

Delete or absorb the added layers when controlled comparisons show that they add
no meaningful validity, recovery, replacement, diagnosis, or held-out performance
for the workload. The goal is not to prove that every Ordivon layer is always
necessary; it is to know exactly when each layer earns its cost.
