---
schema_version: 1
id: security.law-profiles-c0
title: Security law and profile classes C0
type: decision
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - evaluator
  - agent
updated: 2026-08-08
summary: Canonical interpretation of constitutional Security laws, authority and resource grants, experiment profiles, fixtures, and evaluator judgments so local safety gates are not mistaken for universal Agent restrictions.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security
related:
  - security.charter
  - security.authority
  - security.architecture
  - security.research-boundary
  - security.agent-experiment-p0
  - security.windows-kvm-installer-p1
---
# Security law and profile classes C0

## Decision

Ordivon Security does not treat every current admission check, timeout, action menu, no-network mode, or evaluation disposition as the same kind of rule.

The repository uses four rule classes:

1. **constitutional law** — preserves authority, epistemic separation, causal accountability, identity, and recoverability across experiments;
2. **authority or resource grant** — states what one Actor, principal, experiment, or backend may control or spend inside a declared scope;
3. **experiment profile or fixture** — intentionally narrows the world or action surface to isolate a research variable and may be replaced when the experiment changes;
4. **evaluator judgment** — interprets evidence for one evaluation purpose but does not become world truth or universal action law.

A current implementation may be narrower than the constitutional model. Unsupported or unadmitted behavior must not be re-described as universally forbidden unless a constitutional authority boundary actually forbids it.

## Constitutional law

The following current properties are constitutional because stronger Agents still require them:

- **sovereignty and authority** — reachability is not authority; an effect must remain inside an owned or explicitly delegated scope;
- **truth separation** — Actor claims, management intent, sensors, evaluator output, execution receipts, and independent world truth are different authorities;
- **causal accountability** — intent, admission, execution, receipt, observed effect, and verified consequence must remain distinguishable;
- **exact identity and provenance** — actions, worlds, models, tools, resources, and evidence must be attributable to the identities that produced them;
- **recovery without guessing** — ambiguous execution or owner loss is reconciled from durable identity and observed state rather than repaired by blind replay or broad deletion;
- **authority ownership** — Host semantic continuity, Runtime physical execution, Security domain admission, and world/truth producers do not silently inherit one another's authority.

These laws exist to make autonomous action intelligible and recoverable. They do not tell an Agent which strategy is prudent.

C0 identified two constitutional mechanisms that were incomplete. C1 has now made one of them physically executable without generalizing it prematurely:

- `RangeAuthority` zone/capability grants are consumed by `RangeSession.admit_effect()` and physically accepted for one exact S6 peer-replacement effect; this proves the law path, not a universal action framework;
- `RangeEvent.causalParents` still records causal claims without validating parent existence, same-Session ownership, parent-before-child ordering, or acyclicity. C1-B reconstructed interrupted single-effect states from durable effect identity, physical phase, and Host truth; C1-C then interrupted peer-B *inside* materialization and still did not require a generic causal DAG. The C1-C falsifier instead exposed incomplete transient resource ownership: a stable `peer-a-removed` phase coexisted with already-created B namespace/veth resources, allowing the old reconciler to make a false clean claim.

See [`EXECUTABLE-AUTHORITY-C1.md`](EXECUTABLE-AUTHORITY-C1.md), [`AUTONOMOUS-INTENT-C1A.md`](AUTONOMOUS-INTENT-C1A.md), [`INTERRUPTED-CONSEQUENCE-C1B.md`](INTERRUPTED-CONSEQUENCE-C1B.md), and [`PARTIAL-MATERIALIZATION-C1C.md`](PARTIAL-MATERIALIZATION-C1C.md). Later experiments should strengthen causal structure only when concurrent/shared effects, continuation dependencies, compensation, or another real consumer cannot be resolved from exact semantic identity, exact resource ownership, and independent world observation.

## Authority and resource grants

A grant is not a moral judgment and is not necessarily permanent. It answers questions such as:

- which zones and resources this Actor may affect;
- which capabilities are delegated;
- which environment or Sample identity an Evaluation covers;
- how much model, Tool, token, memory, process, wall-time, or Artifact budget is available;
- which external world, if any, belongs to the declared authority scope.

Budgets are therefore resource law, not generic distrust of Agent judgment. A rational Agent may choose an aggressive or conservative strategy inside the same grant.

The current `AuthorityManifest.operatorId` name and `operator:` prefix are legacy schema vocabulary. They identify the grant issuer in current Evaluation evidence; they do not establish a constitutional requirement that a human synchronously approve actions.

## Experiment profiles and fixtures

Profiles may deliberately make legal states impossible because the experiment needs a controlled comparison. Their restrictions apply only to the named profile and evidence claim.

Current examples:

| Current mechanism | Class | Scope |
|---|---|---|
| Contest one proposal per Actor/tick and simultaneous resolution | profile | deterministic synchronous comparison |
| peer failure or rejected proposal invalidates the Contest tick | profile | preserves synchronous Trial attribution |
| CAGE `select_team_plan`, `native-policy`/`sleep`, `mustNotInventActions` | fixture/profile | isolates Provider/Harness/Host/Runtime variables in P0 |
| exact benign Windows Sample admission | profile | proves machine lifecycle, evidence, and closure before broader execution |
| P0/P1 no-network modes | profile | proves a specific containment/observation claim; not a universal doctrine that every authorized Range must have no network |
| P1 `executionAuthorized: false` and controller not admitted | stage profile | preparation/materialization evidence only |
| `RangeAuthority.externalBoundary == denied` | current S0 profile encoding | current persistent Range has no delegated external scope; this single enum value is not the final constitutional authority model |
| fixed time/token/process limits | grant/profile value | declared resource ownership for a run |

A profile may narrow a constitutional grant for an experiment. It may not silently widen sovereignty, turn a sensor into truth, erase uncertain effects, or claim another subsystem's authority.

Every new restrictive profile should state:

- the research variable it isolates;
- the scope in which the restriction applies;
- the evidence claim it makes possible;
- the condition under which the restriction can be removed, widened, or replaced.

## Evaluator judgment

`Finding`, severity, confidence, `EvaluationDisposition`, reward, score, and similar outputs are interpretations over evidence.

For example, `credential-access`, `process-injection`, or destructive behavior may be high-risk findings in a software-assessment profile while being an explicitly authorized objective for a Red Actor inside another Range. The evaluator owns its judgment, not the underlying world fact and not the Actor's authority.

An evaluator or Guardian may itself be fallible, manipulable, or an experimental attack surface. Security must preserve the evidence needed to study that failure rather than promote evaluator output to truth.

## Guardian interpretation

Guardian is not a universal strategy judge.

The useful Agent-first role is narrower: enforce environment, authority, and resource invariants that define whether the declared experiment still exists. Examples include an unexpected network device in a no-network profile or exhaustion of a declared runtime budget.

Current `GuardianPolicy.terminateOn` is declarative metadata rather than a generic executable policy language: present backends emit their own typed `GuardianRecord` decisions and do not consume arbitrary `terminateOn` strings. Future code must either make a condition typed and enforceable or stop presenting it as stronger policy than it is.

## Reading current non-admission correctly

Use these interpretations:

```text
not implemented       != constitutionally forbidden
not admitted in P0    != globally prohibited
high-risk finding     != action authority revoked
command returned zero != verified consequence
sensor observed X     != world truth X
recovery uncertain    != safe to replay blindly
```

When a stronger experiment needs a currently closed capability, the first question is not “how do we bypass the safety rule?” It is:

> Which rule class closed it, what evidence was that rule protecting, and can the new experiment preserve the constitutional invariants with a wider profile or grant?

## C0 classification of active code

| Mechanism | Decision |
|---|---|
| management / contested / sensor / world-truth separation | **keep as constitutional law** |
| exact identity, evidence digests, durable resource identity | **keep as constitutional infrastructure** |
| Host / Runtime / Security authority separation | **keep as constitutional law** |
| exact owner-loss reconciliation and `attention-required` on unresolved authority | **keep as autonomy-enabling recovery infrastructure** |
| one recovery mutator per exact world generation | **constitutional recovery-authority law; C1-E proves predecessor provenance must remain distinct from current recovery ownership** |
| C1-E per-Run `flock` + claim metadata | **current single-host mechanism, not universal law; claim binds exact generation/provenance while kernel gate enforces exclusion** |
| zone/capability `RangeAuthority` | **constitutional law; executable for one accepted C1 physical effect, not yet generic** |
| `RangeEvent.causalParents` | **keep intent; C1-B through C1-E resolved interruption, partial materialization, continuation, and one ownership race without a generic DAG, so strengthen only when multiple successors, shared effects, compensation, or distributed causation creates genuine ambiguity** |
| Harness resource budgets | **keep as configurable resource grants** |
| synchronous Contest tick/action rules | **retain as explicit profile, never generalize to RangeSession** |
| CAGE two-plan model action surface | **retain only as P0 fixture** |
| P0 benign-only and P1 preparation-only Windows gates | **retain as named Evaluation profiles** |
| current `externalBoundary=denied` singleton | **retain for current S0 profile; do not treat as universal external-effect prohibition** |
| `operator:` identity vocabulary | **compatibility residue; later migrate toward principal/grant issuer semantics if a consumer requires it** |
| free-form Guardian `terminateOn` | **do not expand as a generic safety language; either type real invariants or shrink the field later** |
| Finding severity / disposition | **retain as evaluator judgment only** |
| generic human approval or global context-free risk threshold | **do not add** |

## C0 stop condition

C0 is complete when the canonical entry, architecture, research boundary, Agent P0, and Windows P1 documentation all point back to this classification and no current profile is described as a universal Security law.

C0 deliberately does not change action admission. C1 owns the first executable `RangeAuthority` experiment.
