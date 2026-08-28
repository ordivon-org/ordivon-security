---
schema_version: 1
id: security.partial-materialization-c1c
title: Partial Materialization C1-C
type: experiment
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
summary: Physical proof that stable topology phase and durable effect identity are insufficient to justify a recovery clean claim when an admitted effect has created transient Host resources before publishing stable state; exact transient resource ownership plus independent Host type and residual observation restores truthful closure without introducing a generic transaction framework.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security-range
related:
  - security.interrupted-consequence-c1b
  - security.persistent-range-recovery-s6r
  - security.law-profiles-c0
  - security.authority
  - security.evidence
---
# Partial Materialization C1-C

## Question

C1-B established that an interrupted consequential effect can remain semantically identifiable after its controller dies. It also showed that stable physical phases plus independent Host truth can distinguish an intermediate effect from a completed effect whose response was lost.

The remaining ambiguity sits *inside* one physical materialization step:

> What if the effect has already created owned physical objects that are not yet represented by the last stable topology phase?

C1-C tests that question on the existing actor-authorized S6 peer replacement. It deliberately does not add a durable transaction log, substep state machine, generic compensation engine, persistent `RangeSession`, or causal DAG first.

## Exact physical fault point

Peer-B creation currently proceeds through concrete Linux operations before S6 publishes `peer-b-present`:

```text
create B network namespace
→ create q<session> ↔ w<session> veth pair in Host root namespace
→ move q into B namespace
→ move w into fabric namespace
→ attach w to fabric bridge
→ configure interfaces/address
→ start peer-B service
→ publish peer-B resource identity
→ publish peer-b-present
```

The C1-C baseline kills the owner immediately after the veth pair exists in the Host root namespace, before either end is moved and before peer-B identity is published into live Range state.

At that point the durable ledger still truthfully reports the last stable topology:

```text
topologyPhase       = peer-a-removed
currentPeerAddress  = null
```

but the physical world contains additional transient resources.

## Baseline falsifier: a false clean claim

The baseline is bound to Security revision:

```text
git:2458ad7225d3e4727f06534c2ebc7f12409bca88
```

The admitted Actor effect identity survived owner loss. Independent Host observation found:

```text
fabric namespace        = present
peer-B namespace        = present
Windows TAP             = present
q<session> root veth    = present
w<session> root veth    = present
QEMU / swtpm / tcpdump  = live
owner                    = dead
```

The existing S5/S6 reconciler then terminated the declared processes, removed the declared namespaces, removed the Run directory and ledger, and returned:

```text
status            = passed
reconciled        = 1
attentionRequired = 0
```

However, independent Host root-netlink observation after reconciliation still found both veth ends.

Therefore the reconciler's clean claim was false.

This is not merely a resource-leak defect. It is an authority/truth defect:

> **A recovery component may not claim a world is clean when its declared ownership model omits resources that the same accepted effect can create before stable-state publication.**

The experiment runner then removed the two exact residual links only as explicit experiment cleanup. That cleanup is not counted as reconciler success.

## Why the stable phase was insufficient

C1-B had established a useful relation:

```text
durable effect identity
+
durable physical phase
+
independent Host truth
→ classify interrupted consequence
```

C1-C reveals a new distinction:

```text
effect semantic identity
≠ stable topology phase
≠ transient materialization resource ownership
≠ world truth
```

`peer-a-removed` was a correct stable phase. The error was assuming that this phase exhaustively described all objects the in-flight effect could already own.

A stable phase can therefore remain true while being insufficient for recovery closure.

## Minimal mechanism: exact transient resource ownership

The baseline did not justify persisting every physical substep. The missing fact was smaller: S6 already deterministically derives the Host link names used for peer-B materialization from the Range Session identity.

At revision:

```text
git:39693ebf1fc51a2814a8d15ddc136530ecf46533
```

S6 durable identity now includes:

```text
ownedHostLinkCandidates = [q<session>, w<session>]
```

The reconciler does not trust those names merely because they appear in a ledger. It independently derives the same candidate names from the admitted S6 session identity and fails closed if the durable declaration differs.

For each candidate still present in the Host root namespace, reconciliation additionally requires Host netlink to identify the object as a `veth` before deletion. A same-name object of another kind is not deleted and must produce unresolved recovery rather than a clean claim.

After deletion, Host state is observed again. A clean result now requires:

```text
managed processes absent
∧ owned namespaces absent
∧ exact owned Host links absent
```

The reconciliation receipt explicitly retains:

```text
requestedHostLinks
residualHostLinks
```

This extends recovery ownership without turning names into universal deletion authority.

## Physical acceptance after the fix

The exact same `after-peer-b-root-veth-created-before-placement` fault point was repeated on revision `39693eb`.

Before recovery, Host observation again established:

```text
peer-B namespace exists
q/w veth pair exists in Host root namespace
stable topology remains peer-a-removed
owner is dead
QEMU / swtpm / tcpdump remain live
exact Actor effect identity is durable
```

The new reconciler then reported the exact Host links it owned and removed:

```text
requestedHostLinks = [q<session>, w<session>]
residualHostLinks  = []
residualNamespaces = []
status             = passed
```

Independent Host observation after reconciliation found no candidate root links and no owned namespaces.

The experiment cleanup step was still executed as a falsifier, but it had no work to do:

```text
requested = []
clean     = true
```

This is the critical acceptance boundary: recovery itself, not the test harness, closed the partial materialization.

## Normal-path regression

The same revision was then run through the ordinary Guest-driven, backend-owned S6 acceptance.

The accepted normal path retained:

```text
peer-a-present
→ peer-a-removed
→ peer-b-present
```

The Guest reached both peers, Host topology truth retained all three phases, the external packet sensor observed both challenge flows, the final world contained peer B, exactly one Windows network device remained visible through the accepted management observation, and destruction was clean.

Therefore adding transient Host-resource ownership to recovery does not replace or break normal S6 topology progression.

## What C1-C proves

For this exact S6 effect and fault point, C1-C proves:

- an effect may own physical resources that are not represented by the last stable topology phase;
- durable effect identity alone does not enumerate those transient resources;
- a reconciler can return a mechanically successful receipt while making a false clean claim if its ownership model is incomplete;
- recovery `clean` is a truth/authority claim, not merely a collection of successful delete commands;
- deterministic transient resource identities can be declared durably without persisting a generic substep transaction log;
- declared names are not sufficient deletion authority: the reconciler independently derives expected names from the session identity and verifies present objects are `veth` links before deleting them;
- post-delete Host re-observation is required before `residualHostLinks=[]` can support a clean claim;
- the same partial fault closes without experiment cleanup after the minimal fix;
- the ordinary S6 world remains accepted on the same implementation.

The resulting recovery condition for this consumer is:

```text
exact semantic effect identity
+
exact resource ownership identity
+
independent Host observation
+
post-action residual verification
→ truthful closure
```

## What C1-C does not prove

C1-C does not prove:

- safe continuation from the partial peer-B state while keeping the Windows world alive;
- idempotent completion of the missing peer-B materialization suffix;
- repair or compensation policy;
- crash safety at every instruction boundary inside peer-B construction;
- exactly-once behavior for arbitrary effects;
- concurrent or cross-Agent partial effects over shared resources;
- a need for generic durable substep identity;
- a need for generic `RangeEvent.causalParents` validation;
- external or uncontrolled target authority.

C1-C deliberately accepts safe closure to zero as the recovery policy being tested. It does not confuse truthful cleanup with autonomous continuation.

## Causality result

Partial materialization was expected to be a stronger candidate for forcing a generic causal DAG. It still did not.

The physical falsifier was explained and corrected using three narrower identities:

```text
which admitted effect?
→ durable effect binding

which transient physical objects can that exact S6 session own?
→ deterministic resource candidates

which of those objects actually exist, and of what kind?
→ independent Host observation
```

The missing abstraction was **resource-ownership completeness**, not event-parent topology.

This does not demote causality law. It sharpens when stronger causal structure should be introduced: only when multiple effects, shared objects, compensation dependencies, or ambiguous continuation cannot be resolved by exact semantic identity plus exact resource identity plus world observation.

## Resulting pressure

C1-D has now physically continued this exact partial world without first closing the Range. The same Windows Guest consumed peer A, survived the original controller SIGKILL, and then consumed peer B after a fresh process completed the missing materialization suffix from durable effect/resource identity plus current Host placement. No durable substep state, old Range object, or old event stream was needed. See [`FRESH-CONTROLLER-CONTINUATION-C1D.md`](FRESH-CONTROLLER-CONTINUATION-C1D.md).

The new pressure is ownership rather than progress representation. During continuation, durable owner identity still names the dead predecessor, so current reconciliation law would still consider the world orphaned. The next experiment should race successor continuation against reconciliation and require an exact durable claim/lease/epoch only if that race proves it necessary.

## Post-closeout executable standing — 2026-08-28

C1-C's partial-materialization result, exact transient-resource ownership correction, independent Host observation requirement, reconciler behavior, S6 normal-path regression and source-fenced acceptance evidence remain current. A later deletion tournament showed that the extracted `windows_kvm_partial_world_fixture.py` and related acceptance-support helpers had no current executable consumer after C1-D itself became historical apparatus; tests of those helpers did not constitute a new production/reusable responsibility. Their source is therefore retained under `fixtures/archive/support/`, alongside the historical runner family, rather than in the current package. Current regression stays on the real `WindowsTopologyChurnRange` effect-binding/recovery contracts. The accepted fixed trial remains exactly recoverable from revision `39693ebf1fc51a2814a8d15ddc136530ecf46533`; the earlier false-clean baseline remains recoverable from `2458ad7225d3e4727f06534c2ebc7f12409bca88`.
