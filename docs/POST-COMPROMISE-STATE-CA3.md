---
schema_version: 1
id: security.post-compromise-state-ca3
title: Post-Compromise State CA3
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-14
summary: Bounded local post-compromise experiment separating persistent artifacts, usable control, synthetic credential authority, verified footholds, controller-directed movement, delegated continuation, eradication and stale beliefs.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.classical-capability-basis-ca0
  - security.vulnerability-evidence-ca2
  - security.research-boundary
---
# Post-Compromise State CA3

## Question

CA3 asks what remains after one-shot execution and which facts are actually distinct resources for an adaptive actor:

```text
persistent bytes/service
!= usable control
!= credential authority
!= second foothold
!= delegated continuation
```

The experiment intentionally starts below VM/network fidelity. Three exact owned local entities `a/b/c` use synthetic generation-bound credentials, process-isolated worker invocations, management-owned world truth and bounded filesystem state. No network, real account, malware or external target is required to test these distinctions.

## Canonical run

Apparatus revision: `27de2f9`.

Runtime Job: `job-019ffeef-3c30-77a1-be91-2508ce2f59a4`.

Retained stdout digest: `sha256:64ccc3692577a2bac1d277cce4843d0b9be8f4fe2a8e9ee586fe9822abad0bbd`.

All ten semantic gates pass.

## Persistence is not control

Node A first establishes current control and one benign startup/persistence artifact. Runtime state is then cleared and a restart activates the persisted service. Management rotates/revokes A's synthetic credential before the old controller reconnects.

Final pre-eradication truth is intentionally mixed:

```text
persistencePresent = true
serviceLive = true
credentialRevoked = true
currentControl = false
reconnect.usableControl = false
```

Therefore persistent state can be real while the controller has no usable authority path back to it. CA3 retains `CONTINUITY` and `CONTROL` as distinct coordinates.

## Credential possession is not authority

The same synthetic B credential first establishes target control. Management then revokes it and advances the target's authority generation. An otherwise identical stale movement attempt is rejected and produces no current control.

The capability is therefore not “token bytes exist.” It is an applicable authority relation between exact credential identity and current target authority state.

## Movement is a target consequence

A movement request is not a foothold. CA3 counts movement only after target-side world truth records `currentControl=true`. This keeps credential observation, provider receipt and second-foothold consequence separate.

## Controller-directed versus delegated continuation

CA3 compares two bounded paths to B and C under restored synthetic authority.

Controller-directed:

```text
controller selects B control
controller selects C control
C.currentControlSource = controller-propagation
```

Delegated:

```text
controller selects B control
controller activates one maxChildren=1 delegation on B
B locally invokes the exact C control action
C.currentControlSource = delegated-from:b
```

Both reach the same bounded world consequence, but the location of next-target selection/execution differs. This justifies retaining `control mode` as an orthogonal coordinate without introducing a `WORM` semantic effect or reusable propagation engine.

It does not prove delegated continuation is strategically better. That question belongs to CA6 under adversarial counterplay.

## Eradication and stale belief

Management then removes persistence, live service, current control and delegation state and revokes/advances all three authority generations. Stale controller actions using all previously valid credentials fail on A/B/C.

This establishes a simple but important rule:

> fresh world/authority truth dominates stale offensive resource belief.

A persistent Security-owned credential/foothold database is therefore not required merely to remember old state. Re-observable provider/world truth remains authoritative.

## CA3 results

- `CONTINUITY != CONTROL`: persisted/activated state can exist without usable control.
- `credential possession != AUTHORITY`: current target acceptance/generation matters.
- `movement request != foothold`: verified target control is the consequence boundary.
- `controller-directed != delegated continuation`: identical target outcome can differ in where continuation is selected/executed.
- revocation/eradication changes current capability applicability; stale beliefs must fail rather than silently recreate control.
- CA0's role-neutral relation hypothesis survives this pressure: Blue-style revocation/eradication reverses the same AUTHORITY/CONTROL/CONTINUITY relations Red-style actions acquire.

## Provider-first result

CA3 needed ordinary process/filesystem mechanics and experiment-local synthetic authority, not a credential-stealing tool, worm framework or lateral-movement product. Higher fidelity is not justified until a later hypothesis depends on real protocol, OS credential or endpoint semantics.

## Next pressure

CA4 should now add the missing Blue plane and test the evidence/action chain:

```text
raw observation
-> derived detection/classification
-> adjudication
-> response receipt
-> fresh post-response truth
```

It should retain known-clean, malicious/synthetic, delayed/conflicting and sensor-failure controls and avoid an omniscient `DETECT` primitive.

## Post-closeout executable standing — 2026-08-28

CA3's accepted/falsified research result and source-fenced evidence remain canonical. The one-shot `cli_ca3_post_compromise_state.py` experiment runner is retained under `fixtures/archive/runners/` rather than the current package because it has no installed command, current source/research consumer, exact documentation invocation, or current surface claim; its remaining unit test exercised runner-local experiment apparatus. The accepted evidence is indexed by the `27de2f9` receipt. Restoring the runner is an explicit reproduction/new-experiment action, not a current Security capability requirement.
