---
schema_version: 1
id: security.persistent-range-recovery-s6r
title: Persistent Range Progression and Recovery S6-R
type: architecture
profile: engineering
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
updated: 2026-08-07
summary: Post-S6 strengthening that makes inspection read-only, binds changing Range resources into durable authority, and physically proves owner-loss reconciliation for the accepted S6 topology shape.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.topology-churn-s6
  - security.windows-kvm-substrate-s2
  - security.windows-kvm-recovery-p0.1
  - security.architecture
---
# Persistent Range Progression and Recovery S6-R

## Why this stage exists

S6 proved that one Windows Guest can remain alive while management replaces lightweight peer A with peer B. A post-acceptance source audit then found that the physical result was stronger than one implementation detail: `WindowsTopologyChurnRange.inspect()` still called the replacement controller. Reading current state could therefore trigger deletion and creation of network resources.

The same audit also found that S5/S6 wrote machine ledgers through `WindowsKvmMachineProvider`, but the existing `ordivon-security-windows-kvm-reconcile` consumer was Evaluation-specific. It required `evaluation-run:*` and `evaluation-instance:*` identity and could not reconcile a Range ledger after owner loss.

S6-R therefore asks three narrower questions:

1. **P0 — progression:** can the physical world advance without `inspect()` causing the effect?
2. **P1 — durable authority:** after A is replaced by B, does root-owned state describe the resources that actually exist now?
3. **P2 — recovery:** after the exact Security owner is killed while B, QEMU, swtpm, and the packet sensor are still live, can a new management process reconcile the declared world to zero residuals?

No generic world scheduler, topology graph, mutation API, or recovery framework is introduced.

## P0 — observation is not an effect

S6 now runs a backend-local management controller. The controller watches the maintained peer process and performs the A-to-B replacement independently of `RangeSession.inspect()`.

```text
peer A completes
      ↓
backend-local controller
      ↓
management replacement intent
      ↓
physical namespace change
      ↓
Host topology observation
      ↓
durable/current truth

inspect()
      ↓
read current state only
```

`inspect()` may still reconcile already-observable machine-exit bookkeeping inherited from the machine lifecycle, but it no longer initiates the consequential topology change.

The initial S6 topology truth is also emitted once rather than once by S5 and again by S6. Peer namespace names use a deterministic 32-bit SHA-256 prefix rather than the last four characters of the session identity.

A peer-A nonzero exit is retained as `fabric.peer-a-failed` and does not become a successful topology replacement.

## P1 — command completion is not world truth

The first post-audit implementation exposed two additional timing assumptions.

### Fast completion is not missing identity

Peer B is a one-shot maintained service. A live Guest can connect, receive the banner, and let B exit 0 before management samples its process start time. The corrected rule is:

```text
B still alive  → bind PID + process start time
B exited 0     → no live B process remains to recover
B exited != 0  → failure
```

Namespace and topology ownership remain durable even when the one-shot service has already completed.

### `ip netns del` is intent, not immediate truth

A later physical run showed that `ip netns del` can return while the old fabric veth is still briefly visible through Host bridge state. S6-R therefore waits for **external topology convergence**, bounded to ten seconds, and only then emits `peer-a-removed` truth.

```text
management: delete A namespace
        ↓
Host bridge observation still contains A port
        ↓
keep observing
        ↓
Host bridge observation contains only Windows TAP
        ↓
world-truth: peer-a-removed
```

There is no fixed sleep that upgrades command success into truth.

## Durable resource authority

The S5/S6 Range ledger now binds the current recoverable resource set in addition to machine identity:

- Range Session and Range identities;
- exact fabric and current peer namespaces;
- deterministic set of namespaces this Range is allowed to remove;
- peer process PID/start time when a live peer exists;
- tcpdump PID/start time;
- current `topologyPhase` and current peer address;
- exact maintained canary path and digest;
- existing QEMU/swtpm/process and run-directory facts from `WindowsKvmMachineProvider`.

S6 persists this authority after the externally observed A removal and again after B materialization. A later owner therefore does not have to reconstruct the current peer from process names or broad namespace scans.

## P2 — Range recovery is a separate policy consumer

The existing Evaluation reconciler is intentionally not generalized. Evaluation owns `EvaluationSpec`, `evaluation-run:*`, fixture state, and its own extra ledger fields. S6-R adds `ordivon-security-windows-kvm-range-reconcile` for the exact S5/S6 fabric shapes.

The Range reconciler:

- ignores Evaluation ledgers;
- accepts only the exact S5/S6 Range IDs and deterministic namespace identities;
- skips an exact live owner;
- closes peer, tcpdump, QEMU, and swtpm only when PID/start-time/command identity agrees;
- deletes only the deterministic namespace candidates owned by that Range;
- removes the exact run directory, ledger, and maintained canary;
- emits `attention-required` rather than guessing when identity is unsafe or incomplete.

This split is deliberate:

```text
WindowsKvmMachineProvider
    machine/process/ledger primitives
           │
           ├── Evaluation reconciler
           │      Evaluation identity + policy
           │
           └── S5/S6 Range reconciler
                  Range/fabric identity + policy
```

Same mechanical substrate does not imply one universal reconciliation policy.

## Physical owner-loss challenge

The accepted owner-loss challenge is bound to Security revision `1eb638c962ac023d19514f645930cbefa4de08e9`.

To isolate recovery from Windows cold-start variance, the recovery-specific test driver starts the real S6 QEMU/fabric and completes peer A's maintained one-shot service from inside peer A's own namespace. This drives the normal backend controller to `peer-b-present` without claiming another Guest-connectivity acceptance; Guest-driven A-to-B behavior is verified separately by the final normal S6 regression.

At the kill gate the root ledger already said:

```text
machine phase        = executing
topologyPhase        = peer-b-present
currentPeerAddress   = 10.253.70.4
QEMU                 = live
swtpm                = live
peer B               = live
tcpdump               = live
```

The exact owner process was then killed with SIGKILL. Before the new reconciler started, an independent process check confirmed that all four managed child processes were still live. The new management process then produced:

```text
status               = passed
reconciled           = 1
attentionRequired    = 0
qemuClosed           = true
swtpmClosed          = true
peerClosed           = true
captureClosed        = true
residualNamespaces   = []
runDirectoryRemoved  = true
ledgerRemoved        = true
canaryRemoved        = true
```

A post-reconcile `/proc`, namespace, run-directory, ledger, and canary audit found zero declared residuals.

The sanitized evidence index is [`../evidence/acceptance/windows-kvm-s6-progression-recovery-1eb638c.json`](../evidence/acceptance/windows-kvm-s6-progression-recovery-1eb638c.json).

## Final normal-path regression

The same final revision was then run through the ordinary Guest-driven S6 acceptance. It was accepted with:

```text
peer-a-present
→ peer-a-removed
→ peer-b-present
```

The intermediate Host truth contained only the Windows TAP. The Guest claim reported successful A and B banner interactions, the external packet sensor observed both flows, current truth ended at B, controller error was absent, and normal closure remained clean.

This matters because owner-loss recovery was not accepted by replacing the original workload with a synthetic recovery-only world.

## Falsifiers that changed the implementation

1. **Read caused effect.** Post-S6 source audit showed `inspect()` initiated physical replacement. Progression moved to a backend-local controller.
2. **Fast B completion looked like missing recovery identity.** A one-shot B could exit 0 before process-start-time sampling. Exit 0 now means no live process remains to recover.
3. **Namespace deletion looked synchronous.** `ip netns del` returned while the old fabric port was still externally visible. World truth now waits for bounded Host-observed convergence.
4. **Cold start polluted the recovery experiment.** One recovery attempt never reached A before the maintained peer's socket timeout. The final P2 challenge drives A locally so owner-loss recovery is the only variable.
5. **Evaluation policy leaked into Range recovery.** The first real owner-loss run reached durable B with live QEMU/swtpm/peer/tcpdump, but the new reconciler rejected the ledger because its validator required Evaluation-only `runDiskPath`. Range validation now requires Provider-core fields plus Range-owned resources only.

## What S6-R proves

For the accepted S6 physical topology:

- observing current Range state is no longer the trigger for topology replacement;
- backend-owned asynchronous progression survives the existing thin `RangeSession` contract;
- physical command completion and externally observed world convergence are distinct facts;
- the current recoverable Range resource set can be retained outside the owner process;
- a new management process can reconcile an owner-killed S6 Range while QEMU, swtpm, peer B, and tcpdump are still live;
- process closure and namespace/file closure can be verified independently;
- the ordinary Guest-driven S6 path remains accepted after the strengthening.

## What S6-R does not prove

S6-R does not prove:

- crash atomicity at every instruction inside the A-to-B transition; the owner-loss gate occurs only after `peer-b-present` is durably committed;
- hard-failure recovery for arbitrary future Range shapes; the reconciler admits only exact S5/S6 identities;
- physical S5 owner-loss recovery, although S5 identity is supported by deterministic tests;
- Actor-requested effects, `RangeAuthority` admission, or a persistent-world action gateway;
- multiple full-OS failure domains, external egress, or uncontrolled targets;
- that packet capture is world truth.

## Next pressure

C1 and C1-A subsequently introduced the consequential Actor-requested effect while preserving:

```text
Actor intent
  ≠ Security admission
  ≠ backend execution
  ≠ effect receipt
  ≠ external world verification
```

C1-B then killed the effect owner during the physical transition. That experiment showed the exact boundary S6-R left open: durable physical resource identity can close an orphaned world to zero, but it cannot by itself explain which admitted effect produced an intermediate topology. S6 now additionally persists the existing immutable Actor effect binding and non-truth receipt. See [`INTERRUPTED-CONSEQUENCE-C1B.md`](INTERRUPTED-CONSEQUENCE-C1B.md).

The next unresolved pressure is partial materialization inside a physical effect substep, not a generic `RangeAction` gateway.
