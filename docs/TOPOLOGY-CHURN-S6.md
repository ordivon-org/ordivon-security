---
schema_version: 1
id: security.topology-churn-s6
title: Live Topology Churn S6
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
summary: Accepted live topology-change Range where one Windows Guest remains in the same QEMU lifecycle while management removes lightweight peer A and introduces peer B, preserving current truth, historical truth, sensor evidence, Guest claims, and residual closure.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.isolated-fabric-s5
  - security.range-session-s0
  - security.architecture
---
# Live Topology Churn S6

## Graduation question

> Can world topology change while the same real Guest remains alive, without losing authoritative current state, historical state transitions, external sensor separation, or residual closure?

S6 answers **yes for one maintained topology replacement inside the accepted isolated fabric**. The Windows Guest remains in one QEMU lifecycle while lightweight peer A disappears and peer B appears.

## Why S6 exists

S5 proved one static physical contested fabric. Its backend representation still assumed one peer namespace, one peer veth, and one long-lived `fabricTruth` snapshot. That was sufficient while the world stayed static but did not show whether a persistent `RangeSession` could survive a changing physical world.

A pure Linux namespace probe first established that the substrate itself was not the problem:

```text
bridge: []
  ↓ add peer A
bridge: [A]
  ↓ delete peer A namespace
bridge: []
  ↓ add peer B
bridge: [B]
```

The fabric kept zero L3 addresses and no external route, the replacement peer had no default route, and cleanup remained complete. S6 therefore tested Ordivon's representation and authority boundaries rather than inventing new networking machinery.

## Physical challenge

The accepted S6 sequence is:

```text
same Windows KVM Guest / same QEMU lifecycle
10.253.70.2/24
       │
       ├─ TCP → peer A 10.253.70.3:48080
       │          banner ORDIVON-S6-PEER-A
       │
       │  management removes peer A namespace
       │  Host observes only the Windows TAP
       │
       │  management creates peer B
       │
       └─ TCP → peer B 10.253.70.4:48080
                  banner ORDIVON-S6-PEER-B
```

The Guest canary retries peer B while the management-owned topology changes. QEMU is not restarted between the two interactions.

## No new RangeSession mutation API

S6 deliberately does **not** add `RangeSession.mutate_world()`, `RangeSession.action()`, a topology graph, or a generic node API.

The topology replacement is an exogenous/backend-owned world change. The existing `RangeSessionBackend` contract already permits a backend to evolve asynchronously and emit events. That proved sufficient for this consumer:

```text
backend-owned physical change
        ↓
management event describing controller intent/completion
        ↓
independent world-truth snapshots
        ↓
RangeSession polls and preserves ordered events
```

A generic action/effect path should be introduced only when a contested Actor must deliberately request such a consequential change. S6 does not create that consumer prematurely.

## Current truth and historical truth

The central representation result is that **event history and current state are complementary, not substitutes**.

The accepted world-truth history is exactly:

```text
peer-a-present
  currentPeerAddress = 10.253.70.3

peer-a-removed
  currentPeerAddress = null
  bridge ports = [Windows TAP]

peer-b-present
  currentPeerAddress = 10.253.70.4
  bridge ports = [Windows TAP, peer-B veth]
```

`topologyHistory` preserves all three observations. At the same time, `fabricTruth` is updated to the final `peer-b-present` snapshot. S6 rejects a model in which the history is accurate but the advertised current world state remains stale.

## Authority separation

S6 retains the S5 planes:

```text
management
  peer replacement start/completion, QMP lifecycle, closure

world-truth
  Host Linux netlink/bridge snapshots before, between, and after the replacement

sensor
  Host tcpdump observation of both TCP exchanges

contested
  Guest Runner diagnostics and Guest canary claim that both peers were reached
```

The topology controller describes what management attempted. Its management event does not establish that the physical bridge changed. Only the subsequent Host netlink/bridge observation owns that fact.

Likewise, the pcap is an external sensor, not lossless world truth.

## Accepted physical facts

The final acceptance is bound to implementation revision `03a93e36b53455477a3cd2b47006c53621317caf`.

It establishes:

- QMP still observes one Windows network device throughout the maintained challenge;
- the Guest uses the exact QEMU MAC `52-54-00-53-35-01` and a connected `10.253.70.0/24` route;
- Guest → peer A completes a real TCP handshake and receives the maintained A banner;
- management removes peer A while QEMU is still running;
- Host world truth observes the intermediate bridge with only the Windows TAP;
- management creates peer B at a different namespace/veth identity and IP;
- Host world truth observes peer B attached and makes that snapshot the current `fabricTruth`;
- Guest → peer B completes a real TCP handshake and receives the maintained B banner;
- Host tcpdump independently observes both complete TCP exchanges;
- QEMU, swtpm, the machine Run, ledger, fabric namespace, and surviving peer-B namespace all close with zero residuals.

The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-s6-topology-churn-03a93e3.json`](../evidence/acceptance/windows-kvm-s6-topology-churn-03a93e3.json).

## Real failures and corrections

### Fast success looked like startup failure

The first physical S6 run failed at the replacement-peer startup check. The check treated any peer-B process that had already exited after 250 ms as a startup failure.

That assumption is valid only when no consumer can exist yet. In S6 the Windows Guest is already alive and actively retrying peer B. A short-lived maintained service can therefore be connected, send its banner, and exit successfully before the controller inspects its process state.

The corrected rule is semantic rather than temporal:

```text
replacement peer still running  → ready / waiting
replacement peer exited 0       → may already have completed service
replacement peer exited nonzero → startup/service failure
```

The acceptance still requires the independent Guest result and external pcap to prove the actual B interaction.

### Accurate history with stale current truth

A subsequent physical run completed both TCP flows and preserved topology-change events, but the inherited `fabricTruth` field still represented the initial peer-A topology. The history was true while the current snapshot was stale.

S6 therefore made current topology an explicit acceptance gate. `fabricTruth` must move through the observed phases and finish at `peer-b-present`, while `topologyHistory` retains the ordered past states.

This is not a new graph model. It is the minimum correction required once the world can change.

## What S6 proves

For this maintained challenge:

- a persistent physical Range can change topology without restarting its full Windows Guest;
- backend-owned asynchronous world evolution fits the existing `RangeSession` contract;
- one lightweight materialization can be destroyed and replaced while another higher-fidelity materialization persists;
- world-truth events can reconstruct the transition independently of Guest claims;
- current truth and historical truth can remain mutually consistent;
- packet sensing can span both pre- and post-change interactions;
- resource closure survives topology churn.

## What S6 does not prove

S6 does not provide:

- Actor/Agent-requested topology changes or a general action/effect gateway;
- multiple simultaneously active peer services beyond the maintained replacement sequence;
- a generic `RangeNode`, topology graph, materialization registry, or promotion framework;
- multiple full operating-system failure domains;
- routing, DHCP, DNS, NAT, zones, Internet simulation, or external targets;
- arbitrary offensive actions, lateral movement, credentials, or cross-host persistence;
- lossless packet truth or causal attribution from pcap alone.

## Next pressure

S6 should stop here. Exogenous topology churn did **not** justify expanding the generic `RangeSession` API.

The next useful question should come from a different consumer. One strong candidate is the first consequential world change requested by a contested Actor: can an Actor propose an effect, can Security admit it, can the backend execute it, and can external world truth verify or reject the claimed result while preserving `proposal ≠ effect`? That should be audited against current code before any generic action gateway is designed.
