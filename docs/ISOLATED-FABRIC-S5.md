---
schema_version: 1
id: security.isolated-fabric-s5
title: Isolated Fabric Authority S5
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
summary: First accepted contested network in the physical Security Range: one disposable Windows KVM Guest and one lightweight peer share an externally owned isolated L2 fabric while management, topology truth, packet observation, Guest claims, and residual closure remain separate authorities.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - ordivon-security
related:
  - security.out-of-band-truth-s4
  - security.windows-kvm-substrate-s2
  - security.range-session-s0
  - security.architecture
---
# Isolated Fabric Authority S5

## Graduation question

> Can a real disposable Guest participate in contested networking without collapsing the management boundary into the contested world?

S5 answers **yes for one maintained Windows KVM Guest and one lightweight synthetic peer on one isolated L2 fabric**. It does not claim a general multi-node cyber range.

## Why the S5 hypothesis changed before implementation

The first post-S4 plan assumed that the next useful experiment would require several full Windows VMs. Physical probes showed that this was the wrong unit of thought.

A bridge created directly in the WSL root network namespace inherited existing Docker/WSL forwarding policy and could not carry the intended peer traffic even though both bridge ports were forwarding. Moving the bridge into its own Linux network namespace removed that coupling. Two lightweight namespaces then communicated over a private bridge, had no external route, were observable from the management side, and closed without residual namespaces.

A second probe ran QEMU inside that isolated network namespace while keeping its Unix QMP socket controllable from the root management namespace. This established that mature Linux/QEMU primitives already provide the mechanical substrate. Security only needed to bind identity, authority, evidence, and closure around them.

S5 therefore did not build a topology engine, virtual switch, network controller, or fleet of Windows VMs.

## Materialization

The accepted Range uses heterogeneous fidelity:

```text
management namespace
  ├─ QMP / process / ledger authority
  ├─ Linux netlink topology inspection
  └─ external tcpdump sensor
          │
          │ authority boundary
          ▼
isolated fabric namespace
  └─ bridge with no IPv4/IPv6 L3 address and no route
       ├─ TAP ─ Windows 11 KVM Guest
       │          10.253.60.2/24
       │
       └─ veth ─ lightweight Linux peer namespace
                  10.253.60.3/24 : 48080
                  maintained banner service
```

The fabric has no uplink. The lightweight peer has only its connected `10.253.60.0/24` route and no default route. The bridge has exactly the declared TAP and peer-veth ports.

This establishes a practice-derived rule: **Range nodes are world entities; full VMs are only one materialization.** An experiment should pay the fidelity cost required by the variable it studies. S5 intentionally does not turn that rule into a generic fidelity framework.

## Provider boundary

`WindowsKvmMachineProvider` remains the machine substrate. S5 adds only the ability to bind QEMU launch to one exact pre-existing Linux network namespace:

```text
ip netns exec <exact-fabric-namespace>
  → existing setpriv privilege drop
    → existing QEMU execution identity
```

The Provider still owns QEMU/swtpm process identity, machine ledger, QMP inspection, termination, recovery-compatible state, and residual machine closure. It does not authorize Range topology or network policy.

Invocation identity and binary identity are deliberately separate. S5 discovered that `/usr/bin/mcopy` is a multicall symlink to `mtools`: resolving the symlink and executing the target changed behavior because `argv[0]` selects the mtools operation. S5 therefore preserves the invocation path while binding the resolved executable path and digest in evidence.

## Authority separation

S5 is the first physical Range with all four of these sources active at once:

```text
management
  QMP network-device count, QEMU lifecycle, ledger, closure

world-truth
  Host Linux netlink/bridge observation of the declared fabric topology,
  absence of fabric L3 addresses, absence of external routes, active TAP carrier

sensor
  Host-side tcpdump packet observation

contested
  Guest Runner diagnostics and Guest canary connectivity claim
```

The new `sensor` Range event plane exists because S5 now has a real producer. A pcap is an independent external observation, but it is not promoted to world truth: packet capture can start late, drop packets, or observe only a bounded filter.

## Accepted physical facts

The final physical acceptance is bound to implementation revision `c1cef7a79ad0f501083940c8742db02a7ddb0bb1` and the sanitized evidence index at [`../evidence/acceptance/windows-kvm-s5-isolated-fabric-c1cef7a.json`](../evidence/acceptance/windows-kvm-s5-isolated-fabric-c1cef7a.json).

The accepted run independently established:

- QMP observed exactly one network-class device in the Windows Guest;
- the Guest-side maintained canary bound configuration to QEMU MAC `52-54-00-53-35-01` and confirmed the connected `10.253.60.0/24` route before connecting;
- the fabric bridge had zero L3 addresses;
- the bridge contained exactly the declared active TAP and peer-veth ports;
- the fabric namespace had no route and the lightweight peer had no default route;
- the Windows Guest completed a real TCP handshake with `10.253.60.3:48080` and received the maintained 16-byte peer banner;
- the Host packet sensor independently observed the SYN, SYN/ACK, ACK, banner payload, and connection close;
- QEMU and swtpm exited, the run ledger and directory were removed, both network namespaces were deleted, and no Range residual object remained.

The Guest claim and packet capture agree on this maintained challenge, but neither owns the Host topology or residual-closure facts.

## Real failures and corrections

S5 retained several failures rather than smoothing them away.

### Root-network coupling

The first bridge smoke test put the contested bridge in the WSL root network namespace. Existing Docker/WSL forwarding policy interfered with peer traffic. The correction was architectural rather than firewall-specific: the contested fabric moved into its own network namespace, eliminating dependence on unrelated Host forwarding rules.

### Invocation path is not executable identity

The first implementation rejected symlinked `python3` and `mcopy` paths. A second attempt resolved all tool paths before invocation. That broke `mcopy`, because `/usr/bin/mcopy` selects the `mtools` multicall operation through its invocation name. The final model preserves the invocation path and separately records the resolved target and digest.

### Guest NIC identity

The first real Windows networking run configured the first Guest adapter reported as hardware/up. PowerShell reported configuration success, but Winsock returned `10051` (`WSAENETUNREACH`) and the external packet sensor saw no challenge packet. The Guest contained multiple adapter records, so “first suitable adapter” was not an adequate identity rule.

The maintained canary was corrected to target the exact QEMU-declared MAC and to wait until Windows reports the connected Range route before attempting the peer connection. The following physical run produced the complete externally observed TCP exchange.

### Diagnostic timeout versus acceptance bound

A later exact-commit run used a deliberately shortened 180-second diagnostic bound and terminated before Guest Runner produced evidence. The canonical S5 acceptance bound remains 360 seconds. The same exact commit completed successfully under that bound. The failed 180-second receipt is retained because it demonstrates that diagnostic time budgets must not be silently promoted into product acceptance semantics.

## What S5 proves

For the maintained first contested-network challenge:

- a real Windows KVM Guest can be placed inside a network namespace that has no path into the Host root network namespace or Internet;
- a lightweight peer can provide real kernel TCP/IP behavior without requiring a second full VM;
- management authority remains outside the contested fabric while QEMU still uses that fabric;
- topology facts, packet observations, and Guest claims can coexist without authority conflation;
- heterogeneous materialization can preserve the network variable being studied while sharply reducing resource cost;
- both successful execution and timeout/failure paths can close machine and fabric resources cleanly.

## What S5 does not prove

S5 does not provide:

- several independently compromised full operating systems;
- lateral movement, credential propagation, or cross-host persistence;
- DHCP, DNS, routing, NAT, multiple zones, or Internet simulation;
- arbitrary services or arbitrary model-generated offensive actions;
- complete packet truth, lossless telemetry, Zeek/Suricata semantics, or live Guest process truth;
- dynamic topology changes or node churn during one session;
- a generic `RangeNode`, topology, fidelity, promotion, or materialization framework;
- production cyber operations or authorization outside the declared isolated Range.

## Next pressure

S5 should stop here. The fabric boundary itself has survived its first real Windows consumer.

The next experiment should add complexity only where a new research question requires it. A natural falsifier is to introduce another independently materialized lightweight peer/service or a topology change during one live Range and ask whether current backend-local identities and external truth remain sufficient. If repeated consumers expose the same node/fabric mechanism, only then should Security consider extracting a reusable topology or materialization abstraction. A second full VM should be introduced only when the hypothesis actually depends on an independent OS/kernel/failure domain.
