# Phase 0 module boundaries

## Purpose

This document fixes the ownership boundary for Ordivon Security Phase 0. It
classifies the current modules, names their authority, and records whether each
is reusable Security infrastructure or a reference acceptance harness.

## Classification and disposition

| Classification | Repository surfaces | Authority | Phase 0 disposition |
|---|---|---|---|
| Security core contract | `ordivon_security_contracts/campaign.py`, `schemas/campaign-manifest.schema.json`, `docs/campaign-contract-v0.md` | Security owns Campaign identity and revision, Security Actor identity/role/plane/evaluation status, admission Authority bindings, separate Capability and Consequence Envelopes, and the evidence-bound Outcome record. Referenced Host, Runtime, Link, Edge, and Game identities remain opaque and component-owned. | Retain as reusable Security contract. Keep the bounded Python compatibility validator, but freeze its vocabulary and scope; it is not a general JSON Schema engine. |
| Authority ledger and replay | `ordivon_security_contracts/ledger.py`, `scripts/inspect_campaign_ledger.py` | Security owns admission and lifecycle event ordering, the append-only hash chain, Security operation state, and the deterministically replayed Campaign projection. Component-native journals remain authoritative for native effects. | Retain as reusable Security authority and replay boundary. Preserve all negative, failed, unknown, observer-loss, residual, invalid, and inconclusive records. |
| Evidence and bundle | `ordivon_security_contracts/bundle.py`, `scripts/verify_evidence_bundle.py`, `evidence/README.md` | Security owns bundle membership, byte digests, seal material, and Campaign replay verification. The emitting component or independent judge remains authoritative for the meaning of attached native evidence. | Retain as reusable bounded export and verification boundary. It is not telemetry storage or signature infrastructure. |
| Component-neutral coordinator and binding | `ordivon_security_contracts/bindings.py`, `ordivon_security_contracts/coordinator.py` | Security owns immutable association from Campaign/World identities to component-native snapshots, durable operation intent, fixed lifecycle ordering, reconciliation state, and residual classification. Each component owns admission and effects for its native operation and object. | Retain as reusable fixed coordinator. Do not add user-defined workflows, scheduling, native state copies, or component-specific lifecycle authority. |
| Reference acceptance harness | `ordivon_security_contracts/process_ports.py`, `ordivon_security_contracts/live_composition.py`, `scripts/run_live_component_composition.py` | No new production authority. These surfaces invoke component-owned Link and Edge JSON controls and hold one Link fixture process within the declared Runtime Workspace for the P0-C acceptance run. | Acceptance-only. They are not the Campaign engine, a workflow DSL, Host, Runtime, a production adapter suite, or a general process manager. Replace or relocate them when a component-owned production integration exists; do not grow them into shared infrastructure. |
| Conformance support | `fixtures/`, `tests/`, and validation scripts | No runtime authority. Fixtures are synthetic contract examples and tests establish only the behavior they execute. | Retain as conformance and regression evidence. They make no real attack, defense, escape, or containment claim. |

`ordivon_security_contracts/__init__.py` is an export surface for the reusable
contract primitives. Its presence does not promote acceptance-only modules into
the reusable boundary.

## Core semantic ownership

- **Campaign** names the admitted Security experiment and immutable revision.
- **Actor** records only Security identity, role, plane, and evaluation status.
  Host retains Agent cognition, Goal, Task, Context, and ownership.
- **Authority** binds admission, lifecycle, observer, judge, World, provenance,
  and envelope identities. It does not replace native authorization or policy
  enforcement in another component.
- **Capability Envelope** states what the evaluated subject can use.
  **Consequence Envelope** independently states what external effects are
  authorized. They remain separate even when one Campaign binds both.
- **Outcome** is an evidence-bound judge record for one exact Campaign and
  environment. An enum or infrastructure closure alone is not an attack,
  defense, escape, or containment result.

## Acceptance-only hard boundary

For a completed, exactly identified P0-C run, the harness records real
acceptance evidence: a component-owned Link World and observer chain, a
Runtime-held loopback fixture process, a real Edge local-unshare body reached
through the component-owned long-lived JSONL surface, lifecycle receipts,
residual accounting, reconstruction, and sealed bundle replay.

P0-C does not attach the Edge body to the Link data plane, execute an evaluated
Agent, integrate Host or Game, or establish a Red/Blue result. The acceptance
harness may coordinate its own child processes only for this run. It must not
become process management, container or network infrastructure, telemetry,
workflow, or a second implementation of Host, Runtime, Link, Edge, or Game.

## Component Receipt and Attestation terminology

This is a documentation-level semantic freeze only. It does not add or revise a
Schema, public Protocol, wire field name, signature format, or trust system.
The semantic fields may be carried by the native payload, immutable binding,
and surrounding Security ledger together rather than duplicated in every
record.

A **Component Receipt** has the following minimum semantic fields:

- issuing component identity;
- exact Security operation identity and operation kind;
- component-native result or disposition;
- native subject identity or resolving binding;
- receipt integrity digest;
- native evidence or journal reference.

A **Component Attestation** has the following minimum semantic fields:

- attester identity and authority role;
- exact receipt, binding, or evidence subject identity and digest;
- typed predicate;
- verdict or disposition;
- evidence references;
- issuance context supplied by the authoritative ledger or component.

An Attestation is not synonymous with a cryptographic signature. Phase 0 does
not define signing, key distribution, rotation, revocation, or trust-chain
infrastructure.

## Host Binding direction

The Host Binding direction is:

```text
Security Campaign + Security Actor
            │ consumes Host-issued identity snapshot or receipt
            ▼
Host-owned Agent / Goal / Task identity + revision + evidence root
```

Security records the immutable association and carries the Security Campaign
and Actor identities unchanged. Host creates and owns its Agent, Goal, Task,
Context, cognition, and journal. Security must not create replacement Host
identities, copy Host state, or use the binding as authority to manage Host
execution. This direction is terminological guidance for future conformance
work and changes no current Schema or component Protocol.

## Phase 0 sequence

After the completed P0-C infrastructure-only acceptance boundary, work proceeds
in this order:

```text
Persistent Body + Attachment
→ single evaluated Agent
→ fixed/deterministic Campaign
→ passive/rule-based Blue
→ adaptive Red/Blue
```

Each step adds evidence needed by the next. The final adaptive Red/Blue target
remains required; intermediate acceptance does not redefine completion.
