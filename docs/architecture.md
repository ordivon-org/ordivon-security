# Architecture

```text
Campaign Manifest
  ├─ Capability Envelope
  ├─ Consequence Envelope
  ├─ Actor contracts
  ├─ World and target authority
  ├─ Objectives and stop conditions
  └─ Evaluation contract
          │
          ▼
Campaign Authority Ledger
  ├─ fixed lifecycle operations
  ├─ component-native identity bindings
  ├─ unknown-result reconciliation
  └─ residual-state evidence
          │
          ▼
Host + Runtime + Link + Edge + Game
          │
          ▼
Independent Observer and Judge
          │
          ▼
Sealed Evidence Bundle + Replay + Outcome
```

## Planes

- **Management plane** creates, freezes, resets, and destroys the range and cannot be controlled by evaluated Agents.
- **Experiment plane** contains Red, Blue, neutral, service, and user actors.
- **Observation plane** preserves authoritative network, execution, topology, and judge events.
- **Evidence export plane** moves bounded evidence out without becoming a command path back into the range.

The lifecycle authority, judge, and observer identities are independent from
evaluated experiment actors. Observer loss is recorded separately from
experiment success or failure.

## State ownership

| State | Owner |
|---|---|
| Campaign admission, phase, lifecycle operation, outcome | Security |
| Agent Goal, Task, Context, cognition | Host |
| Workspace, Job, Attempt, process tree, Artifact | Runtime |
| Network World, mutation, egress evidence | Link |
| remote/disposable Node and Node lifecycle | Edge |
| deterministic scenario, World mutation, replay and score | Game |

Security does not copy component-native journals. A `ComponentBinding` joins the
Security Campaign and World IDs to one native object identity, revision, root
digest, and bounded metadata.

## Module boundary

| Classification | Modules | Phase 0 role |
|---|---|---|
| Security core contract | `campaign.py` | Campaign, Actor, Authority, Capability and Consequence Envelopes, and Outcome admission semantics |
| Authority ledger and replay | `ledger.py` | append-only Security lifecycle truth and deterministic projection |
| Evidence and bundle | `bundle.py` | bounded export, integrity verification, and replay material |
| Component-neutral coordinator and binding | `bindings.py`, `coordinator.py` | immutable native identity bindings and fixed lifecycle ordering |
| Reference acceptance harness | `process_ports.py`, `live_composition.py` | P0-C Link/Edge/Runtime composition only |

Only the first four rows are reusable Security boundaries.
`process_ports.py` and `live_composition.py` are acceptance-only: they are not
the Campaign engine, a workflow DSL, Host, Runtime, or a general process
manager. Native process, container, Node, and network authority stays with
Runtime, Edge, and Link. See
[`module-boundaries.md`](module-boundaries.md) for the complete authority and
Phase 0 disposition.

## Lifecycle boundary

Campaign lifecycle v0 supports only:

```text
prepare → start → freeze → export → reset → destroy → reconstruct → verify
```

This is a fixed coordinator, not a workflow DSL or scheduler. Every component
call is preceded by a durable operation intent. Ambiguous responses become
`unknown` and are reconciled through the original native operation identity;
missing evidence never authorizes automatic redispatch.

Emergency destruction may proceed from admitted, preparing, ready, running,
frozen, or invalid state. A final outcome is admitted only after destruction,
so cleanup and residual inspection remain possible after failure.

## Evidence and replay

The Security ledger is an append-only hash chain. Evidence export stages and
seals a bounded directory, then atomically renames it into place. Verification
checks every listed file digest and deterministically rebuilds the Campaign
projection from the admitted manifest and complete event chain.

There are two distinct identity checks:

1. **structural replay** verifies retained events and evidence roots without
   re-executing effects;
2. **reconstruction comparison** recreates a component from declared inputs and
   requires its native binding digest to equal the admission binding.

## Current executable slice

The reusable implemented slice includes Campaign admission, lifecycle
authority, component bindings, fixed coordination, response-loss
reconciliation, observer loss, residual reports, reconstruction comparison,
evidence export, replay, and infrastructure outcome classification.

Production Link, Edge, Runtime, Host, and Game control surfaces remain
component-owned. Security deliberately does not introduce a shadow network
controller, Node runtime, Job registry, Host journal, or Game database. The
P0-C reference acceptance harness wraps real component-owned Link and Edge
JSON control surfaces and holds one Link fixture process under the declared
Runtime Workspace; that wrapper does not become a production adapter or a new
component authority.

The remaining Phase 0 order is Persistent Body plus Attachment, one evaluated
Agent, a fixed/deterministic Campaign, passive/rule-based Blue, and finally
adaptive Red/Blue. These are evidence gates; the final adaptive Red/Blue target
is not reduced by the intermediate slices.
