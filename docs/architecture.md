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

The implemented slice includes Campaign admission, lifecycle authority,
component bindings, fixed coordination, response-loss reconciliation, observer
loss, residual reports, reconstruction comparison, evidence export, replay,
and infrastructure outcome classification.

Concrete Link, Edge, Runtime, Host, and Game adapters remain component-owned.
Security deliberately does not introduce a shadow network controller, Node
runtime, Job registry, Host journal, or Game database.

The first future adversarial slice may add evaluated Red and Blue actors only
after a real disconnected component composition proves the lifecycle boundary.
