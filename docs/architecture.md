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
Host + Runtime + Link + Edge + Game
          │
          ▼
Independent Observer and Judge
          │
          ▼
Replay Bundle + Outcome + Recovery evidence
```

## Planes

- **Management plane** creates and destroys the range and cannot be controlled by evaluated Agents.
- **Experiment plane** contains Red, Blue, neutral, service, and user actors.
- **Observation plane** preserves authoritative network, execution, topology, and judge events.
- **Evidence export plane** moves bounded evidence out without becoming a command path back into the range.

## First vertical slice

The first executable system should be one disconnected dynamic range with three services, one disposable Edge node, one Red Agent, one Blue Agent, one independent observer, deterministic reset, and a complete replay bundle.
