# Capability gaps

## P0 — first valid experiment

| Capability | Current state |
|---|---|
| Campaign Manifest and stable Campaign identity | implemented |
| Capability and Consequence Envelopes as separate typed objects | implemented |
| Authority binding for owned or explicitly authorized worlds | implemented for explicit local manifests; shared range registry pending |
| Red, Blue, neutral, service, observer, judge, and lifecycle actor contracts | implemented |
| Model, Host, Tool, memory, time, compute, and collaboration capability profile | implemented |
| Independent append-only lifecycle event root | implemented |
| Out-of-band freeze, export, reset, destruction, and unknown-result reconciliation | implemented in Security plus component-owned Link and Edge ports |
| Deterministic reconstruction comparison and residual-state accounting | implemented and exercised against real Link and Edge bodies |
| Replay bundle across component-native identities | live Link, Edge, and Runtime composition implemented; Host and Game consumers pending |
| Outcome taxonomy including observer loss and invalid evidence | implemented |
| At least one infrastructure-only live Campaign | implemented |
| Persistent Edge-to-Link network attachment | pending; intentionally deferred to P0-D design review |
| At least one adaptive Red/Blue scenario | pending |

The control-plane blocker has been removed. A live infrastructure-only Campaign
now creates a deterministic Link World, runs its loopback fixture under an
Ordivon Runtime Workspace Job, executes a real Edge local-unshare body, and
closes prepare, start, freeze, reset, destroy, reconstruction, residual, replay,
and final evidence-bundle verification.

This proves lifecycle and evidence composition. It does **not** prove that the
Edge body is attached to the Link Network World. The current Edge body has an
empty ephemeral network namespace, while Link's loopback fixture remains a
separate Runtime-held process. Persistent network attachment, veth topology,
route/DNS application, and packet-level impairment are the next large design
boundary and must be reviewed before implementation.

## P1 — full-spectrum research

- dynamic multi-stage Web, service, operating-system, identity, and network campaigns;
- adaptive defense, deception, repair, and restoration;
- prompt, context, memory, Tool, Artifact, identity, delegation, evaluation, and supply-chain attacks;
- multi-Agent teams and communication or ownership failures;
- range-local Tool generation and controlled persistence;
- long-horizon campaigns and model or Host replacement;
- causal comparison of model, Harness, Tool, budget, and topology contributions.

## P2 — frontier research

- attack-defense coevolution;
- evidence-governed Skill or policy learning;
- organizational Agent structures and resource economies;
- days-long campaigns and cross-range transfer;
- verified post-training and evaluation datasets.
