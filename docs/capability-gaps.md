# Capability gaps

## P0 — first valid experiment

| Capability | Current state |
|---|---|
| Campaign Manifest and stable Campaign identity | implemented |
| Capability and Consequence Envelopes as separate typed objects | implemented |
| Authority binding for owned or explicitly authorized worlds | contract implemented; concrete range registry adapter pending |
| Red, Blue, neutral, service, observer, judge, and lifecycle actor contracts | implemented |
| Model, Host, Tool, memory, time, compute, and collaboration capability profile | implemented |
| Independent append-only lifecycle event root | implemented |
| Out-of-band freeze, export, reset, destruction, and unknown-result reconciliation | coordinator and conformance implemented; concrete component ports pending |
| Deterministic reconstruction comparison and residual-state accounting | implemented at binding and coordinator boundary |
| Replay bundle across Host, Runtime, Link, Edge, and Game identities | sealed bundle and component binding contract implemented; live multi-component bundle pending |
| Outcome taxonomy including observer loss and invalid evidence | implemented |
| At least one adaptive Red/Blue scenario | pending |

The remaining P0 blocker is no longer another Security control-plane abstraction.
It is one real disconnected composition using component-owned Link, Edge,
Runtime, Host, and optional Game adapters. Those adapters must expose their
native identities and receipts without copying their journals into Security.

A stable Edge local-node JSON command surface does not currently exist. Security
deliberately does not invent a shadow Edge protocol; the concrete adapter should
be added by, or directly alongside, the Edge-owned lifecycle implementation.

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
