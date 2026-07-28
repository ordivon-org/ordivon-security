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
| One evaluated Agent in the attached world | pending after P0-D |
| Fixed/deterministic evaluated Campaign | pending after the single-Agent slice |
| Passive/rule-based Blue | pending after the fixed Campaign |
| At least one adaptive Red/Blue scenario | pending; final Phase 0 target unchanged |

## P0-C evidence boundary

The control-plane blocker has been removed. The P0-C acceptance harness can
create a deterministic Link World, run its loopback fixture under an Ordivon
Runtime Workspace Job, execute a real Edge local-unshare body, and close
prepare, start, freeze, reset, destroy, reconstruction, residual, replay, and
final evidence-bundle verification. Each completed run records its exact
Campaign and environment identities in private output; this document does not
claim an unidentified run.

An identified completed P0-C run proves lifecycle and evidence composition. It
does **not** prove that the Edge body is attached to the Link Network World. The
current Edge body has an empty ephemeral network namespace, while Link's
loopback fixture remains a separate Runtime-held process. Persistent network
attachment, veth topology, route/DNS application, and packet-level impairment
are the next large design boundary and must be reviewed before implementation.

## Remaining Phase 0 order

The implementation and evidence sequence is:

1. **P0-D — Persistent Body + Attachment:** keep an Edge body alive and attach
   it to the declared Link World with independently observable lifecycle and
   residual evidence.
2. **single evaluated Agent:** add exactly one Host-owned evaluated Agent only
   after the attached body boundary is established.
3. **fixed/deterministic Campaign:** exercise that Agent against a fixed
   scenario with deterministic setup, judging, teardown, and replay.
4. **passive/rule-based Blue:** add a non-adaptive or rule-driven defensive
   actor so observation and scoring mature before co-adaptation.
5. **adaptive Red/Blue:** run the required adaptive adversarial Campaign with
   authoritative evidence.

These stages narrow implementation risk; they do not lower the final Phase 0
goal. A fixed target, a single evaluated Agent, or passive/rule-based Blue does
not satisfy the final adaptive Red/Blue target.

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
