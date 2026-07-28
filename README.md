# Ordivon Security

**Full-spectrum adversarial Agent systems research.**

Ordivon Security is the application and laboratory layer for maximum-capability elicitation, dynamic cyber-range experiments, attack-defense coevolution, containment, replay, and recovery research.

```text
maximize internal Agent capability
+ independently constrain external consequence
+ preserve authoritative evidence
```

It composes the broader Ordivon stack:

- Host owns Agent cognition, Goal, Task, Context, and ownership;
- Runtime owns trusted-local execution and analysis;
- Link owns the network world and communication fabric;
- Edge owns remote Agent bodies and their lifecycle;
- Game contributes scenario, replay, and scoring machinery;
- Security owns Campaigns, actors, objectives, consequence envelopes, judges, and evaluation.

## Current state

The repository contains three executable boundaries:

1. **Campaign Manifest v0** validates admission identity, exact cross-project
   references, independent capability and consequence envelopes, actors,
   authority, objectives, stop conditions, transitions, and outcomes.
2. **Campaign lifecycle v0** provides an append-only authority ledger, immutable
   component bindings, fixed prepare/start/freeze/reset/destroy coordination,
   unknown-result reconciliation, residual-state classification, reconstruction
   identity checks, and sealed evidence-bundle replay.
3. **Live component composition v0** consumes component-owned Link and Edge
   control surfaces while Ordivon Runtime holds the real loopback fixture. It
   executes a real local-unshare Edge body and closes a complete infrastructure
   Campaign with clean residual accounting and independent bundle verification.

Lifecycle v0 is not a workflow engine and does not copy Link, Edge, Runtime,
Host, or Game state. Each component retains its native identity and journal;
Security binds only immutable identity and evidence roots.

The live composition does not attach the Edge body to the Link data plane. That
larger network-attachment boundary remains an explicit design problem rather
than a hidden claim.

No Red/Blue Agent, exploit, public target, or executable attack implementation
exists in this repository.

Start with:

- [`CHARTER.md`](CHARTER.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/campaign-contract-v0.md`](docs/campaign-contract-v0.md)
- [`docs/campaign-lifecycle-v0.md`](docs/campaign-lifecycle-v0.md)
- [`docs/live-composition-v0.md`](docs/live-composition-v0.md)
- [`docs/capability-gaps.md`](docs/capability-gaps.md)
- [`docs/research-boundary.md`](docs/research-boundary.md)
- [`schemas/campaign-manifest.schema.json`](schemas/campaign-manifest.schema.json)

## Validation

Validate the Campaign fixture and run all standard-library tests:

```bash
python3 scripts/validate_campaign.py \
  fixtures/campaigns/valid/minimal-owned-range.json
python3 -m unittest discover -v
```

Inspect a ledger or verify a sealed evidence bundle without mutation:

```bash
python3 scripts/inspect_campaign_ledger.py /path/to/ledger --events
python3 scripts/verify_evidence_bundle.py /path/to/bundle
```

The fault matrix covers response loss after native admission, observer
unavailability, a lost Node, ambiguous destruction, residual Node state,
reconstruction drift, event tampering, bundle tampering, and complete
prepare-to-destroy closure with receipts.
