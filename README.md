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

This repository now includes an executable Campaign Manifest v0 contract. It
validates admission identity, exact cross-project references, independent
capability and consequence envelopes, actors, authority, objectives, stop
conditions, and outcomes. No executable Cyber Range or attack implementation
exists.

Start with:

- [`CHARTER.md`](CHARTER.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/capability-gaps.md`](docs/capability-gaps.md)
- [`docs/research-boundary.md`](docs/research-boundary.md)
- [`docs/campaign-contract-v0.md`](docs/campaign-contract-v0.md)
- [`schemas/campaign-manifest.schema.json`](schemas/campaign-manifest.schema.json)

Validate the fixture and run all tests with the standard library:

```bash
python3 scripts/validate_campaign.py \
  fixtures/campaigns/valid/minimal-owned-range.json
python3 -m unittest discover -v
```
