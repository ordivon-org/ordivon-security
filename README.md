# Ordivon Security

**Agent-native strategic adversarial research.**

Ordivon Security studies intelligent actors pursuing conflicting objectives under partial observation, manipulated information, adaptive opposition, and contestable evaluation. Cyber environments are the first reproducible domain, not the final boundary.

## Active core

The active repository contains two executable surfaces:

1. `ordivon_security_experiments/` — Actor, World, Observation, Decision, hidden evaluation record, exact Trial identity, immutable Trace, independent Scorer, evidence sealing, analysis, model-backed actors, a local dynamic-opponent fixture, and a pinned CAGE 4 adapter;
2. `ordivon_security_evaluations/` — bounded adversarial evaluations that test exact claims such as provenance loss, reconciliation errors, omitted evidence, or evaluator manipulation.

### Why these parts are not replaceable by ordinary tests

- **Actor-specific Observation versus hidden World truth** prevents an Agent from receiving opponent or scorer state it could not observe. A normal unit test has no such epistemic boundary.
- **Exact Trial identity** prevents results produced by different actors, worlds, scorers, seeds, opponents, or turn limits from being compared as one experiment.
- **Independent Scorer and sealed hidden record** allow offline rescoring and make the evaluator a separate, contestable research subject rather than letting the executing World certify itself.
- **Immutable Trace and per-dimension outcomes** preserve strategic diagnosis that one aggregate success flag would erase.
- **Mature external adapters such as CAGE 4** test whether a local result transfers beyond a fixture designed by this repository.

Delete or narrow any mechanism when its research question disappears, a mature external system provides the same epistemic separation more cheaply, or no active experiment consumes it.

## Removed active machinery

The former Campaign Manifest, lifecycle ledger, coordinator, evidence-bundle format, process ports, and Link/Edge/Runtime live-composition harness had no external consumer. They proved one historical infrastructure-composition experiment but did not produce strategic adversarial autonomy. They are removed from the active package; [`docs/archive/campaign-v0.md`](docs/archive/campaign-v0.md) binds the exact revision and reproduction command without restoring that machinery to current `main`.

Security therefore owns no cross-project lifecycle, provider authority, Runtime state, World database, general workflow engine, IAM layer, scanner, or production attack platform.

## Verification

Default CI validates only the active experiment and evaluation code:

```bash
python3 -m unittest discover -v
```

The bounded local comparison remains an explicit research run rather than a merge ritual:

```bash
./scripts/run_round1_acceptance.sh
```

CAGE 4 and model-backed runs remain optional because they require pinned external source or locally configured providers.

## Research route

Current work prioritizes:

- opponent modelling and belief revision;
- deception and counter-deception;
- initiative, tempo, escalation, withdrawal, and resource allocation;
- organization, delegation, trust, collusion, and internal compromise;
- held-out opponents and transfer;
- evaluator manipulation and scorer integrity;
- attack-defense adaptation across repeated encounters.

New ontologies, control planes, monitors, or evidence layers require a named adversarial experiment that fails without them and a deletion condition.

See [`CHARTER.md`](CHARTER.md), [`docs/experiment-layer.md`](docs/experiment-layer.md), [`docs/research-agenda.md`](docs/research-agenda.md), and the retained Round 1 reports under [`docs/`](docs/).
