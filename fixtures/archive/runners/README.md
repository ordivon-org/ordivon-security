# Archived acceptance runners

Experimental acceptance runners moved here by the cleanup sweep
(`scripts/cleanup_sweep.py`) when they lost every live consumer:

- no `pyproject.toml` entry point
- no import from `src/`, `tests/`, `research/`, or `scripts/`
- no mention in `docs/` (the experiment may have docs, but the runner
  itself was never referenced)

The experiments they drove remain canonical history: their accepted
receipts live in `evidence/acceptance/` and their conclusions live in
`docs/`. Archiving the runner does not touch evidence (AGENTS.md rule 19:
evidence is history; runners are not compatibility requirements).

## Contents

C1 successor/recovery family (these four imported one another in a closed
cluster — archiving one exposed the next):

- `cli_windows_kvm_unpublished_completion_acceptance.py` — C1H
  (receipt: `evidence/acceptance/c1h-unpublished-completion-6fce713.json`)
- `cli_windows_kvm_mid_successor_recovery_acceptance.py` — C1G
  (receipt: `evidence/acceptance/c1g-mid-successor-recovery-38f6e52.json`)
- `cli_windows_kvm_multiple_successors_acceptance.py` — C1F
  (receipt: `evidence/acceptance/c1f-multiple-successors-511f08f.json`)
- `cli_windows_kvm_successor_ownership_acceptance.py` — C1E
  (receipt: `evidence/acceptance/c1e-successor-ownership-d82241b.json`)
- `cli_windows_kvm_successor_reconciler_race_acceptance.py` — C1F-adjacent
  reconciler race runner (imported live c1a/c1b/c1d/c1c helpers, but no
  module imported it; no doc or evidence mention)

World-entity family:

- `cli_world_entity_prebody_abandonment_acceptance.py`
  (receipt: `evidence/acceptance/world-entity-prebody-abandonment-e640b28.json`)
- `cli_world_entity_publication_recovery_acceptance.py`
  (receipts: `evidence/acceptance/world-entity-publication-race-03a55aa.json`,
  `world-entity-publisher-crash-03a55aa.json`)
- `cli_world_entity_controller_loss_acceptance.py`
  (receipt: `evidence/acceptance/world-entity-controller-loss-09a350c.json`)

All archived runners use absolute imports only, so they remain readable as
historical artifacts.

## Restoring

If a future experiment needs one of these runners, `git mv` it back to
`src/ordivon_security/` and register it in `pyproject.toml` if it should be
a console script. Do not re-add it without a consumer (AGENTS.md rule 17).
