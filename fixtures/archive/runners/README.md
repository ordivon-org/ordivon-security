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

- `cli_windows_kvm_c1a_acceptance.py` — C1-A autonomous physical intent proof
  (receipt: `evidence/acceptance/c1a-autonomous-range-intent-f692c22.json`;
  reusable intent semantics graduated to AF2 current contracts)
- `cli_windows_kvm_fresh_controller_continuation_acceptance.py` — C1D
  (receipt: `evidence/acceptance/c1d-fresh-controller-continuation-691145f.json`;
  unique fresh-controller continuation apparatus retained historically, no current
  package/command consumer)
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

C1 consequence-protocol family (C1-I through C1-N):

- `cli_vanishing_consequence_acceptance.py` — C1-I
  (receipt: `evidence/acceptance/c1i-information-loss-3241eb9.json`)
- `cli_recipient_commit_gap_acceptance.py` — C1-J
  (receipt: `evidence/acceptance/c1j-recipient-commit-gap-6563613.json`)
- `cli_intrinsic_idempotency_acceptance.py` — C1-K
  (receipt: `evidence/acceptance/c1k-intrinsic-idempotency-e41ccf0.json`)
- `cli_compensation_acceptance.py` — C1-L
  (receipt: `evidence/acceptance/c1l-compensation-bbbacb4.json`)
- `cli_compensation_information_loss_acceptance.py` — C1-M
  (receipt: `evidence/acceptance/c1m-compensation-information-loss-404e7e6.json`)
- `cli_downstream_truth_failure_acceptance.py` — C1-N
  (receipt: `evidence/acceptance/c1n-downstream-truth-failure-88d068b.json`)

These runners form a bounded local consequence-protocol research chain. C1-N imports the
C1-M compensation binding as historical experiment apparatus; archiving the family together
preserves that relation without promoting it to current shared support.

Classical/adaptive carrier research family:

- `cli_ca1_carrier_matrix.py` — CA1 classical execution-carrier matrix
- `cli_ca2_vulnerability_evidence.py` — CA2 provider/vulnerability evidence
- `cli_ca3_post_compromise_state.py` — CA3 post-compromise state
- `cli_ca4_defensive_plane.py` — CA4 defensive observation/response plane
- `cli_ca6_tactical_adaptation.py` — CA6 tactical adaptation

CA5 and CA7 already close through evidence/document standing rather than a current runner.
The archived CA runners have no installed command or current package consumer; their accepted
receipts and canonical documents remain the owner-native research record.

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
