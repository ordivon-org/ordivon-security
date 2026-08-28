# Archived acceptance runners

Experimental acceptance runners moved here by the cleanup sweep
(`scripts/cleanup_sweep.py`) after retirement-time deletion pressure showed that no
current executable responsibility required the complete runner. Typical retirement evidence is:

- no `pyproject.toml` entry point;
- no production/current source consumer of the complete runner;
- no current runbook invocation requiring the runner in the live package;
- any reusable fixture/support responsibility required by current consumers has already been
  extracted to an owner-local non-CLI module.

Canonical documents may later name the archived path explicitly to make executable standing and
reproduction history recoverable. Such archival documentation is history/currentness metadata,
not a new current consumer.

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

Adversarial capability-environment intermediate experiment chain:

- `cli_adversarial_capability_environment_ace1.py` — ACE1 source-role ablation
- `cli_adversarial_capability_environment_ace2.py` — ACE2 objective-warning ablation
- `cli_adversarial_capability_environment_ace3.py` — ACE3 world-truth-role ablation
- `cli_adversarial_capability_environment_ace4.py` — ACE4 consequence-misrepresentation proof
- `cli_adversarial_capability_environment_ace5.py` — ACE5 structured-consequence repair
- `cli_adversarial_capability_environment_ace6.py` — ACE6 first-class-consequence treatment
- `cli_adversarial_capability_environment_ace7.py` — ACE7 representation-precedence treatment

Their exact receipts remain under `evidence/acceptance/ace1-*` through `ace7-*`. The
current contracts forced by ACE6/7 are tested directly against `RangeEffectInterface` and
Harness compilation using `adversarial_capability_environment_fixture.py`; ACE11 consumes
the same bounded authority/effect fixture without importing historical ACE4 orchestration.

Intent-convergence falsifier family:

- `cli_intent_finalization_if0_acceptance.py` — IF0 explicit-finalization falsifier
  (aggregate evidence: `evidence/acceptance/if0-if2-intent-convergence-cb2f0ae.json`;
  apparatus revision `4e30b93a71d0132522234e05cc7bf93cc5af9a57`)
- `cli_intent_readback_if1_acceptance.py` — IF1 exact-readback/digest-bound-finalization falsifier
  (aggregate evidence: `evidence/acceptance/if0-if2-intent-convergence-cb2f0ae.json`;
  apparatus revision `e9c344f40281653ccf2603ce3387b0ede78a9194`)

IF3 later preserves the IF2 success after removing IF1 readback/finalization Tools, so IF1
remains historical falsifier apparatus rather than a current package capability.

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
