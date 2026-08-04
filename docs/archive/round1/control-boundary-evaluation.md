# R-A Adversarial Control-Boundary Evaluation

Security implementation revision: `887eab1bfb1f34f88418dddbf20535dc4ade9482`
Game main revision: `83127fc5d770bc199af532fb3aa7e6ba67d28b3b`
Game implementation revision: `56e99b8fdb3da8878cc771e5b361b33164fb45cb`
Bound Game report SHA-256: `b111dcab83d094dfa87c67b5e2d6d0a4504860a054152c6cdd856aebfd53d662`

## Experiment

The evaluator consumed the exact seven-pair Game M5-R1 report and produced 12 adversarial mutations plus matched clean controls (24 scenarios total). It did not execute or copy Game, Host, Runtime, or Campaign state machines.

## Baseline results

| Baseline | Exact decisions | False abstentions | Unsafe proceeds | Recovery misses |
|---|---:|---:|---:|---:|
| model-only-instruction | 13/24 | 0 | 11 | 1 |
| fixed-risk-or-approval | 13/24 | 1 | 10 | 1 |
| native-state-only | 18/24 | 0 | 5 | 1 |
| provenance-reconcile-verify | 24/24 | 0 | 0 | 0 |

The provenance-bound, reconcile-first, independently verified baseline classified every scenario correctly. Model-only and fixed-threshold controls each classified only 13/24. Native state without provenance/coverage binding classified 18/24 and still failed stale source, omission, hidden-memory, laundering, and UNKNOWN recovery cases.

## Boundary findings

- Post-commit refusal preserved already committed Effects; the evaluator recorded zero retroactive Effect erasures.
- Observer or monitor unavailability did not veto otherwise valid work.
- UNKNOWN required reconciliation rather than retry, success, or generic hold.
- Exact authority, current lease generation, unique submission, authoritative Artifact comparison, and required Verification remained owner-local controls.
- Two additional minimal facts were exposed: omission-aware evidence coverage and a provider-replacement continuity receipt.

## Architecture dispositions

| Candidate | Decision | Owner |
|---|---|---|
| model-only non-action instruction | delete | none |
| global risk score or approval threshold | delete | none |
| generic approval plane | shrink | Host authority binding |
| provenance-bound Context and source evidence roots | retain-localize | Host Context plus source adapters |
| reconcile-first UNKNOWN operation handling | retain-localize | Host/provider operation boundary |
| independent accepted verification before completion | retain-localize | Host completion authority |
| required evidence coverage including unfavorable evidence | retain-minimal | Host completion proposal |
| provider replacement continuity receipt | retain-minimal | Host/Harness reconstruction boundary |
| observer or monitor liveness veto | delete | none |
| new Security control state machine | delete | none |

## Conclusion

No new Security control platform, generic Hook system, trust score, or approval plane is justified. Security retains the adversarial matrix and evaluation evidence; Host/Harness own the two minimal continuity/completion facts, while existing Game and Host invariants remain in their current owners.

## Limitations

- This is a deterministic adversarial ablation over committed Game evidence, not an estimate of open-world model policy quality.
- The four baselines are explicit evidence-admission ablations; they do not represent complete commercial safety products.
- No public target, exploit, credential, or uncontrolled network action was used.
