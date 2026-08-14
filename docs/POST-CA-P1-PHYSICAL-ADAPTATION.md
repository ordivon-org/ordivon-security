---
schema_version: 1
id: security.post-ca-p1-physical-adaptation
title: Post-CA P1 — Physical Adaptive Capability Composition
type: experiment
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-14
summary: Owned local physical consumer testing fixed scripted, thin adaptive and Harness/model treatments against real provider receipts, fresh filesystem consequences, authority/policy counterplay and explicit information acquisition.
evidence_status: verified
readiness: ACCEPTED
---
# Post-CA P1 — Physical Adaptive Capability Composition

## Question

CA6 showed in a semantic arena that a thin observation-driven adaptive policy and the Harness/model Agent could both outperform a fixed script. P1 asks whether that law survives when actions are no longer semantic booleans but real bounded providers with subprocess receipts, mutable authority/policy state and independently re-read consequences.

P1 intentionally does **not** add exploit execution, real credentials, malware, network effects, lateral movement, Campaign state or a provider gateway.

## Physical world

Every treatment receives the same four interfaces and at most two actions:

- `control.credential` — a subprocess worker consumes an exact generation-bound **synthetic** token; revocation changes authority generation and makes stale possession fail;
- `control.script` — an exact maintained local shell carrier checks an owner policy file before producing the same benign control consequence;
- `control.maintenance` — an owner-native maintenance provider produces the same benign control consequence at higher cost/exposure and is independent of credential/script policy;
- `inspect.applicability` — a read-only observer returns exact current synthetic authority and policy state and cannot establish control.

The common consequence is an actual temporary-world file whose fresh re-read proves `controlEstablished=true` and records the source. Provider receipts explicitly retain `worldTruthVerified=false`.

Every treatment gets a fresh temporary owned world and must delete it completely at closeout.

## Frozen variants

1. `current-low-cost` — all paths current; credential is cheapest.
2. `stale-credential-counterplay` — visible evidence initially says all paths available, but immediately before the **first consequential action** Blue revokes the synthetic credential and blocks script while maintenance remains.
3. `all-control-unknown` — all consequential paths are UNKNOWN; inspection is available; actual credential is revoked while script/maintenance remain current.
4. `script-current-credential-revoked` — credential is visibly unavailable; script and maintenance are available.

Inspection does not bypass counterplay: if an Agent inspects first, the Blue policy change still occurs immediately before its first later consequential action.

## Deterministic result

The fixed script always tries credential then script.

The thin adaptive policy contains no variant names. It chooses the lowest cost+exposure action among currently `AVAILABLE` paths; if no consequential path is justified, it inspects. After real provider receipts/counterplay it replans from the newly visible state.

On clean implementation revision `e0ba5c13bd2ea820dff5190e4e197c80e8453ecb`:

| variant | fixed script | thin adaptive | adaptive sequence | adaptive regret |
| --- | --- | --- | --- | ---: |
| current-low-cost | success | success | credential | 0 |
| stale-credential-counterplay | **failure** | success | credential → maintenance | 2 |
| all-control-unknown | success, but blind | success | inspect → script | 1 |
| script-current-credential-revoked | success | success | script | 0 |

Thus the central CA6 adaptive-selection law survives physical provider/authority friction: a small current-evidence policy can inspect UNKNOWN, substitute after failed/stale authority, and avoid a fixed adjacent retry path.

## Harness/model treatments

P1 deliberately preserves the existing IF2 deliberation-before-authority and finalized-intent boundary. A model that returns `needs_input`, a transport failure, or an empty finalized request does **not** receive a consequential world effect.

Exploratory treatments exposed substantial stochasticity/provider-path friction and were retained rather than prompt-tuned away:

- one replicate produced one `needs_input` and three provider transport/TLS failures, with zero world effects;
- a later replicate produced one successful `inspect → script` path but also over-inspection, failed stale counterplay and an empty finalized request;
- after correcting an apparatus field that ambiguously called action slots a provider budget, another replicate succeeded in two variants but still returned `needs_input` in two.

The clean-source canonical model Job is:

```text
job-019fffcd-476e-7d52-a13e-359774110b1e
```

Raw private result:

```text
/var/lib/ordivon/security/p1-clean-acceptance.json
sha256:44fbb07877b0266cf9de2b8370ae8deefb9d71e1871f65b2d6ad3deb167962af
```

Canonical outcome:

| variant | model result | sequence | score/regret |
| --- | --- | --- | --- |
| current-low-cost | success | inspect → credential | 97 / 1 |
| stale-credential-counterplay | no effect | IF2 `needs_input` | 0 / 92 |
| all-control-unknown | no effect | IF2 `needs_input` | 0 / 95 |
| script-current-credential-revoked | no effect | IF2 `needs_input` | 0 / 95 |

All model-treatment worlds closed residual state, and every real world effect in the successful path occurred only after a finalized effect intent.

## Interpretation

P1 does **not** support a universal claim that language models are worse than deterministic policies. The treatment mixes model reasoning, IF2/Harness finalization and external provider delivery, and exploratory replicates showed all three can vary.

The narrower result is stronger and useful:

1. physical provider friction did **not** falsify CA6's thin adaptive-policy candidate;
2. the deterministic adaptive policy remained 4/4 and low-regret without knowing variant identifiers;
3. the current Harness/model treatment did not reveal a stable tactical advantage over that policy and was materially less robust across replicates;
4. model epistemic behavior tended to inspect even some explicitly AVAILABLE paths, increasing cost and, under a two-action adversarial budget, sometimes consuming the only chance to recover;
5. the major repeated friction was model/provider/finalization robustness, not a missing cross-provider Security action abstraction.

Therefore P1 leaves CA5 closed: no `RangeActionGateway`, generic tactical state machine, Campaign, Organization or provider registry is earned.

## Acceptance

Implementation revision:

```text
e0ba5c13bd2ea820dff5190e4e197c80e8453ecb
```

Clean-source gates Job:

```text
job-019fffcf-2b25-72e0-8c78-7c80632c34df
```

It passed:

- 409/409 unit tests;
- repository Ruff `E9,F`;
- deterministic physical dogfood with static counterplay failure, adaptive 4/4, UNKNOWN inspection and counterplay substitution;
- clean detached source at the exact implementation revision.

## Limits / reopen conditions

P1 is a local physical provider/filesystem world, not a Windows exploit range and not a real credential environment. Reopen a stronger physical tactical experiment only when an ordinary Security consumer needs materially different provider families or higher-fidelity topology. Reopen CA5 only if at least two such consumers fail for the same missing shared responsibility; integration inconvenience alone is insufficient.
