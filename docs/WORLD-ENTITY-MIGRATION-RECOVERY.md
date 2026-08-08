---
schema_version: 1
id: security.world-entity-migration-recovery
title: World Entity Migration Recovery Boundary
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - maintainer
  - builder
  - agent
updated: 2026-08-08
summary: Physical World Entity KVM recovery boundary: predecessor ownership remains provenance, completed unpublished carriers require independent observation before publication, and the tested single-host publication-only path needs no durable Entity successor claim.
evidence_status: verified
readiness: EXPERIMENTAL
applies_to:
  - world-entity-migration
  - windows-kvm
related:
  - security.unpublished-completion-c1h
  - security.mid-successor-recovery-c1g
  - security.successor-ownership-c1e
  - security.partial-materialization-c1c
  - security.law-profiles-c0
---
# World Entity Migration Recovery Boundary

## Question

The earlier W2 Entity experiment proved that Security can materialize an opaque World Entity continuity payload as a contained Windows KVM carrier. Its recovery path also rewrote `ownerPid` / `ownerStartTime` when another controller claimed an existing machine state.

C1-E through C1-H later established stronger recovery laws:

- predecessor ownership is historical provenance;
- durable publication is not a physical-world progress oracle;
- completion fact, completion publication, and executor liveness are distinct;
- a successor must independently observe enough current truth before deciding whether to continue, adopt, publish, or refuse;
- observation must not silently become intervention.

The Entity integration question therefore became:

> Can an unpublished carrier recover truthfully without owner takeover, blind body replay, or importing a broader successor protocol than the recovery action actually needs?

## Current result

Yes, for the exact single-host publication path tested here.

The destination uses execution identity revision `3`:

```text
recoveryMode = reobserve-and-publish-only-no-owner-rewrite
unpublishedNativeState = unknown-unless-completion-reobserved
```

It preserves these boundaries:

- the original `ownerPid` / `ownerStartTime` remains predecessor provenance;
- a fresh publisher never starts, restarts, or repairs the Entity body while recovering publication;
- an `executing` ledger is not itself proof of completion;
- completion must be independently re-observed from exact QEMU/swtpm process identities, QEMU command binding, QMP running/no-NIC truth, the continuity run disk, and QMP block topology;
- only after those observations agree may the publisher write `migration-running-contained` and commit the materialization receipt;
- if the observations cannot establish completion, the outcome remains `UNKNOWN`.

The current recovery coordinates are deliberately separate:

```text
per-migration flock      → publication exclusion
current physical observe → completion evidence
stable KVM ledger        → durable publication
receipt                  → reconstructable historical outcome
ownerPid/startTime       → predecessor provenance
```

## Negative baseline: do not take over the old owner

The first corrected baseline removed `claim_existing_state` from Entity recovery. Deterministic tests proved that an ambiguous `executing` ledger remains read-only and that retrying `materialize` cannot silently resume an unpublished Run.

Physical acceptance at revision `09a350c4ab2f81e0bd84c0323eeae1efc18a2c49` then killed the original controller after QEMU had started and QMP had confirmed no network device, but before stable materialization publication. The retained index is [`../evidence/acceptance/world-entity-controller-loss-09a350c.json`](../evidence/acceptance/world-entity-controller-loss-09a350c.json), SHA-256 `84131f1b992b2cad4835027e92349afe70674d16bde914b3cff9d7dc7e2dc415`.

That baseline established:

```text
controller exit           = SIGKILL / -9
QEMU survived             = true
swtpm survived            = true
fresh reconcile           = UNKNOWN
ledger bytes changed      = false
predecessor owner changed = false
body replay               = false
cleanup                   = clean
```

The result falsified the idea that a fresh controller must rewrite historical ownership merely to recover an Entity trajectory.

## Clean revision-3 physical acceptance

The final implementation revision tested physically is `03a55aab0741d3f2259384f543a088cd3ea3f5a7`. That exact revision is retained in canonical ancestry so the following acceptance evidence remains source-bound.

### Competing publishers

The retained index is [`../evidence/acceptance/world-entity-publication-race-03a55aa.json`](../evidence/acceptance/world-entity-publication-race-03a55aa.json), SHA-256 `17270028f90ddee68bef94f7e75a81d83692e58d94cff932acd74be7b074645f`.

After the original controller was killed, two fresh publishers were released concurrently against the same exact migration:

```text
materialized responses      = 2
responses equal             = true
stable publication attempts = 1
stable phase                = migration-running-contained
predecessor owner preserved = true
QEMU identity preserved     = true
swtpm identity preserved    = true
physical body replay        = false
cleanup                     = clean
```

The per-migration process-scoped `flock` serialized this publication race. The losing publisher reused the same retained result rather than creating another publication or replaying the body.

### Publisher dies after stable ledger, before receipt

The retained index is [`../evidence/acceptance/world-entity-publisher-crash-03a55aa.json`](../evidence/acceptance/world-entity-publisher-crash-03a55aa.json), SHA-256 `100e32509f61a6b1492933a075093c9d8f233194022e23e705fd730458e541e6`.

A first fresh publisher independently re-observed the carrier and durably wrote `migration-running-contained`, then was killed with `SIGKILL` before receipt commit. A second fresh process produced:

```text
first publisher exit              = SIGKILL / -9
stable ledger existed             = true
receipt absent at first crash     = true
second response                   = materialized
second stable publication attempt = false
stable ledger bytes unchanged     = true
receipt reconstructed             = true
predecessor owner preserved       = true
QEMU identity preserved           = true
swtpm identity preserved          = true
physical body replay              = false
cleanup                           = clean
```

The stable ledger therefore survives publisher death as the durable publication fact, while the receipt remains reconstructable output rather than a second authority.

## Relation to C1-H

C1-H independently reaches the same core separation in a harder Range profile: the peer-B consequence can be complete and consumed while durable completion publication is stale and the one-shot peer service and Guest executor are already gone. A later successor combines persistent Host topology with independent Guest and read-only sensor evidence, then repairs publication without replaying the Range effect.

Entity revision 3 agrees with that law but has a different consumer-specific mechanism:

```text
C1-H Range
persistent consequence
+ independent completion evidence
+ exclusive recovery authority
+ successor lineage
→ publication-only repair

Entity rev3
live exact carrier
+ independent completion evidence
+ per-migration publication exclusion
→ publication-only repair
```

The difference is intentional. C1 Range successors can continue or mutate an incomplete physical world, so C1-E/F/G/H retain explicit recovery ownership and successor lineage. Entity revision 3 performs no continuation body mutation when repairing publication. Its physical race and publisher-crash tests did not expose a need for an additional durable Entity successor claim.

This does **not** mean executor liveness is universally required for completed-but-unpublished recovery. C1-H proves the opposite for consumed one-shot consequences. QEMU/swtpm liveness is part of this Entity profile's evidence because the claim being published is that the exact carrier is currently materialized and running.

Both profiles preserve the stronger law:

```text
completion fact
!=
completion publication
!=
executor liveness
```

and the evidence-method law:

```text
observation
!=
intervention
```

## Resulting law

For this bounded single-host Entity consumer, the evidence does **not** justify a durable successor claim or lease for publication-only recovery.

The reusable rule is narrower:

> Recovery mechanisms should match the authority of the recovery action. Publication of already-observed truth does not automatically require the same successor protocol as continuation that changes the world.

The current `flock` is only a single-host publication mutex. It is not a universal distributed recovery law, and it does not establish completion by itself.

## What remains valid from the earlier Entity work

- migration identity binds one exact Entity, source World, destination World, source-departure digest, and continuity-payload digest;
- the continuity payload remains opaque to Security and is staged on a removable FAT carrier;
- Guest self-report is not destination materialization authority;
- the KVM carrier is launched without a network device;
- exact stable publication can reconstruct a lost historical receipt without launching a second body;
- changed source departure, continuity payload, environment generation, or materialization identity fails closed.

## What this does not prove

Entity Migration remains experimental and is not yet promoted to the World production contract surface. The accepted evidence does not prove:

- cleanup or retry authorization for a retained pre-body fence;
- safe recovery when native launch evidence exists but no exact live carrier or stable publication can be established;
- current Entity presence after the native carrier later exits;
- authenticated source-World authority beyond the current caller trust boundary;
- distributed or multi-host publication arbitration;
- recovery of an information-theoretically ambiguous one-shot effect whose delivered and undelivered histories converge to the same observable state.

## Next pressure

The next local Entity recovery problem is **pre-body abandonment**, not publication authority. A controller may die after the durable migration fence exists but before QEMU materially starts. The discriminating states are:

```text
migration-staged + no native launch evidence
swtpm-started + exact TPM-only process
ambiguous launch evidence + no stable QEMU publication
```

The first two may justify exact cleanup followed by `not_committed` / retry-safe only if independent process and filesystem observation proves that no Entity carrier body launched and cleanup reaches zero residuals. The third must remain `UNKNOWN` unless stronger evidence removes the ambiguity.
