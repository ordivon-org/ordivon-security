---
schema_version: 1
id: security.agent-first-structure-af1
title: Agent-first Structure AF1
type: decision
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-28
summary: Structural classification separating reusable Security constitution, scoped profiles, cross-repository integrations, and research apparatus without breaking accepted historical imports or inventing new universal frameworks.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.start
  - security.charter
  - security.law-profiles-c0
  - security.range-session-s0
---
# Agent-first Structure AF1

AF1 corrects dependency and discovery semantics after C0/C1 research advanced beyond the original Contest-first product structure.

## Four structural tiers

Security code and experiments are interpreted through four tiers:

1. **constitution / reusable substrate** — authority, truth/evidence distinctions, `RangeSession`, typed effect intent and recovery laws that have survived multiple falsifiers;
2. **profile** — synchronous Contest, CAGE team-plan control, software Evaluation, Guardian rules, Windows KVM and other bounded experimental worlds;
3. **integration** — bindings to Host, Runtime, Harness, World destination interfaces or other repositories whose state machines remain foreign authority;
4. **research apparatus** — acceptance runners, fault injectors, canaries and Case-specific probes whose evidence may be durable while their orchestration API is not.

`ordivon_security.security_surface_manifest()` is the machine-readable projection of this classification. AF1 originally retained `ordivon_security.api` as a mixed-maturity compatibility facade. A later Existence Gauntlet 2.0 pass found no external production consumer and retired that broad intermediary while preserving the narrower package-root exports through direct owner-module bindings; the full maturity-classified surface remains available through `security_surface_manifest()`.

## Boundary correction

`RangeAuthority.externalBoundary` remains part of exact authority identity, but Security core no longer interprets it as a singleton global enum. The value is now an exact non-empty **profile-defined boundary label**.

Thus `externalBoundary = denied` continues to describe current no-uplink experiments, while another explicitly owned/delegated profile may bind a different exact label without changing Security constitution. This change does not grant authority: zone/resource/capability admission and the owning World/profile still determine what an effect can reach.

## Canonical semantic import paths

New code should use `ordivon_security.integrations` and `ordivon_security.world_boundary` for Host/Runtime experiment adapters and World destination/admission adapters respectively.

The `integrations` namespace is reserved for current foreign-system bindings. IF0/IF1 readback/finalization machinery is experiment-specific and lives in `finalized_range_intent_research_fixture.py`; current IF2 may consume that historical treatment without promoting it into the reusable integration surface.

Historical `ordivon_security.actors.host_assigned`, `actors.runtime_assigned`, and `evaluation.world_*` paths remain valid compatibility paths where current consumers still require them. World destination implementations now live under `ordivon_security.world_boundary`; the historical Evaluation module paths are thin aliases rather than a second ownership claim.

## Explicit non-goals

AF1 does not redesign the Agent cognition loop, remove Contest or Evaluation, make Host/Runtime integration a Security core primitive, invent an external-scope ontology, move every historical acceptance helper, or create a transaction, causal-DAG, policy, trust, organization or society framework.

The next step is AF2: graduate only the minimum autonomous Range-intent surface already forced by C1-A, without importing Contest tick/action-menu assumptions.

## Currentness correction — 2026-08-28

AF1's original machine-readable surface used wildcard locators such as `ordivon_security.cli_*_acceptance` and `ordivon_security.cli_windows_kvm_p1_*` to classify broad research-apparatus families. That was a useful 2026-08-08 approximation, but later Existence Gauntlet work retired or archived many one-shot runners while those wildcards continued to project them as if they were current package affordances.

The current surface therefore no longer uses wildcard module locators. Historical acceptance standing is projected separately through `docs/authority.md`, `evidence/acceptance`, and `fixtures/archive/runners`, explicitly without claiming current package membership. The P1 research entry now denotes the exact currently installed command family from `pyproject.toml`; unregistered probes are not implied merely because their filenames share a prefix.

This preserves AF1's four-tier distinction while adding a currentness rule: **category membership and historical provenance do not establish current executable existence.**

## Post-Existence-Gauntlet executable topology — 2026-08-28

At Security source revision `774e33594345bfd1dd0686456498d9ea7a3f0154`, the current top-level CLI namespace has 38 modules and an exact liveness partition:

- 21 installed commands declared by `pyproject.toml`;
- 15 explicitly represented `research-apparatus` modules in `security_surface_manifest()`;
- 2 documented manual `python -m` commands (`cli_windows_host_p1_baseline` and `cli_windows_kvm_acceptance`).

There is no fourth/unclassified CLI class and the current CLI→CLI import graph has zero edges. Two P1 self-test programs remain current test apparatus but no longer carry the `cli_` identity because neither installation metadata, current surface representation, nor documentation treats them as a command interface.

Shared executable responsibility that survived deletion pressure now lives outside command runners. Current examples include `adversarial_capability_environment_fixture.py`, `autonomous_communication_research_fixture.py`, `incentive_communication_research_fixture.py`, `intent_convergence_research_fixture.py`, `deliberation_before_authority_research_support.py`, and `p1_physical_adaptation_research_fixture.py`. These modules exist because more than one current consumer requires the same exact fixture/support semantics; they are not a generic experiment framework. Test-only support extracted solely to keep historical runners mechanically convenient is not a current capability and belongs with archived apparatus.

The resulting structural rule is stronger than the original AF1 classification:

1. a current command must have an explicit current role witness — installed, research-surface, or documented manual;
2. a unit test can preserve a current invariant without making the tested module a public/current CLI affordance;
3. experiment chronology does not require every historical runner to remain importable from the current package;
4. when a historical runner contains a responsibility still required by multiple current consumers, extract only that responsibility and archive the orchestration;
5. current representation must not resurrect withdrawn apparatus through wildcard/category projection.

`fixtures/archive/runners/` therefore contains historical reproduction apparatus whose evidence and canonical conclusions remain valid. Restoring one of those runners is an explicit new reproduction/experiment decision, not a compatibility obligation.

This engineering contraction did not change the selected research-result standing projected by `research/security/authority/CURRENT.json`; its immutable source manifest remains a historical semantic-base binding and is not rewritten merely because current executable placement changes. Current implemented behavior continues to be owned by current source/tests, while `docs/authority.md` remains the owner-native recovery map for research authority.
