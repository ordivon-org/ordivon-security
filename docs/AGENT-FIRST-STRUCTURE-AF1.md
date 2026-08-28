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

`ordivon_security.security_surface_manifest()` is the machine-readable projection of this classification. AF1 originally retained `ordivon_security.api` as a mixed-maturity compatibility facade. Existence Gauntlet 2.0 retired that broad intermediary but temporarily preserved narrower package-root domain exports through direct owner-module bindings. A later consumer census found zero current Security/cross-repository consumers for every root-level Range/Contest/Evaluation/Provider/Corpus class export, while README already made `ordivon-security-surface` the ordinary/full entry. The package root is therefore navigation-only: it exposes the ordinary/full surface projections and read-only ordinary capability preflight; domain contracts are imported from their owner modules/facades. This prevents package-root convenience from flattening constitution, profiles, integrations, and research into one apparent maturity tier.

## Boundary correction

`RangeAuthority.externalBoundary` remains part of exact authority identity, but Security core no longer interprets it as a singleton global enum. The value is now an exact non-empty **profile-defined boundary label**.

Thus `externalBoundary = denied` continues to describe current no-uplink experiments, while another explicitly owned/delegated profile may bind a different exact label without changing Security constitution. This change does not grant authority: zone/resource/capability admission and the owning World/profile still determine what an effect can reach.

## Canonical semantic import paths

New code should use `ordivon_security.integrations` and `ordivon_security.world_boundary` for Host/Runtime experiment-adapter discovery and World destination/admission adapters respectively. Host/Runtime turn-driver implementations remain physically under `actors/` because they implement Security's `AgentTurnDriver` side of `NativeHarnessActorBackend`; `integrations` is their canonical foreign-lifecycle projection, not a second implementation owner.

The `integrations` namespace is reserved for current foreign-system bindings. IF0/IF1 readback/finalization machinery is experiment-specific and lives in `finalized_range_intent_research_fixture.py`; current IF2 may consume that historical treatment without promoting it into the reusable integration surface.

AF2 and IF2/IF3 do share one narrower treatment-extension contract inside `integrations.harness_range_intent`: the exact `RANGE_INTENT_TOOL_NAME` / `RANGE_INTENT_PROMPT_REVISION`, `RangeIntentBridge`, `resolve_recorded_range_intent`, and source-binding helpers. Those names exist so ablations can hold the effect-intent transport and foreign-source identity fixed while varying deliberation/finalization treatment. They are module-level research/integration contracts and are deliberately absent from `ordivon_security.integrations.__all__`.

Historical compatibility survives only under current consumer pressure. `ordivon_security.actors.host_assigned` / `actors.runtime_assigned` remain physical implementation paths for the foreign-lifecycle Actor variants, while `ordivon_security.evaluation.world_entity` remains a frozen compatibility alias because current World production acceptance still imports that exact path. The old `evaluation.world_resource` and `evaluation.world_message` aliases had no current external/source consumer beyond compatibility tests and are retired. World destination implementations live under `ordivon_security.world_boundary`; compatibility never constitutes a second ownership claim.

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

There is no fourth/unclassified CLI class and the current CLI→CLI import graph has zero edges. Two P1 self-test programs were first stripped of a false `cli_` identity and then, under a later package-membership deletion pressure, moved to `tests/support/`: no current source consumer, surface entry, runbook or installed command required their Python orchestration in the package. Their bounded C resources remain package fixtures under test.

Shared executable responsibility that survives deletion pressure may live outside command runners. Most current examples — `autonomous_communication_research_fixture.py`, `incentive_communication_research_fixture.py`, `intent_convergence_research_fixture.py`, `deliberation_before_authority_research_support.py`, and `p1_physical_adaptation_research_fixture.py` — have multiple current source consumers. `adversarial_capability_environment_fixture.py` is the bounded counterexample: it has one current source consumer (ACE11), but it owns the exact ACE4–ACE11 cross-treatment authority/effect/consequence fixture used to prove that ACE6/7/9/10 regressions vary only the intended representation coordinate. Folding that fixture into ACE11 would couple treatment identity back to one runner. Thus multiple current consumers are strong sufficient extraction pressure, not a universal necessity; an independently meaningful semantic/authority/lifecycle boundary may also justify one-current-consumer support. Tests alone still do not create current package capability, and support extracted solely to keep historical runners mechanically convenient belongs with archived apparatus.

The resulting structural rule is stronger than the original AF1 classification:

1. a current command must have an explicit current role witness — installed, research-surface, or documented manual;
2. a unit test can preserve a current invariant without making the tested module a public/current CLI affordance;
3. experiment chronology does not require every historical runner to remain importable from the current package;
4. when a historical runner contains a responsibility still required by multiple current consumers, or an independently meaningful semantic/authority/lifecycle boundary that cannot be folded into its one current consumer without re-coupling the experiment, extract only that responsibility and archive the orchestration;
5. current representation must not resurrect withdrawn apparatus through wildcard/category projection.

`fixtures/archive/runners/` therefore contains historical reproduction apparatus whose evidence and canonical conclusions remain valid. Restoring one of those runners is an explicit new reproduction/experiment decision, not a compatibility obligation.

This engineering contraction did not change the selected research-result standing projected by `research/security/authority/CURRENT.json`; its immutable source manifest remains a historical semantic-base binding and is not rewritten merely because current executable placement changes. Current implemented behavior continues to be owned by current source/tests, while `docs/authority.md` remains the owner-native recovery map for research authority.

The AC0 communication fixture applies the same rule to experimental identity: `AC0_RANGE_ID`, Actor A/B identities and authorities, message/shared zones, message/activation capabilities/effects, and fixed signal treatments are explicit module-level research-fixture coordinates. AC1/AC2/IF may reuse those exact coordinates to preserve counterfactual comparability; they are not exported from the package root and do not constitute a generic social/communication ontology.
