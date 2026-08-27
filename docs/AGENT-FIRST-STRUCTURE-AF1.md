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
updated: 2026-08-08
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

Historical `ordivon_security.actors.host_assigned`, `actors.runtime_assigned`, and `evaluation.world_*` implementations remain valid compatibility paths so accepted evidence and tests are not rewritten merely for directory aesthetics.

## Explicit non-goals

AF1 does not redesign the Agent cognition loop, remove Contest or Evaluation, make Host/Runtime integration a Security core primitive, invent an external-scope ontology, move every historical acceptance helper, or create a transaction, causal-DAG, policy, trust, organization or society framework.

The next step is AF2: graduate only the minimum autonomous Range-intent surface already forced by C1-A, without importing Contest tick/action-menu assumptions.
