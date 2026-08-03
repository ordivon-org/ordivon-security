---
schema_version: 1
id: security.evidence
title: Evidence
type: reference
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - evaluator
  - maintainer
  - agent
updated: 2026-08-03
summary: Canonical reference for sanitized Security experiment and evaluation evidence, identity, digests, authority boundaries, limitations, and excluded sensitive artifacts.
evidence_status: verified
readiness: READY
applies_to:
  - ordivon-security-evidence
related:
  - security.experiment-layer
  - security.research-boundary
  - security.authority
---
# Evidence

## Scope

This directory retains sanitized evidence needed to reproduce, audit, rescore, or constrain Security claims. Large raw Trials, secrets, credentials, real endpoints, packet captures, personal network evidence, and unauthorized external artifacts remain outside Git.

## Contract

Repository evidence must bind exact experiment, implementation, Actor, World, Scorer, seed, opponent, resource, and source identity where applicable; preserve individual Trial references; include Artifact and Trace digests; state authority and external-effect boundaries; and record limitations, null results, and dispositions.

## Errors

Evidence is inadmissible when identity is incomplete, raw sensitive material is included, aggregate results erase Trial provenance, source or Trace digests are missing, hidden evaluation material leaked into Actor context, external authority is ambiguous, or a report claims more than the retained artifacts support.

## Compatibility

Current experiment and R-A evaluation evidence remains readable through its recorded schema and exact source identity. Historical Campaign reproduction is bound by [`../docs/archive/campaign-v0.md`](../docs/archive/campaign-v0.md) and does not make the removed Campaign format an active evidence contract.

Sanitized adversarial experiment and evaluation summaries belong here when they are required to support current claims. Raw secrets, real endpoints, packet captures, credentials, personal network evidence, large raw Trial traces, and historical Campaign bundles remain outside active repository evidence unless a specific archived reproduction record requires them.

Sanitized experiment evidence belongs under [`experiments/`](experiments/) when
it contains:

- exact experiment and implementation identity or file digests;
- aggregate results that do not erase individual Trial references;
- source Artifact and trace digests;
- explicit authority and external-effect boundaries;
- limitations, null results, and retain/reduce/delete decisions.

Round 1 evidence:

- [`experiments/round1-20260730.json`](experiments/round1-20260730.json)

R-A control-boundary evidence:

- [`r-a-control-boundary/report.json`](r-a-control-boundary/report.json) binds
  the exact Game M5-R1 source report, Security implementation revision, 24
  paired scenarios, four baseline decisions, effect accounting, evaluator
  disagreement, and retain/localize/shrink/delete dispositions.
