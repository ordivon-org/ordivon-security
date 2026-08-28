---
schema_version: 1
id: security.defensive-observation-response-ca4
title: Defensive Observation & Response CA4
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-14
summary: Bounded provider-first Blue-plane experiment separating raw artifact observation, ClamAV-derived detection, current applicability adjudication, quarantine response receipt, post-response truth, stale alerts and detector failure.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.classical-capability-basis-ca0
  - security.post-compromise-state-ca3
  - security.research-boundary
---
# Defensive Observation & Response CA4

## Question

CA4 asks whether a useful Blue plane can stay thin while preserving the distinctions an adaptive defender actually needs:

```text
raw observation
!= derived detection/classification
!= adjudication
!= response receipt
!= post-response world truth
```

The experiment uses the already-installed ClamAV provider plus an EICAR standard anti-malware test pattern, not real malware. The response surface is one case-local quarantine move inside an owned temporary world.

## Canonical run

Apparatus revision: `2a3d203`.

Runtime Job: `job-019ffef4-46fa-7142-be20-2046e395a6a6`.

Retained stdout digest: `sha256:0b87b389e041e2ee18a6a355181cc7251a3c4edaaed611a69c19bc7ff98c3ccc`.

Provider: ClamAV 1.5.3, signature database generation 28085 as exposed by `clamscan --version` in this run.

All nine gates pass.

## Four controls

### Known clean

The artifact is observed and hashed, ClamAV returns no match, adjudication chooses `NO_RESPONSE`, and fresh truth retains the active artifact.

### Current EICAR test pattern

Raw observation and detector input bind the same exact bytes. ClamAV reports `Eicar-Test-Signature`. Security records that as a provider classification while explicitly retaining `malwareTruthClaim=false`: the fixture is the harmless EICAR test pattern, not real malware.

The experiment response policy chooses `QUARANTINE_TEST_PATTERN`. The filesystem move receipt remains non-truth. Only fresh inspection establishes active artifact absent plus exact quarantined bytes present.

### Stale alert

ClamAV first detects EICAR bytes. Before adjudication, the active artifact is replaced with known-clean bytes. The old detection remains valid historical evidence, but its bound digest no longer matches current truth. Adjudication returns `STALE_NOT_APPLICABLE` and performs no response.

This independently reproduces the CA2/EC1 pattern on a defensive consumer: integrity-valid evidence may still be inapplicable to the current world.

### Detector unavailable

The raw EICAR test artifact remains observable but the detector is intentionally unavailable to the treatment. Adjudication returns `UNKNOWN_NO_RESPONSE`; uncertainty does not silently grant quarantine authority.

## CA4 results

- `observation != detection`: artifact identity can be observed without a maliciousness/test-signature verdict.
- `detection != truth`: provider signature match is derived evidence with provider/database identity and scope.
- `detection != current applicability`: old alert bytes may differ from the current artifact.
- `adjudication != response`: a decision may authorize no effect, especially under stale or unavailable evidence.
- `response receipt != consequence`: a quarantine move receipt is verified by fresh active/quarantine truth.
- detector failure preserves `UNKNOWN`; it does not create an omniscient Blue fallback.

CA0's role-neutral relation hypothesis again survives: Blue quarantine changes ASSET/CONTROL/OBSERVABILITY relations through the same world-transition grammar rather than requiring separate defensive physics.

## Provider-first result

CA4 did not install Zeek, Suricata, YARA, Velociraptor, osquery or a SIEM merely for coverage. The existing ClamAV detector was sufficient to force the evidence/action boundaries. Additional providers should enter only when a real network/process/endpoint hypothesis requires their native evidence.

Security therefore owns only:

- exact provider and evidence identity;
- information/currentness boundary;
- response admission/scope;
- independent post-condition truth;
- adversarial interpretation.

It does not own antivirus signatures, a detection-rule engine or a SOC data plane.

## Consequence for CA5

CA1-CA4 now provide four materially different consumers: Windows execution carriers, LLVM vulnerability analysis, post-compromise state/authority, and ClamAV defensive detection/response. The next question is empirical rather than architectural preference:

> Did these consumers repeatedly require one missing Security provider-binding abstraction, or did provider-specific adapters plus existing owner contracts already suffice?

CA5 should answer that by code/evidence audit before implementing any gateway.

## Post-closeout executable standing — 2026-08-28

CA4's accepted/falsified research result and source-fenced evidence remain canonical. The one-shot `cli_ca4_defensive_plane.py` experiment runner is retained under `fixtures/archive/runners/` rather than the current package because it has no installed command, current source/research consumer, exact documentation invocation, or current surface claim; its remaining unit test exercised runner-local experiment apparatus. The accepted evidence is indexed by the `2a3d203` receipt. Restoring the runner is an explicit reproduction/new-experiment action, not a current Security capability requirement.
