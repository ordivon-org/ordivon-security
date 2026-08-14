---
schema_version: 1
id: security.post-ca-o1-carrier-observability
title: Post-CA O1 — Carrier Observability Under Same Effect
type: experiment
profile: research
lifecycle: accepted
source_role: canonical
visibility: public
owners:
  - ordivon-security
updated: 2026-08-14
summary: Same-effect Windows carrier experiment showing that carrier identity can create decision-relevant Blue telemetry without becoming a semantic capability domain; accepted conclusion is scoped to valid treatments and does not rank universal stealth/loudness.
evidence_status: verified
readiness: ACCEPTED_SCOPED
---
# Post-CA O1 — Carrier Observability Under Same Effect

## Question

CA1 established that native, PowerShell, WSH/VBScript and MSI can realize the same exact benign semantic effect and therefore are not four semantic capability domains. O1 asks the narrower downstream question:

> Can carrier choice still become Agent-decision-relevant because a Blue observer receives materially different telemetry while the payload/effect is held constant?

## Instrumentation

O1 adds two read-only Windows-native Event Log counts to the maintained CA1 probe, identically for every treatment:

- `Microsoft-Windows-PowerShell/Operational` total-event before/after delta;
- `Application` events whose provider is `MsiInstaller` before/after delta.

The probe links only the Windows Event Log API (`wevtapi`) in addition to the existing bounded fixture dependencies. Existing CA1 network-import rejection remains active and every compiled treatment reported `networkImportMatches=[]`.

No Sysmon, EDR, SIEM, third-party Sample, or network capability was added.

## Valid physical evidence

Runtime Job:

```text
job-019fffa8-96ce-7650-8c05-757aa2a070fc
```

Raw private result:

```text
/var/lib/ordivon/security/o1-result.json
sha256:a8d525e3565f62bbc562641ef07a0c051a46e76cb79d55c601b591925aff694e
```

Three treatments completed the exact maintained semantic effect with the same payload bytes, SYSTEM identity and residual closure:

| carrier | effect completed | PowerShell Operational delta | MsiInstaller delta |
| --- | ---: | ---: | ---: |
| native | yes | 0 | 0 |
| WSH/VBScript | yes | 0 | 0 |
| MSI installed custom action | yes | 0 | **8** |

The MSI treatment also retained its existing installer log and uninstall cleanup evidence. This is sufficient to establish the scoped existence claim:

```text
same semantic effect + same payload bytes
can produce carrier-specific Blue telemetry
```

For this exact image/configuration, MSI produced an OS-native event-channel signal that the completed native and WSH treatments did not.

## Invalid PowerShell treatment

The same run observed PowerShell Operational delta `+2`, but the PowerShell carrier itself did not complete within its original 30-second bounded wait. It returned `STILL_ACTIVE`, produced no effect marker/effect evidence, and the Evaluation ended `guardian-runtime-bound-exceeded` with clean residual closure.

Therefore O1 **does not** accept the joint claim that a successfully completed PowerShell realization produces this delta. The observation remains a scoped invalid-trial clue only.

A later full-matrix retry increased the PowerShell wait experimentally, but its first Guest failed to produce any fixture result before the global Guardian bound. That retry was also invalid and cleanly closed; the timeout expansion was reverted rather than promoted into CA1.

## Interpretation

O1 strengthens the CA1 carrier law rather than replacing it:

1. carrier identity remains orthogonal to semantic effect;
2. carrier properties can become Agent-visible when they change observation/exposure or another decision coordinate;
3. Blue event presence remains observation evidence, not maliciousness or consequence truth;
4. one event-channel distinction does not justify a universal `stealth` or `loudness` ranking;
5. missing/invalid telemetry for another carrier is `unresolved`, not evidence of absence.

## Provider admission result

Existing Windows-native telemetry already answered the existence question through the valid MSI contrast. O1 therefore does **not** admit Sysmon, a SIEM, or an EDR dependency merely for coverage. A richer provider should be introduced only if a later consumer specifically requires a distinction that current channels cannot supply.

## Falsifiers and limitations

- one Windows image and one maintained benign same-effect payload only;
- event counts are channel/configuration dependent;
- native `expectedParentObserved=false` in this run shows process-lineage observation itself remains imperfect and should not be promoted into a universal carrier fact;
- PowerShell successful-effect telemetry remains unresolved after invalid trials;
- no malicious Sample or real-world evasion claim is made.
