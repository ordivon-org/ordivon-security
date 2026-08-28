---
schema_version: 1
id: security.classical-execution-carriers-ca1
title: Classical Execution Carriers CA1
type: experiment
profile: research
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - researcher
  - builder
  - evaluator
  - agent
updated: 2026-08-14
summary: Physical same-effect carrier experiment across native execution, PowerShell, Windows Script Host/VBScript, and Windows Installer, establishing that carrier identity is an orthogonal decision coordinate rather than a semantic effect domain.
evidence_status: verified
readiness: ACCEPTED
applies_to:
  - ordivon-security
related:
  - security.classical-capability-basis-ca0
  - security.windows-kvm-installer-p1
  - security.research-boundary
---
# Classical Execution Carriers CA1

## Question

CA0 retained `carrier/substrate` as an orthogonal capability coordinate but deliberately did not decide when that coordinate deserves Agent attention. CA1 asks the narrower causal question:

> If the semantic effect and payload are held constant, what changes when the same bounded Windows effect is reached through different execution carriers?

The experiment is designed to falsify two opposite errors:

1. treating PowerShell, VBScript, MSI, macro, loader, or a trusted system binary as independent semantic attack effects merely because the carrier name differs;
2. erasing carrier identity completely even when carrier-specific availability, policy, provenance, process lineage, telemetry, latency, lifecycle, or cleanup changes the choice available to an adaptive actor.

CA1 does **not** execute malware, unknown Samples, third-party code, live credentials, or any network-capable payload.

## World and authority

The canonical physical matrix runs on Security source revision:

```text
1ce7d6052b781656734814f7a8098bbe44447802
```

It reuses the accepted P1 derived Windows KVM base:

```text
windows-p1-derived-256fdc6acef0b149.manifest.json
sha256:6bf0726530f587ef9be9724df6538316d5028c57492a10a7993520c16ca02fa9
```

Each treatment receives a fresh disposable Windows world with:

- no NIC;
- `network_mode=deny-all`;
- one maintained benign fixture as the only executable Sample authority;
- `SYSTEM` execution through the existing sealed Guest runner;
- no third-party Sample execution;
- explicit prohibition on network access, credential collection, target expansion, and unknown Sample execution;
- independent QMP/provider lifecycle and residual-closure evidence;
- one verified Evidence Bundle per treatment.

The four worlds differ only in the maintained carrier fixture and run identity. They all materialize the same effect executable once per matrix and require the same marker/evidence consequence.

## Same-effect control

The canonical matrix uses one compiled effect payload across all four treatments:

```text
effectId  = ca1-same-effect-v1
sha256    = sha256:5f9836e4d7068959a0efd49e57e4f8734c6867e09a5adae1d1a703fd6c767b52
byteLength = 19968
```

The payload performs one bounded local consequence:

```text
write exact marker bytes
+ write effect evidence containing process / parent / SID
+ request no network
```

Every treatment must prove:

- exact marker content;
- exact effect payload digest;
- effect evidence exists;
- execution token is `SYSTEM`;
- provider run completes;
- disposable machine residual closure is clean.

Thus a carrier is not credited merely because its outer process exits successfully.

## Treatments

### Native control

The maintained outer fixture launches the same effect executable directly.

Purpose: establish the minimum provider path with no script interpreter or installer lifecycle.

### PowerShell

The outer fixture writes one maintained local `.ps1` and invokes Windows PowerShell with `-NoProfile -NonInteractive -File`.

After a successful positive effect, the same treatment performs one negative carrier-policy probe with `-ExecutionPolicy Restricted`. The negative probe must fail without recreating the marker, after which the positive same-effect state is restored for normal experiment completion.

This probe is deliberately **not** an authority test. PowerShell execution policy remains provider/host policy evidence.

### Windows Script Host / VBScript

The outer fixture writes one maintained local `.vbs` and invokes `cscript.exe` with a bounded command that launches the exact same effect payload and waits for its exit.

WSH is the physical hosted-script contrast in the accepted base because it is present without adding a new application provider.

### Windows Installer

The outer fixture writes one exact maintained MSI and invokes `msiexec.exe` locally with no network source. The MSI installs the exact same effect executable, invokes it through a Type-18 installed-EXE custom action, then the outer fixture uninstalls the product and verifies that the installed payload is removed.

The canonical MSI binds:

```text
ProductCode = {D1C2146B-8AD8-4C5E-B782-F414717A1011}
custom action type = 18
condition = NOT Installed
sequence = immediately after InstallFinalize
```

The installer treatment additionally requires an installer log and successful uninstall as carrier-specific lifecycle evidence.

## Retained falsifiers

CA1 did not proceed directly to a successful matrix. Three materially useful apparatus failures were retained.

### F0 — physical identity can be semantically exact but operationally too long

The first state root encoded the full carrier name into the QMP Unix-socket path. The resulting path exceeded the provider/Unix-socket bound and failed before VM creation.

The Evaluation correctly closed as an invalid Trial with no created machine residuals.

The fix did **not** shorten semantic identity. Physical state directories became compact `c0..c3` navigation identities while full carrier identity remained in Evaluation, fixture, and evidence objects.

Candidate rule:

```text
physical navigation identity != semantic experiment identity
```

### F1 — physical success does not excuse wrong evidence identity

The first full matrix physically completed native, PowerShell, and WSH same-effect execution, but the Guest result emitted a generic fixture ID while each Provider admission expected a carrier-qualified fixture ID.

The Windows KVM backend correctly classified those Trials `windows-kvm-guest-result-invalid` despite the marker having been produced.

The fix was exact identity propagation, not acceptance weakening.

This independently reinforces:

```text
physical consequence != admissible experiment evidence
```

### F2 — provider sequencing is part of carrier applicability

The first MSI used an immediate Type-18 installed-EXE custom action after `InstallFiles`. `msiexec` returned `1603`, produced no semantic marker, and there was no installed product to uninstall.

The Type-18 provider contract requires a non-deferred action whose source file is not already installed to run after `InstallFinalize`. Moving only that provider-specific sequence point produced a successful MSI treatment while leaving the effect payload and semantic objective unchanged.

Therefore:

```text
same effect + available binary != applicable carrier
```

Provider-specific sequencing/preconditions can determine whether a carrier capability is currently available.

## Canonical physical matrix

The final clean-source Runtime Job is:

```text
job-019ffec2-1e26-7700-a421-f969b8547afa
```

The complete external result object is bound by:

```text
sha256:702ffdca8699a0aa1136bc0e3999489a176a91597c6aa22ab361d8164a34af82
```

| Carrier | Result | Same effect | SYSTEM | Carrier evidence | Residual closure |
| --- | --- | --- | --- | --- | --- |
| native | completed | exact | yes | direct baseline | clean |
| PowerShell | completed | exact | yes | `powershell.exe` parent; Restricted negative gate blocked | clean |
| WSH / VBScript | completed | exact | yes | `cscript.exe` parent | clean |
| MSI installed custom action | completed | exact | yes | `msiexec.exe` parent; installer log; install/uninstall lifecycle | clean |

Observed carrier-local elapsed times in this exact matrix were:

```text
native       141 ms
WSH          453 ms
MSI         1750 ms
PowerShell  2407 ms
```

These values are retained as Trial evidence only. CA1 does **not** claim a universal performance ordering from one Windows image and one maintained effect.

All four final Evaluations closed `no-issue-observed`, `benign-fixture-completed`, and `residualClosed=true`.

## What the matrix establishes

### CA1-L1 — carrier is not a semantic effect domain

Four materially different execution paths reached the same exact effect payload and effect identity.

For this consumer:

```text
PowerShell
WSH / VBScript
MSI
native execution
```

are not four different semantic world effects.

They are different realizations of an effect whose operational properties may differ.

This strengthens CA0's separation:

```text
semantic relation transition
!=
mechanism
!=
carrier/provider realization
```

### CA1-L2 — carrier becomes Agent-relevant only through a decision-changing property

The experiment supports a narrower rule than “always expose carrier.”

A carrier deserves projection into the Agent choice surface only when current evidence shows a materially relevant difference such as:

- provider/application availability;
- provenance or trust state;
- policy gate;
- required user/application interaction;
- authority/process lineage;
- telemetry or defender exposure;
- latency or resource cost;
- installed/persistent footprint;
- rollback, uninstall, or cleanup obligation;
- target/platform fidelity or applicability.

If two carrier bindings are equivalent under the current objective, authority, constraints, and opponent evidence, exact carrier identity may remain provider/evidence metadata rather than occupying the semantic action surface.

### CA1-L3 — carrier policy is evidence, not Security authority

The canonical PowerShell treatment demonstrates that a carrier policy can materially change immediate availability: the positive script completed, while the `Restricted` negative probe exited nonzero and left the marker absent.

That does not make PowerShell ExecutionPolicy a Security authorization system. `RangeAuthority` still owns admitted experiment consequence scope.

The distinction is:

```text
Security authority: may this Actor/effect be attempted here?
carrier policy: will this provider/host accept this realization under current configuration?
```

An Agent may need both facts, but they have different owners.

### CA1-L4 — installer lifecycle is real carrier semantics, not a new payload effect

MSI reached the same effect only through provider-owned installation sequencing. It additionally created:

- product/package identity;
- installed-file state;
- installer log evidence;
- install transaction/lifecycle;
- explicit uninstall/cleanup work.

Those properties can change tactical cost, exposure, persistence footprint, and cleanup planning without changing the downstream semantic effect.

The correct model is therefore:

```text
same semantic effect
+ installer-specific applicability/lifecycle/evidence
```

not:

```text
effect = MSI
```

### CA1-L5 — hosted execution creates decision-relevant lineage evidence

The maintained effect observed `powershell.exe`, `cscript.exe`, and `msiexec.exe` as the expected host/parent for those three carrier treatments.

That host lineage can matter to Blue telemetry and policy even when the child effect is identical. Exact process lineage should therefore remain available as evidence rather than being discarded by semantic normalization.

The native-control parent-name heuristic did not match the generic outer fixture filename; this does not affect its exact effect success and is retained as a limitation rather than repaired into a false equality.

### CA1-L6 — Office macro remains a provider-dependent carrier, not a required core primitive

The accepted Windows base reports the Office Word provider absent in every treatment. CA1 therefore did not install Office simply to complete a taxonomy.

External provider documentation shows that VBA execution depends on application presence plus document provenance/trust/policy state, including Mark-of-the-Web and Trusted Location/Publisher decisions. Those are exactly the kinds of carrier properties CA1 now knows how to represent.

A future Office-capable Range may test those properties when a real consumer needs them. No `MACRO` semantic effect is admitted by CA1.

### CA1-L7 — trusted-system-binary proxy execution is mechanism/provenance pressure, not a new effect

Classical security catalogs distinguish use of signed or otherwise trusted system binaries such as `msiexec.exe` to proxy downstream execution because the trusted host can change process/signature policy and detection surface.

CA1 maps that structure as:

```text
semantic effect = downstream transition
mechanism = proxy/abuse existing trusted functionality
carrier/provider = exact trusted system binary
policy/exposure = carrier-specific
```

A future experiment may force a more specific mechanism vocabulary, but CA1 does not add a `LOLBIN` or `PROXY_EXECUTION` effect domain.

### CA1-L8 — stager/dropper/loader labels describe a flow architecture unless a consumer proves otherwise

Classical tool-transfer and execution behavior is naturally expressible as a sequence:

```text
obtain opportunity/reachability
→ transfer or materialize artifact
→ activate through some carrier/provider
→ downstream semantic effect
```

A dropper, loader, stager, or installer may differ materially in footprint, sequencing, control mode, cleanup, and detection surface. CA1 finds no evidence that these labels should become peer semantic effect domains.

Their stable role is currently better represented through action dependency plus carrier/mechanism/control-mode coordinates.

## Build-identity result

A post-matrix reproducibility probe found that MinGW PE timestamps can be removed with a provider-native linker option, while repeated `wixl` builds of the same source still produced different MSI byte digests even with fixed time/package inputs tested in this round.

CA1 does not respond by building an Ordivon MSI compiler.

The experiment already binds exact compiler/builder identity, exact generated payload/MSI digest, exact treatment fixture digest, and exact physical Evaluation identity. Provider-output reproducibility is therefore an applicability/evidence property, not a reason to transfer the provider's file-format mechanics into Security.

## Consequence for the CA0 basis

CA1 does **not** split or add any of CA0's eight current semantic relation coordinates.

Instead it narrows one coordinate:

> `carrier` survives as an orthogonal operational coordinate, but it should be projected to an Agent only when evidence shows that carrier choice changes availability, preconditions, policy, authority lineage, exposure, cost, lifecycle, cleanup, or fidelity for the current objective/opponent.

This is stronger than a tool taxonomy and thinner than a universal execution abstraction.

## What CA1 does not prove

CA1 does not establish:

- general safety or malicious capability of PowerShell, WSH, MSI, or native binaries;
- a universal latency ranking;
- Office/VBA behavior on an Office-capable image;
- browser, archive, shortcut, signed-script, DLL/driver, or firmware carrier semantics;
- general living-off-the-land effectiveness or defense bypass;
- download/staging behavior over a real contested network;
- stealth or detection quality against an EDR/IDS provider;
- malicious loader/dropper behavior;
- Agent tactical superiority from choosing among carriers.

Those claims belong to later provider-specific consumers, CA4 defensive pressure, or CA6 tactical adaptation.

## Next pressure

CA1 has done enough to constrain the world model. Adding more carriers merely for coverage would now be low-information work.

The next independent problem is CA2:

```text
opportunity discovery
!=
exploitability evidence
!=
provider attempt
!=
verified consequence
```

CA2 should test scanners, fuzzers/program analysis, exact vulnerable target revisions, false positives, exploitability proofs, and provider currentness while reusing CA0/CA1's authority/evidence separation.

## Post-closeout executable standing — 2026-08-28

CA1's accepted/falsified research result and source-fenced evidence remain canonical. The one-shot `cli_ca1_carrier_matrix.py` experiment runner is retained under `fixtures/archive/runners/` rather than the current package because it has no installed command, current source/research consumer, exact documentation invocation, or current surface claim; its remaining unit test exercised runner-local experiment apparatus. The accepted evidence is indexed by the `1ce7d60` receipt. Restoring the runner is an explicit reproduction/new-experiment action, not a current Security capability requirement.
