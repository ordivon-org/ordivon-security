# 目标产品B repack research closeout

Status: **current research cycle closed**
Closeout implementation revision: `f8127d6e840e53108f75b6b730221c75573c94c1`

This document closes the current 目标产品B  Studio  research cycle. It does not create a new execution Authority or Activation.

## What is scientifically closed

### Wrapper to malicious/main MSI reachability

The exact wrapper was observed reaching the exact contained malicious/main MSI. This causal edge is accepted and does not need to be rerun for procedural green status.

### Outer MSI role

Dynamic evidence established the outer 厂商B MSI as a separate wrapper-spawned pre-install prerequisite installer. It is **not** the causal bridge from the wrapper to the malicious/main MSI.

### Post-edge malicious MSI behavior

Direct component execution first failed because the package required bootstrapper context. Supplying only the observed `SETUPEXEDIR` bootstrap context reached the malicious PowerShell custom action. A later bounded zero-NIC trial reached that PowerShell edge and observed no downstream bitsadmin process, new staging file, or matching `OneDriveStandaloneUpdate` task during the bounded window.

The D4 run did **not** directly instrument the first network HEAD request. The accepted interpretation is only that the static ordering plus bounded absence is consistent with failure at or before the first network gate.

## What E2 changed in Ordivon Security

The case forced several general semantics into first-class form:

- Subject, Executor, Execution Context, and Execution Binding are distinct identities.
- Authority, Activation, and Execution are distinct.
- Procedural outcome, containment outcome, and scientific assessment are separate truth domains.
- Reusing a mechanism does not reuse a scientific claim or an Authority.
- Subject dwell, Executor child timeout, Guest instrumentation envelope, and Provider Guardian are distinct clocks.
- Physical canaries remain necessary because unit tests can miss provider/runtime-path failures.
- Stable exact multi-gigabyte execution context belongs in a sealed derived environment rather than being recopied and fully rehashed in every target trial.

The latest additional law is:

> **Environment identity is not Subject projection provenance.**

A bound Subject stored inside an immutable derived environment still requires explicit immutable projection identity in `EvaluationSubjectBinding`.

## E2-B1 loader-causality state

The exact retained product tree was sealed into a derived Windows execution environment and verified by full Host-side readback. A maintained benign Guest boot probe reverified the four key exact identities without launching  or explicitly loading the third-party DLL. A maintained module-load observer canary established `Win32_ModuleLoadTrace` as an admissible exact PID/module-path join mechanism.

The single-use loader Activation was then consumed, but the trial failed **before Windows boot and before any third-party launch** because the bound Subject lacked explicit immutable projection identity in its `EvaluationSubjectBinding`.

The failure is scientifically invalid for loader causality but methodologically productive. The implementation now binds the exact projection digest, while the consumed Activation remains consumed.

Therefore the current B1 cycle closes with:

- Windows boot observed: **no**
-  launch observed: **no**
- replacement `intl.dll` module load observed: **no**
- residual closure: **yes**
- primary loader-causality question resolved: **no**
- automatic continuation authorized: **no**
- replacement Activation authorized by this closeout: **no**

A future loader-causality experiment, if ever justified, is a **new research cycle** with a newly reviewed Authority and single-use Activation. It is not a retry of the consumed cycle.

## Verification state

E2-B1 targeted unit regression: **16/16 passed**.

Full unit discovery executed **355 tests**. **354 passed**. The only error is an external host-tool prerequisite: `/usr/bin/wixl` is absent, so the historical maintained MSI transcript canary cannot be recompiled in the current host tool environment. No test was skipped or weakened to hide this. There were no E2-B1 logic assertion failures.

## Repository integration

The fixed research workspace is intentionally not blindly merged into Security main. At closeout, the workspace and observed Security main are substantially divergent. Integration remains a separate repository-history task and must use explicit lineage analysis rather than merge/rebase by assumption.

## Final boundary

This closeout does not authorize:

- host Windows execution of the repack or replacement DLL;
- network access or live C2;
- downloaded secondary PE execution;
- Case B admission;
- automatic sample reexecution;
- a replacement loader Activation;
- claims that module mapping would prove license success, paid-feature success, or every patch mutation;
- redistribution of replacement DLLs, patch files, or crack recipes.

The current research cycle is closed because its accepted claims, invalid trial, methodological findings, and unresolved scientific question are all explicitly separated and frozen. It is **not** closed by pretending the unresolved loader question was answered.
