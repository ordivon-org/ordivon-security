---
schema_version: 1
id: security.windows-kvm-recovery-p0.1
title: Windows KVM Recovery P0.1
type: specification
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners:
  - ordivon-security
audience:
  - maintainer
  - evaluator
  - agent
updated: 2026-08-06
summary: Crash-recoverable Windows KVM Run ledger and explicit orphan reconciliation beyond the controlled-cancellation P0 gate.
evidence_status: partial
readiness: CANDIDATE
applies_to:
  - ordivon-security-evaluation
related:
  - security.windows-kvm-p0
  - security.evaluation-trial-p0
  - security.authority
---
# Windows KVM Recovery P0.1

P0.1 extends the closed benign-only P0 lifecycle without broadening Sample admission. Every newly created Windows KVM Run writes an atomic private ledger under the root-owned `run-ledgers/` authority. The ledger binds the exact Run, base environment, Evaluation Spec, owner process identity, resource paths, QEMU/swtpm process identities, and lifecycle phase. It is deliberately outside the QEMU-writable Run directory.

The explicit `ordivon-security-windows-kvm-reconcile` command scans the private Run root after a hard process or Runtime failure. It:

- skips a Run when the exact owner PID and process start time are still alive;
- terminates QEMU and swtpm only when PID, start time, and command identity agree;
- removes an orphan Run only after both process identities close;
- leaves missing, unsafe, or process-identity-inconclusive Run state untouched and writes an attention-required diagnostic instead of guessing;
- removes only exact orphan `ordivon-benign-v1-run-<index>.exe` compilation files when no matching acceptance process is active;
- writes a private reconciliation receipt.

The owner-process SIGKILL gate passed from revision `bcac3cc`: the Run was killed after the root-owned ledger reached `executing`, and reconciliation closed QEMU, swtpm, the Run directory, the ledger, and Fixture state with zero residuals. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p01-bcac3cc.json`](../evidence/acceptance/windows-kvm-p01-bcac3cc.json).

The Runtime service restart gate also passed from revision `7b027f0`: the root ledger was captured in `executing`, the Runtime control plane restarted three seconds later, and the active attempt completed the benign Fixture thirty seconds after the restart with QMP network-device count zero and full residual closure.

This stage does not authorize unknown Samples or third-party installers. It remains **candidate** because WSL shutdown recovery is still pending.
