---
schema_version: 1
id: security.windows-kvm-installer-p1
title: Windows KVM Installer Evaluation P1
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
  - researcher
  - agent
updated: 2026-08-06
summary: Separate large-Sample Windows installer profile using exact Case identity and a QEMU-read-only NTFS input disk.
evidence_status: partial
readiness: CANDIDATE
applies_to:
  - ordivon-security-evaluation
related:
  - security.windows-kvm-p0
  - security.windows-kvm-recovery-p0.1
  - security.case-snapshot-p0
  - security.authority
---
# Windows KVM Installer Evaluation P1

P1 is a separate profile. It does not widen `execute-benign-fixture` and cannot reuse the P0 Authority.

P1's closed execution fields are **stage-profile rules**, not a constitutional statement that unknown or high-risk software can never execute. The current stage proves preparation, identity, observation prerequisites, and authority separation while intentionally making third-party execution impossible. A later owned/authorized isolated research profile may admit execution when it preserves the constitutional authority, truth, causal, and recovery invariants described in [`LAW-PROFILES-C0.md`](LAW-PROFILES-C0.md).

The first implemented gate is media preparation only:

1. bind an exact Case, archive SHA-256, byte length, logical name, deny-all network mode, no-restart policy, and observation profile;
2. create an NTFS image sized from the exact source length;
3. copy the archive into the image;
4. stream the embedded file back through `ntfscat` and verify its SHA-256 and length;
5. verify the source did not change during preparation;
6. bind the exact Security source identity and SHA-256 identities of `mkntfs`, `ntfscp`, and `ntfscat`;
7. seal a private manifest with the preparation identity digest, media digest, and QEMU attachment arguments;
8. require `readonly=on`, `removable=on`, and serial `ORDIVON_P1`.

The retained DaVinci profile at `research/cases/windows-kvm-p1-davinci-resolve-studio-21.0.3.7.json` authorizes only `prepare-authorized-windows-installer-media`. The current media gate passed from revision `136a8a7`: the exact 7,428,655,207-byte archive was embedded in an 8 GiB NTFS image, streamed back with the same SHA-256, bound to a QEMU-read-only topology, and tied to the Security revision plus SHA-256 identities for `mkntfs`, `ntfscp`, and `ntfscat`. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-davinci-media-136a8a7.json`](../evidence/acceptance/windows-kvm-p1-davinci-media-136a8a7.json). The earlier `bcac3cc` media is retained only as a superseded pre-provenance record.

`executionAuthorized` remains false, so neither the archive nor any contained installer may be attached to a Guest or executed yet.

Later execution requires a new admitted Guest observation protocol, an exact installer path and arguments, pre/post system snapshots, real residual closure, and a separate acceptance decision.

## Static entry decision

The retained static decision at [`../research/cases/windows-kvm-p1-davinci-static-entry.json`](../research/cases/windows-kvm-p1-davinci-static-entry.json) rejects generation of an executable profile for the current Case. It binds the archive, wrapper, outer MSI, nested GetintoWAY MSI, embedded downloader script, replacement `intl.dll`, and main `Resolve.exe` identities.

The original rejection remains correct, but the R2 causality re-assessment sharpens the attack model into two independent branches rather than pretending the package is one continuous proven chain.

The **ordinary wrapper installation path is statically bound**:

- the wrapper's 312,380-byte PE overlay contains one configured prerequisite action, `SetupFile=DaVinci Resolve\\DaVinci.msi` with `CommandLine=/qr`;
- the outer MSI binds the 152,576-byte unsigned replacement `intl.dll`, the 20,848-byte `intl_original.dll`, and `Patches.txt` to `ResolveFeature` under `INSTALLATIONDIR`;
- the replacement DLL exports the expected `libintl` proxy surface, references `intl_original.dll`, imports `VirtualProtect`, and contains `Patches.txt`, `Resolve.exe`, offset-regeneration, and in-memory patch logic;
- the observed `Resolve.exe` import table does not directly import `intl.dll`, so the exact runtime loader remains a separate question.

The package also contains a **malicious nested branch**. `DaVinci Resolve.7z` contains exactly one unsigned GetintoWAY MSI whose first-install chain still independently verifies:

- `AI_DATA_SETTER` at sequence 6401;
- `PowerShellScriptInline` at sequence 6402;
- download from `corehubpro.com` through BITS or `System.Net.WebClient`;
- extraction of the downloaded ZIP;
- highest-privilege `OneDriveStandaloneUpdate####` scheduled-task creation;
- execution of every EXE found in the downloaded archive.

However, the same R2 re-assessment found no literal reference to the nested archive, nested MSI, downloader URL, or PowerShell chain anywhere in the outer MSI database, and the wrapper overlay lists the nested archive as a distributed file rather than as its configured `SetupFile`. `chainComplete` therefore remains false for a sharper reason: **the malicious nested MSI is real, but ordinary wrapper-to-nested-MSI reachability is not established**. We do not manufacture that missing edge merely to make the attack graph look continuous.

This does not reverse product rejection. The primary path already installs an unsigned runtime patch engine in place of the signed control DLL, and the distribution separately contains a first-install downloader MSI. The original static gate passed from revision `91f08e0`; the later sanitized causality index is [`../evidence/acceptance/windows-kvm-p1-davinci-causality-r2.json`](../evidence/acceptance/windows-kvm-p1-davinci-causality-r2.json).

## Observation contract

Future third-party installer execution requires the canonical profile at [`../research/profiles/windows-kvm-installer-observation-p1.json`](../research/profiles/windows-kvm-installer-observation-p1.json). It requires pre/post snapshots for files, Registry, services, drivers, scheduled tasks, BITS jobs, startup entries, installed products, users/groups, certificates, Defender, and Event Logs. It also requires a complete process tree, PowerShell script-block evidence, MSI and Task Scheduler events, QMP topology authority, host media identity, and residual closure.

The observation contract is evidence infrastructure only. It does not change `executionAuthorized`, bind an installer path, attach the current media, or start Windows.

## DaVinci Case closeout

The current DaVinci package is closed as **rejected**, not promoted to an execution Trial. Independent table-level verification reproduced the wrapper identity, the original and replacement `intl.dll` entries, the nested GetintoWAY MSI, first-install sequences 6401 and 6402, the external downloader, BITS/WebClient transports, highest-privilege scheduled-task creation, and recursive execution of downloaded EXE files.

The final sanitized Case index is [`../evidence/acceptance/windows-kvm-p1-davinci-case-closeout-bf272ab.json`](../evidence/acceptance/windows-kvm-p1-davinci-case-closeout-bf272ab.json). That closeout originally claimed complete media removal, but a later state-root audit found one manifest-bound non-executable 8 GiB image still present. The corrected residual authority is [`../evidence/acceptance/windows-kvm-p1-davinci-residual-correction-r0.json`](../evidence/acceptance/windows-kvm-p1-davinci-residual-correction-r0.json). No installer or contained component was executed to reach the original static decision.

This closes the **ordinary installation admission** for the current DaVinci package. It does not erase the package or prohibit a separately authorized isolated research Trial. Product admission and research admission are different authorities.

## Isolated research admission

The separate contract at [`../research/cases/windows-kvm-p1-davinci-isolated-research-trial.json`](../research/cases/windows-kvm-p1-davinci-isolated-research-trial.json) retains the static product rejection while admitting staged research. Its first action is `verify-read-only-sample-media`:

1. rebuild the exact provenance-bound NTFS media;
2. attach it to a disposable Windows Guest with QEMU `readonly=on` and `removable=on`;
3. execute only the locally compiled `ordivon-readonly-media-verifier-v1`;
4. stream and SHA-256 the exact 7,428,655,207-byte archive from Windows;
5. require a failed write probe with Windows write-protect or access-denied semantics;
6. require QMP authority showing no network-class device;
7. record that no contained EXE, MSI, DLL, script, or archive entry was executed;
8. require complete residual closure.

The `ordivon-security-windows-kvm-p1-readback` command implements this first research Gate. It does not reverse the package rejection and does not yet admit third-party execution. Later Gates may execute the original package or a backdoor-removed derived Case only after the generic installer observer is implemented and independently admitted.

P1 remains a candidate infrastructure track: the read-only media verification backend is implemented; the observer resource and Case authorities are implemented below; generic third-party execution and process-tree orchestration remain pending.

## R0 correction: residual closure

The earlier Case closeout claimed that all prepared P1 media had been removed. A later
state-root audit found one 8 GiB `prepared-not-executable` NTFS image under the separate
`windows-kvm-p1` root. The image and manifest were re-verified, removed, and recorded by
[`../evidence/acceptance/windows-kvm-p1-davinci-residual-correction-r0.json`](../evidence/acceptance/windows-kvm-p1-davinci-residual-correction-r0.json).
The original closeout remains historical evidence; it is not treated as proof of residual
closure without this correction.

## R1: deployment and evaluation are separate authorities

P1 now distinguishes:

- `deploymentAuthorized`: permission to deploy or use a product outside the experiment;
- `evaluationAuthorized`: permission to execute exact components in a disposable evaluation;
- `hostObservationAuthorized`: permission to inspect an existing host baseline read-only;
- `hostModificationAuthorized`: permission to modify the host.

The current P1 model rejects product deployment and host modification. It can authorize
bounded evaluation in disposable Windows KVM and read-only observation of the existing
Windows host baseline. The legacy `executionAuthorized` field remains only as an alias for
isolated evaluation authority.

## R2: observer implementation

`resources/windows_kvm/p1-observer.ps1` now implements bounded pre/post collection for
files, Registry startup state, services, drivers, scheduled tasks, BITS jobs, installed
products, users/groups, certificates, Defender state, Event Logs, and network adapters.
The base-image builder binds and copies this observer into sealed images. An
observer-enabled Windows 11 Enterprise Evaluation base was built and accepted from
revision `1367c76`; the Guest ready receipt names
`C:\ProgramData\Ordivon\p1-observer.ps1`, the observer digest is
`sha256:efeb283d513bfa9f59b4869b1b3385dad881013d64cfe65d3344c864879753d0`,
and QMP recorded zero network devices. The sanitized acceptance index is
[`../evidence/acceptance/windows-kvm-p1-observer-base-1367c76.json`](../evidence/acceptance/windows-kvm-p1-observer-base-1367c76.json).
Process-tree orchestration and the third-party execution backend remain unadmitted.

## R3: Case A, B, and C

| Case | Surface | Current state |
| --- | --- | --- |
| C — installed Resolve Free 21.0.3.7 control | existing main Windows host, read-only | signed executable and official `intl.dll` identities captured before and after without change |
| A — original repack | disposable Windows KVM | mandatory environment transformation manifest binds read-only media, deny-all egress, local record-only FakeNet, secondary-EXE blocking, and overlay destruction; runner still required |
| B — deweaponized derived payload | main Windows controlled-evaluation surface | exact `intl.dll` and `Patches.txt` privately rematerialized; pre/post observer and explicit host-write Gate required before any installed file changes |

Case A's transformation manifest changes the environment while preserving the original Sample bytes. Case B's payload manifest records what was removed and retained, but the materializer refuses `/mnt/*` destinations and cannot deploy to Windows. R3 therefore establishes the comparison topology and evidence inputs without changing the main Windows installation. Case C is labeled Free from the user's declaration; feature-level behavior remains a later comparison Gate.

The host baseline can be reproduced with `ordivon-security-windows-host-p1-baseline`. Its public acceptance index binds the private receipt digest and verifies that `Resolve.exe` and the signed official `intl.dll` were stable before and after collection.


## R4 architecture decision: one controller/orchestrator Runner

**Status: selected; execution contract, read-only media materializer, Controller canary, and selective staging execution control are accepted; sealed Controller/base integration and Case execution remain pending.**

P1 will use one Runner architecture:

```text
WindowsKvmEvaluationBackend
  → exact Case/run binding
  → thin sealed Guest Runner dispatcher
  → generic sealed native controller
  → declarative PowerShell orchestrator
  → Observer artifacts and writable result media
```

The earlier inline Guest Runner prototype and the Case-specific native-launcher prototype are rejected as implementation directions. Their uncommitted states are retained only in the private prototype backup under `/root/backups/ordivon-security-case-a-prototypes-20260806/`; neither prototype defines current behavior.

### Responsibility split

- The host Provider owns Case admission, media identity, disposable overlay and UEFI-variable creation, QMP topology, the outer runtime bound, forced VM termination, Artifact extraction, and residual closure.
- `guest-runner.ps1` remains a small dispatcher. It validates the action class and transfers control; it does not inline installer extraction, network recording, process polling, or Case-specific policy.
- One reproducibly built native controller is sealed into a later P1 base. It validates the exact run binding, places the directly launched process tree in a Windows Job Object, owns controller timeout and cancellation, and emits a bounded controller result. It is generic P1 infrastructure rather than a DaVinci-specific launcher.
- A declarative PowerShell orchestrator owns pre/post Observer invocation, bounded event collection, overlay-local name redirection, a record-only loopback connection sink, installer invocation, and result assembly. It is evidence collection and orchestration, not management-plane authority.
- Process polling may enrich evidence but cannot be a Guardian. Blocking of known secondary staging roots requires an admitted Windows execution-control policy plus a pre-run canary; a WMI/CIM polling loop alone cannot satisfy the transformation manifest.

### Media topology

Case A execution will use four distinct state surfaces:

1. the exact original archive on `ORDIVON_P1`, attached read-only for provenance;
2. a host-materialized extracted execution view on a separate read-only NTFS medium, bound by a complete tree manifest and extraction-tool identity;
3. a writable `ORDIVON_RUN` medium used only for the run manifest and returned evidence;
4. a disposable qcow2 overlay and per-run UEFI variables, both destroyed after closure.

The host-prepared extracted view removes Guest 7-Zip from the trusted execution path. It does not change the original archive bytes. Transformation manifest revision 2 records `host-materialize-read-only-execution-tree` as an explicit additional environment transformation.

### R4-A contracts and materializer

The retained contract at [`../research/cases/windows-kvm-p1-davinci-case-a-execution.json`](../research/cases/windows-kvm-p1-davinci-case-a-execution.json) binds the exact Case manifest, transformation manifest, original archive, wrapper path, wrapper SHA-256 and byte length, observation profile, and required controls. It authorizes only Host-side materialization. It explicitly retains:

- `controllerAdmitted: false`;
- `executionAuthorized: false`;
- `hostModificationAuthorized: false`;
- `exportableArtifact: false`.

`ordivon-security-windows-kvm-p1-materialize-execution-media` implements the materialization gate. Before extraction it validates the 7-Zip technical inventory, rejects unsafe Windows paths, case-insensitive collisions, symbolic links, reparse entries, and declared hard links. After extraction it uses `lstat` to reject links, special files, and multiply linked files; strips Host execute permissions; computes a complete sorted tree manifest; and verifies the exact admitted wrapper identity.

The materializer writes the tree to an NTFS image through a private `nodev,nosuid,noexec` mount, unmounts it, remounts it read-only, and rehashes the complete payload plus the retained tree manifest. A successful result is `materialized-not-admitted`: the manifest declares QEMU read-only arguments but keeps `qemuAttachmentAuthorized`, `controllerAdmitted`, and `executionAuthorized` false.

A benign two-file canary completed archive listing, Host extraction, NTFS population, read-only remount, full digest readback, unmount, and cleanup. Its sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json`](../evidence/acceptance/windows-kvm-p1-case-a-execution-media-canary-6c141b9.json). The actual Case A archive was not materialized or executed by that canary.

### R4-B Controller and execution-control canary

`p1_controller_canary.c` is an Ordivon-maintained, locally compiled Windows PE used only as a disposable no-network canary. It exercises three separable facts before any third-party installer execution is admitted:

- a directly launched child and its descendants are accounted inside one Windows Job Object;
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates both the owned root and a live descendant when controller ownership closes;
- `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` with a limit of one prevents a maintained secondary executable from completing.

The canary deliberately reports `selectiveSecondaryBlocking: false`. The active-process limit is therefore **not** the Case A execution-control policy: it blocks all additional descendant processes and would also reject legitimate installer subprocesses. Its value is narrower: it proves the kernel-level process-tree ownership and broad blocking primitives work in the accepted Windows base, while falsifying the idea that a simple process-count limit can satisfy `block-unknown-secondary-executable-launch`.

The first physical working-tree trial exposed an over-strong canary assertion that required Job accounting to report zero active processes immediately after the root child became signaled. The same trial independently showed descendant accounting, kill-on-close for root and descendant, broad secondary blocking, no QEMU network device, and clean residual closure. The assertion was corrected so process-tree ownership is established by successful child completion, descendant evidence, and Job total-process accounting; residual termination remains owned by the separate kill-on-close gate. A second working-tree trial passed all three canary gates with clean residual closure. The implementation was then committed at `e011541` and reproduced from that exact clean revision: all three Controller gates passed, QMP reported zero network devices, the Provider reported no error, and residual closure was clean. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-controller-canary-e011541.json`](../evidence/acceptance/windows-kvm-p1-controller-canary-e011541.json).

Case A remains non-executable until a **selective** Windows execution-control canary can allow required installer/system subprocesses while denying the declared secondary staging surface, and until the Controller is sealed into a new P1 base.

### R5 selective staging execution control

The exact retained downloader script was re-read from the Case source and re-verified at 2,910 bytes with SHA-256 `fe335766b60b18bfc4890e832a1dfff1e8d0b44bd0aa6059206f34cf7081c397`. Its relevant runtime surface is concrete rather than hypothetical: it creates `%TEMP%\\DaVinci Resolve`, downloads `packagecache_x64_data.zip`, expands the archive into that directory, recursively enumerates `*.exe`, registers each discovered executable as a highest-privilege scheduled task, and starts it. R5 therefore tests only whether the disposable environment can keep that staging tree writable while preventing PE execution from the tree.

An AppLocker blocklist prototype was physically rejected. After correcting the policy XML and adding stage-by-stage evidence, the canary ran as `NT AUTHORITY\\SYSTEM` (`S-1-5-18`), with `Everyone` and `BUILTIN\\Administrators` present in the token. The local policy appeared in the effective policy, but `Test-AppLockerPolicy` returned `AllowedByDefault` for both the allowed and staging-path executables; the staging executable then ran to exit code zero, wrote its marker, and produced no AppLocker deny event. The prototype is therefore not an admitted Guardian for this SYSTEM execution surface.

The narrower candidate uses an NTFS deny ACE for `FileSystemRights.ExecuteFile`, scoped to the exact execution identity and configured with container/object inheritance plus `InheritOnly`. It deliberately does **not** deny write access. One working-tree physical trial against the accepted Windows Enterprise base then established all of the intended contrasts: root and nested text writes succeeded; newly copied PE files at both the staging root and a nested directory inherited the execute deny; the maintained PE outside the staging tree executed successfully and wrote its marker; both staging-tree PE launches were denied before their markers could be written; QMP reported zero network devices; and residual closure was clean.

The implementation was committed at `fe72177` and reproduced from that exact clean Security revision. The accepted run used the same `NT AUTHORITY\\SYSTEM` (`S-1-5-18`) execution identity: root and nested writes remained available, PE files at both staging levels inherited the execute deny, the maintained executable outside the staging tree completed with exit code zero and wrote its marker, both staging-tree launches were denied before their markers could be written, QMP reported zero network devices, the Provider reported no error, and residual closure was clean. The sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-execution-control-canary-fe72177.json`](../evidence/acceptance/windows-kvm-p1-execution-control-canary-fe72177.json).

R5 therefore accepts this **sample-specific environmental transformation**, not a general malware sandbox. Code with authority to rewrite its own ACLs, execute from another path, inject into an already-running process, or use another untested execution mechanism is outside this gate's claim. R5 also does not establish runtime reachability to the malicious nested MSI and does not authorize Case A; the next gate is to seal the generic Controller and this execution-control substrate into a newly accepted P1 base.

### R6-A: generic Controller

R4-B proved the native Windows Job Object primitives with a Controller **canary**, but that executable was intentionally self-testing and Case-independent only in the sense that it did not launch DaVinci. R6-A therefore did not seal the canary as if it were production infrastructure. It extracted a narrower generic Controller whose production target is fixed to the future sealed `C:\ProgramData\Ordivon\p1-orchestrator.ps1`; there is no arbitrary executable target argument. The Controller accepts only a bounded run identity, exact manifest path and SHA-256, result path, and timeout; it hashes the manifest itself with Windows BCrypt before creating the orchestrator process suspended, assigning it to a kill-on-close Job Object, and resuming it.

The Controller has one maintained self-test path so the production binary itself can be evaluated before the orchestrator exists. From exact Security revision `e352e86`, a fresh Runtime Workspace compiled and executed that self-test in the accepted no-NIC Windows base. The run independently verified manifest SHA-256, normal child ownership/completion, a second child reaching the Controller timeout, Job termination of that child before its marker could be written, QMP zero-network-device truth, and residual closure. The exact accepted 25,600-byte PE is retained in the root-only Sample Vault with SHA-256 `eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a`; the sanitized acceptance index is [`../evidence/acceptance/windows-kvm-p1-generic-controller-e352e86.json`](../evidence/acceptance/windows-kvm-p1-generic-controller-e352e86.json).

R6-A deliberately binds that exact PE identity rather than claiming that recompiling the same C source reproduces the same bytes: two observed builds from the same source/compiler produced different executable digests. The next sealing gate must therefore copy the accepted Vault object, not compile a new Controller during image derivation. R6-A still does not exercise the production orchestrator path and does not authorize Case A.

### Network boundary

QEMU continues to expose no network-class device. Known destinations may be redirected inside the disposable Guest to a loopback-only, record-only TCP sink so connection attempts can be counted. The sink does not proxy traffic, decrypt TLS, emulate the remote service, or return executable content. QMP remains authoritative for absence of external network capability.

### Admission sequence

Implementation proceeds through separate gates:

1. contracts and read-only execution-media materialization;
2. native-controller and execution-control canary tests using maintained fixtures only;
3. a newly sealed P1 controller base and independent acceptance;
4. one bounded Case A dynamic Trial;
5. repeated-run and injected-failure residual closure.

No Case A installer execution is authorized by this decision alone. Case B remains blocked until Case A has accepted dynamic evidence and residual closure.
