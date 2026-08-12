# GVA3 Firelight — contained audit result

Status: **authorized-scope contained research completed; no new reportable finding survived. No external submission was attempted.**

## Bound target

- Competition: Immunefi Firelight Audit Competition (2026 cycle).
- Exact published branch: `v1_audit_ready`.
- Exact resolved revision: `42f9ea5e43d88b35197b901acc2a8c24b314fa62`.
- Exact repository archive SHA-256: `cdfefe2932992829fee4da54131dd5899a679b41c5b62ffdf549df92dfc81b15`.
- Current competition-page snapshot SHA-256: `03b257f1ed48f2212af90938459b6c84e588d21cc237ee7bd5a01b894b05b30f`.
- Prior Macro audit-page snapshot SHA-256: `9ebf7de22df9ad59890ff1ae4808d4041aab09bd66cb10a0e75a2e99016816ce`.
- 14/14 published in-scope Solidity paths were present in the exact revision archive.

The Security Case Snapshot materialized 152 entries under `case:gva3-firelight-42f9ea5e`; its manifest digest is `sha256:9fd9a833688bbb81a4173c4d2fac300898056e71a2f568d6dd365a14444318ce`. Quarantine hardening/audit passed before execution work began.

## Reproducible execution environment

The upstream lockfile contains two Git dependencies pinned to exact commits but expressed through SSH transport. Direct SSH installation stalled in the current network environment. GVA3 did not widen versions or edit the canonical Case. In a disposable execution copy it materialized the same exact dependency commits through HTTP archives:

- `flare-smart-contracts@03ae9c741e364bb5582afdb0dc49726b149c18f7` archive SHA-256 `542a156c29c10bb11ccee91a8ecfcd3ede1a45254c68440c20121b7dcabdb60e`.
- `flare-smart-contracts-v2@0b9038144bdebbbe081c649389a8d8fa4a801875` archive SHA-256 `42ce390b908ec7977b9abfabbc592128132fac823b3c8593866d8cc0d18a783b`.

Hardhat required native Solidity compilers 0.8.23, 0.8.28 and 0.8.29. Each exact compiler artifact was materialized from the official Solidity binary index and verified against the published SHA-256 before use. Compilation and testing then ran inside `bwrap --unshare-net` with no network access.

Results:

- 133 Solidity files compiled successfully.
- 448/448 upstream Hardhat tests passed offline.
- Scoped Solhint produced style/NatSpec/version warnings only; no candidate exploit finding.

## Prior audit and duplicate control

The competition explicitly identifies a Macro audit completed 2026-07-29 and current known-issue exclusions. GVA3 treated those as a duplicate/exclusion set rather than a source of “new” findings.

Macro's report publishes per-file hashes. Against the current 14-file scope, 7 files are byte-identical to Macro's audited inputs and 7 differ. Public branch history shows the Solidity-level audit fixes concentrated on 2026-07-21/22; the only later change before the current head was dependency/audit maintenance plus merge. Macro's report states that the subsequent fixes were reviewed. The present competition therefore behaves as a second-opinion / missed-bug hunt rather than a post-audit code-change hunt.

A batch-settlement liveness/atomicity direction was explicitly rejected as non-novel because it substantially overlaps Macro M-2. Current published known-issue exclusions around the first-loss buffer and aggregate-claims operational assumptions were likewise not counted.

## Independent attacks performed

### Real legacy → V2 upgrade

The repository's ordinary proxy test covers current V2 → a test implementation; GVA3 separately exercised the actual legacy `FirelightVaultPredeposits` → current `FirelightVault` path.

- OpenZeppelin `validateUpgrade` passed.
- A legacy proxy was deployed and populated with deposit limit, user shares, total supply/assets, pending withdrawal assets, period configuration, and admin/rescuer roles.
- `upgradeProxy(..., call: initializeV2)` completed.
- All legacy state compared equal before/after; `contractVersion` advanced 1 → 2; newly introduced payout/incident state remained at its expected zero/false defaults.

No upgrade-layout or migration candidate survived.

### Randomized accounting invariants

A disposable test generated 180 random operations across deposits, withdrawal requests, direct donations, period advances and withdrawal claims. After every operation:

`underlying balance of vault == totalAssets() + pendingWithdrawAssets()`

held.

A second sequence created withdrawals in both exposed future buckets and applied repeated payouts. Aggregate user claimable withdrawals never exceeded `pendingWithdrawAssets`, and the same balance invariant held throughout.

Both independent invariant tests passed.

## Result

No new, non-duplicate, in-scope vulnerability candidate survived the evidence, build, upstream-test, static, upgrade, state-machine and randomized-invariant stages. Accordingly:

- no Immunefi report was created;
- no submission fee was incurred;
- no target outside the exact published code scope was tested;
- no mainnet/public-testnet/third-party system was touched;
- no payout is claimed.

This is a **negative audit result**, not proof of absence of vulnerabilities. It is also a resource-allocation result: after the exact environment, 448-test baseline, prior-audit de-duplication, upgrade experiment and randomized invariants all remained clean, the marginal expected value of continuing the same search strategy fell materially. A later campaign should return only with a new hypothesis/tool/channel rather than spending more tokens on the same surface.
