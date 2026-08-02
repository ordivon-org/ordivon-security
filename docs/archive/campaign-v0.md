# Campaign v0 historical reproduction

Campaign Manifest, lifecycle ledger, coordinator, evidence-bundle, process-port, and live-composition code left the active Security package because no current experiment or external repository consumed it. The final complete source remains immutable at:

```text
36ce116c8de9df492946a04b710b6fe71aef901a
```

Reproduce the historical Round 1 acceptance without restoring the platform to current `main`:

```bash
git worktree add /tmp/ordivon-security-campaign-v0 36ce116c8de9df492946a04b710b6fe71aef901a
cd /tmp/ordivon-security-campaign-v0
./scripts/run_round1_acceptance.sh
```

The historical reports are:

- `docs/round1-experimental-results.md`;
- `docs/round1-full-experimental-report.md`.

The current `scripts/run_round1_acceptance.sh` intentionally refers to the active adversarial experiment layer and is not a compatibility alias for Campaign v0.

## Why this archive entry remains

It preserves the ability to challenge or reproduce a published historical conclusion while keeping roughly seven thousand lines of unconsumed infrastructure out of active imports, CI, and maintenance. Delete this page only when the historical report itself is removed or a durable external archive carries the exact revision and reproduction command.
