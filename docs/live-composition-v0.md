# Live component composition v0

## Purpose

This acceptance slice proves that component-owned Link and Edge control planes
can participate in one Security Campaign while Ordivon Runtime holds the live
fixture process. It contains no evaluated Red or Blue Agent.

```text
Security Campaign Ledger
  ├─ Link Security Port → deterministic Network World + observer chain
  ├─ Edge JSONL Control → real local-unshare disposable body + evidence
  └─ Runtime Workspace  → live Link loopback fixture process
```

`ordivon_security_contracts/process_ports.py` and
`ordivon_security_contracts/live_composition.py` together form the reference
P0-C acceptance harness. They are not the Campaign engine, a workflow DSL,
Host, Runtime, or a general process-management library. Their child-process
handling exists only to drive this acceptance composition; production process,
Node, container, and network lifecycle remain owned by Runtime, Edge, and Link.

## Component-owned surfaces

Security consumes, but does not reimplement:

- `link-world-security`, a one-shot JSON CLI owned by Ordivon Link;
- `ordivon_edge_node_control.ts`, a long-lived JSONL session owned by Ordivon Edge;
- the surrounding Ordivon Runtime Workspace Job as the trusted execution substrate.

The Edge surface is deliberately long-lived because lease tokens are
non-persistent and are invalidated when its management process restarts. A
one-shot CLI would either lose the lease boundary or persist bearer authority.
`EdgeJsonLinePort` is the real cross-language JSON adapter used by this
acceptance harness, but it is not a Security-owned Edge protocol or a general
production adapter.

## Live lifecycle

The acceptance runner performs:

```text
declare Edge identity
→ admit Security Campaign
→ bind Link / Edge / Runtime native identities
→ prepare
→ start Link fixture under Runtime
→ execute one real Edge unshare body
→ freeze Edge, stop Runtime fixture, freeze Link
→ reset Edge and Link
→ destroy Runtime fixture, Edge body, and Link World
→ assess residual state
→ reconstruct Link and Edge in fresh roots
→ verify component evidence
→ record final Security outcome
→ export and independently replay a sealed bundle
```

The coordinator orders start as Link → Runtime → Edge and freeze as
Edge → Runtime → Link. This ensures future network-attached bodies cannot begin
before their network fixture exists and cannot continue after the Runtime-held
fixture is withdrawn.

## P0-C evidence scope

For a completed acceptance run, the exact Campaign, Security World, Link World,
Edge Node, Runtime Workspace, source revisions, ledger head, and bundle digest
are recorded in the private output and sealed bundle. Those identified
artifacts support the following P0-C properties:

- one Security Campaign and Security World bind three native component identities;
- the Link World uses its real manifest identity and observer chain;
- the Runtime-held loopback fixture accepts real TCP connections while running;
- the Edge body runs through the real Linux unshare/chroot executor;
- the Edge body has no inherited production credential, writable rootfs,
  `/proc`, `/dev`, or usable network;
- freeze, reset, destroy, reconstruct, and verify operations produce receipts;
- Runtime and Link independently agree that fixture listeners are gone;
- Edge provider bodies are absent while management and evidence journals are
  explicitly retained;
- the final Security outcome is derived only after clean residual accounting;
- the final evidence bundle independently replays the complete ledger.

This document alone does not assert that an unidentified run succeeded. Attack,
defense, escape, and containment claims require the exact Campaign and
environment identity plus authoritative evidence; P0-C executes no evaluated
Agent and makes none of those claims.

## Explicit non-claims

This slice does not prove:

- an Edge body attached to a Link subnet;
- packet-level Link partition, latency, loss, route, or DNS enforcement;
- long-running Edge process freeze/resume;
- Host Task or Game Run integration;
- Red/Blue Agent behavior;
- VM or microVM isolation;
- protection against a compromised host administrator.

The result is a real cross-project lifecycle composition, not yet a real
multi-node adversarial data plane.

## Running the acceptance

The runner accepts exact component-owned executable paths and an output root:

```bash
python3 scripts/run_live_component_composition.py \
  --campaign-template fixtures/campaigns/valid/minimal-owned-range.json \
  --link-manifest-template /path/to/ordivon-link/config/worlds/disconnected-three-service.toml \
  --link-security-executable /path/to/link-world-security \
  --link-world-executable /path/to/link-world \
  --edge-cwd /path/to/ordivon-edge \
  --edge-command=/usr/bin/node \
  --edge-command=--import \
  --edge-command=tsx \
  --edge-command=scripts/ordivon_edge_node_control.ts \
  --output-root /private/output/root \
  --runtime-workspace-id <workspace-id> \
  --runtime-source-revision <commit> \
  --runtime-client-request-id <request-id> \
  --security-source-revision <commit>
```

The output root contains the admitted manifest, Security ledger, component
journals and evidence, the final sealed bundle, and a sanitized
`acceptance-result.json`. It must be private and outside Git.
