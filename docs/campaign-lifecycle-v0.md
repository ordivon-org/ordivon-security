# Campaign lifecycle v0

## Purpose

Campaign lifecycle v0 is the minimum independent authority and evidence plane
for a disposable Ordivon Security range. It is intentionally narrower than a
workflow engine or a second Host.

It owns:

- one admitted Campaign Manifest;
- an append-only, hash-chained Security lifecycle ledger;
- immutable bindings from Security identities to component-native identities;
- fixed prepare, start, freeze, reset, destroy, reconstruct, and verify operations;
- explicit unknown-result reconciliation;
- residual-state classification;
- bounded one-way evidence export and deterministic replay.

It does not own Link network truth, Edge Node state, Runtime Jobs, Host Tasks,
or Game Runs. Those components remain authoritative for their native objects.

## Identity model

Security and component identities are related but not interchangeable:

```text
Security Campaign ID
Security World ID
        │
        ├─ Link binding    → Link World ID + observer head
        ├─ Edge binding    → Edge Node ID + identity digest
        ├─ Runtime binding → Workspace / Job / Attempt identity
        ├─ Host binding    → Goal / Task identity
        └─ Game binding    → Run ID + replay digest
```

A `ComponentBinding` contains both semantic identities and one immutable native
identity snapshot. Reconstructing a component must reproduce the same binding
digest; a different revision, root digest, native ID, or metadata fails the
reconstruction operation.

## Authority ledger

The ledger stores one immutable JSON event per file:

```text
ledger/
├── manifest.json
├── .ledger.lock
└── events/
    ├── 00000000000000000001.json
    ├── 00000000000000000002.json
    └── ...
```

Each event binds:

- Campaign and Security World identity;
- monotonic sequence;
- real UTC timestamp;
- actor identity;
- event kind and optional operation identity;
- canonical data;
- previous event hash;
- event hash.

The first event is always `campaign_admitted`. Every projection is rebuilt from
the admitted manifest and complete event chain. Materialized projections are
not persisted as a second source of truth.

The file lock serializes writers. Event files are written through a private
staging file, `fsync`, and atomic rename. Existing event paths are immutable.

## Campaign phases

```text
admitted
  ├─ preparing → ready → running → frozen → ready
  ├───────────────────────────────→ destroyed
  └─ invalid ─────────────────────→ destroyed
```

Emergency destruction is allowed directly from admitted, preparing, ready, or
running state. A final outcome cannot be recorded until the Campaign reaches
`destroyed`; cleanup and residual inspection therefore remain possible after
an experiment failure or observer loss.

## Operation state

Lifecycle operations use a separate state machine instead of expanding the
Campaign phase enum:

```text
prepared
  ├─ dispatched → succeeded
  │             ├─ failed
  │             └─ unknown → reconciling → succeeded | failed | unknown
  └─ failed
```

The coordinator persists `prepared` and `dispatched` before invoking a native
component port. A lost response becomes `unknown`. Reconciliation queries the
original component-native operation identity; it never authorizes a new
physical dispatch.

Supported fixed operations are:

- `prepare`;
- `start`;
- `freeze`;
- `export`;
- `reset`;
- `destroy`;
- `reconstruct`;
- `verify`.

No user-defined DAG, loop, scheduler, or arbitrary lifecycle command exists.

## Component ports

`ComponentPort` is a narrow Python protocol over existing component contracts:

```text
snapshot(campaign_id, world_id)
execute(operation, operation_id)
reconcile(operation, operation_id)
residual_checks()
```

Concrete adapters must live with, or directly wrap, the native component
contract. The Security repository does not implement a shadow Link controller,
Edge Node runtime, Runtime Job system, Host journal, or Game replay database.

The current repository provides the authority, coordination, and conformance
boundary. The P0-C acceptance harness now includes a real cross-language
`EdgeJsonLinePort` that consumes the component-owned
`ordivon_edge_node_control.ts` long-lived JSONL surface. This corrects the
earlier assumption that no real Edge JSON adapter was available. The adapter
remains acceptance-only: it neither defines a new Edge protocol nor transfers
Edge Node or process authority into Security.

## Receipt, attestation, and Host binding terminology

Phase 0 freezes only the minimum cross-component meaning of these terms, not a
JSON shape, public Protocol, or signature scheme. A **Component Receipt**
semantically carries:

- the issuing component identity;
- the exact Security operation identity and operation kind;
- the component-native result or disposition;
- the native subject identity or the binding through which it is resolved;
- an integrity digest and native evidence or journal reference.

The surrounding Security ledger may supply Campaign, World, actor, and recorded
time context; a native receipt need not duplicate that context. A
**Component Attestation** is an identified component or authority statement
over an exact receipt, binding, or evidence digest. Its minimum meaning is the
attester identity and role, exact subject identity and digest, typed predicate,
verdict, evidence references, and issuance context. Phase 0 specifies no
signature format, key lifecycle, or trust infrastructure.

The **Host Binding** direction is Security Campaign plus Security Actor toward
a Host-owned Agent/Goal/Task identity, revision, and evidence root. Security
consumes the Host-issued identity snapshot or receipt and records an immutable
binding; it does not create Host objects, copy Goal/Task/Context state, or mint
replacement Host identities. These terms are documentation constraints only
and do not change the current Schema or component protocols.

## Independent observer loss

Observer availability is orthogonal to experiment success or failure.

When a port raises `ObserverUnavailableError`:

1. the lifecycle operation becomes `unknown`;
2. a separate `observer_unavailable` event is admitted;
3. later infrastructure outcome classification becomes `observer_loss` with
   `inconclusive` evidence quality;
4. freeze, destroy, and residual cleanup may continue through independent
   management paths.

The system never converts missing observation into guessed success, guessed
failure, or clean residual state.

## Residual state

Residual checks have five possible statuses:

- `clean`;
- `expected_retained`;
- `unexpected_residual`;
- `unknown`;
- `observer_unavailable`.

The report classification is derived rather than caller-selected:

```text
unexpected_residual present  → residual_failure
unknown or observer loss     → inconclusive
otherwise                    → clean
```

Expected retained observer history does not make a disposable world dirty.
Uninspectable state never becomes `clean`.

## Evidence bundle

Evidence export is bounded and one-way. It writes a private staging directory,
seals every listed file by SHA-256, and atomically renames the complete bundle
into place.

```text
bundle/
├── bundle-manifest.json
├── bundle-seal.json
├── campaign/
│   ├── manifest.json
│   ├── events.json
│   ├── projection.json
│   ├── bindings.json
│   └── residual-report.json   # optional
└── components/                # optional bounded attachments
```

Exported bytes are never executed or interpreted as lifecycle commands.
Attachment paths cannot escape the bundle or replace Campaign control files.
The verifier checks:

- exact listed versus physical file set;
- every byte length and SHA-256 digest;
- bundle manifest and seal;
- admitted Campaign identity;
- complete event hash chain;
- deterministic projection replay;
- projection head and revision.

An existing valid destination is idempotently reused only when its bundle
identity matches.

## Outcome precedence

`finalize_infrastructure_outcome` derives one infrastructure classification:

1. observer unavailable → `observer_loss`;
2. unexpected residual state → `containment_failure`;
3. failed lifecycle operation → `invalid_run`;
4. unresolved operation → `inconclusive_evidence`;
5. otherwise → `success`.

This is infrastructure closure, not a Red/Blue objective score. Agent-specific
outcomes remain governed by the Campaign Manifest judge contract.

## Inspection

Verify a live ledger without mutation:

```bash
python3 scripts/inspect_campaign_ledger.py /path/to/ledger
python3 scripts/inspect_campaign_ledger.py /path/to/ledger --events
```

Verify and replay an exported bundle:

```bash
python3 scripts/verify_evidence_bundle.py /path/to/bundle
```

Run all conformance and fault-injection tests:

```bash
python3 -m unittest discover -v
```

## Proven fault cases

The test suite covers:

- event-byte tampering;
- invalid operation transitions with no partial write;
- immutable manifest and component binding identity;
- one destroy response lost after native admission;
- reconciliation without a second dispatch;
- one unavailable observer component;
- one lost Node represented as unknown residual state;
- unexpected Node body after destruction;
- reconstruction identity match and drift;
- bounded export path traversal and control-file collision;
- bundle tampering;
- final outcome before destruction;
- invalid event calendar timestamps;
- complete prepare, start, freeze, export, reset, destroy, residual, and outcome
  closure with receipts.

## Deferred work

The following remain outside lifecycle v0:

- concrete production adapters for every component;
- production promotion and ownership of the component-owned Edge JSONL control
  surface and any production Edge adapter;
- Runtime MCP adapter wiring in this repository;
- long-running service deployment;
- generalized workflow or scheduling;
- public Protocol promotion of Campaign, World, Node, or bundle schemas;
- Red/Blue Agent behavior and attack-defense evaluation.

Those additions require demonstrated consumers and must not expand this control
plane merely for architectural symmetry.
