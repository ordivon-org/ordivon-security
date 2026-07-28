# Campaign Manifest v0

Status: executable experimental contract (`schema_version: "0.1.0"`)

Campaign Manifest v0 is the admission and evidence boundary for an Ordivon
Security experiment. It owns Security identities and bindings. It does not
implement Host cognition, Runtime execution, Link networking, Edge lifecycle,
Game mechanics, attacks, defenses, or public-target integrations.

## Contract objects

- `campaign` is a stable Security Campaign ID and immutable record revision.
- `world` is a stable Security World ID and revision. Its exact Link topology,
  Edge fleet, and Game scenario tuples are references to those projects, not
  copies of their contracts.
- `authority` is the admission record. It binds the exact Campaign and World
  revisions, stable authority identity, admission actor, out-of-band lifecycle
  actor, independent judge and observers, and both envelope identities.
- `provenance` contains the exact source and policy tuples used for admission.
- `actors` contain only Security-owned identity, role, plane, and evaluation
  status. They do not duplicate Host or Runtime objects.
- `objectives` name an experiment-plane actor, explicit criteria, and expected
  evidence locations.
- `stop_conditions` declare typed stop, freeze, or destroy responses. Every
  Campaign includes an out-of-band `authority_action`. `deadline` requires a
  numeric limit; `budget_exhausted` requires a resource name and numeric limit.
- `capability_envelope` records internal Agent capability for one evaluated
  subject: exact model, Host, Runtime, Tool catalog, memory, compute, time,
  resources, and collaborating evaluated actors.
- `consequence_envelope` independently records authorized external consequence:
  exact World revision, targets, networks, identities, data, resources, and
  external boundaries.
- `outcome` is null for an admitted record and required for a completed record.

An exact cross-project reference is the tuple `project`, `id`, `revision`, and
`digest`. The ID namespace must agree with `project`. These tuples are opaque
identities supplied by their owning projects; Security does not interpret or
reimplement their contents.

Every adapter carries `campaign.id`, `campaign.revision_id`, `world.id`, and
`world.revision_id` unchanged. It may add a local receipt ID but must not mint
replacements for these authoritative identities.

## Authority and control independence

`authority.authority_id` is not an actor ID. It identifies the authority under
which admission exists. `admitted_by_actor_id` names the lifecycle-authority
actor that emitted the record. `lifecycle_actor_id`, `judge_actor_id`, and every
`observer_actor_id` resolve to declared, non-evaluated actors in management or
observation planes.

Lifecycle, judge, and observer actor IDs are pairwise distinct. The authority
ID is distinct from all actors. The Capability subject and collaborators must
be evaluated experiment actors, so an evaluated Agent cannot become its own
judge, observer, or lifecycle authority.

The admission record ID is deterministic:

```text
<campaign-id>:admission-<campaign-revision>
```

The authority record binds each envelope by its logical ID, revision, and
digest. The binding is outside both envelopes. This is what keeps Capability
and Consequence orthogonal without weakening the admission link.

## Identity and canonicalization

Logical IDs are lowercase `urn:ordivon:<project>:<kind>:<name>` values.
Campaign and World revision IDs are derived exactly as:

```text
<logical-id>:revision-<positive-integer>
```

`ordivon-canonical-json-v0` is a deliberately small deterministic JSON profile:

1. input is UTF-8 without a byte-order mark;
2. object keys are sorted by Unicode scalar value;
3. arrays retain order;
4. quotation mark, reverse solidus, and JSON control characters use the exact
   JSON escapes `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, and `\t`;
5. other U+0000–U+001F controls use lowercase `\u00xx`; all other Unicode
   scalar values are emitted as UTF-8;
6. Unicode strings are preserved exactly—there is no normalization;
7. integers are base-10 signed 64-bit values with no leading zero;
8. floats, non-finite numbers, lone surrogates, cycles, duplicate JSON keys,
   and nesting deeper than 64 containers are rejected;
9. there is no insignificant whitespace.

Preserving Unicode scalars avoids dependence on a runtime Unicode normalization
database. Canonically equivalent spellings may therefore have different
digests, by design. Producers that want normalized prose must normalize before
admission and preserve that spelling.

A digest is lowercase `sha256:` plus the hexadecimal SHA-256 of canonical
bytes:

- `identity.manifest_digest` covers the whole manifest except that field;
- each envelope digest covers the entire envelope except its own `digest`.

No other field is excluded. Authority envelope references therefore do not
create a cycle: the envelope digests are computed first, the authority binds
them, and the manifest digest binds the whole result.

The committed fixture uses synthetic external-reference digests. It makes no
claim about a real build, target, environment, attack, defense, escape, or
containment result.

## Admission and transition invariants

- A materialized Campaign record and both envelope revisions are immutable.
- The next Campaign record preserves its logical ID and advances exactly one
  Campaign revision. A completed Campaign cannot return to `admitted`.
- A changed Capability or Consequence substance preserves its logical ID and
  advances exactly one envelope revision.
- A revision-only envelope bump is invalid. Unchanged substance retains its
  exact revision and digest.
- A Capability-only Campaign revision retains the complete Consequence
  Envelope unchanged.
- A Consequence change is explicit, advances the Campaign record, and is bound
  by the newly derived admission record.
- World substance changes advance the World revision. Because Consequence
  binds `world_revision_id`, a World change also requires a newly scoped
  Consequence revision.
- Reference tuple changes inside World or Capability are substance changes;
  they cannot reuse those component revisions.
- Target authority, objective actors, Capability subjects and collaborators,
  outcome judge, and admission actors must resolve within the same manifest.

`validate_campaign` validates one record. Transition rules require the prior
record:

```bash
python3 scripts/validate_campaign.py current.json --previous previous.json
```

A pairwise transition cannot prove that a revision was never used in a
non-adjacent historical branch. The authoritative admission ledger must enforce
global uniqueness and append-only ordering.

## Outcome taxonomy

The authoritative judge records one of:

- `success`: every objective is assessed `achieved`;
- `partial_progress`: every objective is conclusively assessed and at least one
  is `partially_achieved`;
- `defense`: every objective is conclusively assessed and every Red objective
  is `prevented` or `not_achieved`, with at least one `prevented`;
- `escape`: a consequence-boundary breach is conclusively evidenced and
  `containment_breach` is true;
- `observer_loss`: authoritative observation was lost, evidence quality is
  `inconclusive`, and a reason code explains the loss;
- `invalid_run`: validity is broken, evidence quality is `invalid`, and a
  reason code explains why;
- `inconclusive_evidence`: evidence cannot support a claim, evidence quality is
  `inconclusive`, and a reason code explains the gap.

Every outcome has evidence. Every non-unknown objective assessment has its own
evidence. Escape, observer loss, invalid run, and inconclusive evidence require
reason codes. Negative, failed, escaped, invalid, observer-loss, and
inconclusive records remain first-class records.

An outcome enum alone is not an attack, defense, escape, or containment claim.
Such a claim also requires the exact Campaign revision, World revision,
environment references, authoritative actors, and evidence.

## Bounded validation and path behavior

The CLI accepts one caller-selected local path and, optionally, one prior path.
It intentionally has no repository-root sandbox: reading an arbitrary path is
the purpose of a local file validator. Callers embedding it in a service must
apply their own path authorization before invoking it.

The standard-library loader caps each file at 1 MiB, collections at
contract-specific maxima, validation errors at 100, canonical nodes at 100,000,
and nesting at 64. These are v0 admission limits, not Host or Runtime resource
budgets.

Invalid fixture case files are test data, not accepted Campaigns. Their base
paths are resolved and required to stay beneath `fixtures/campaigns`.

## Compatibility

Version `0.1.0` is pre-1.0 and strict. Readers reject unknown properties and
unknown versions. Patch releases may clarify documentation or fix validators
without changing accepted data. A minor v0 release may add optional data but
uses a new exact `schema_version`. Removing fields, changing admitted meaning,
or changing canonicalization requires a new major contract. A canonicalization
label never changes in place.

The implementation supports Python 3.10 or newer and has no third-party runtime
dependencies. The schema remains Draft 2020-12 for adapters that use a mature
JSON Schema implementation; the included validator implements and checks the
bounded vocabulary used by this schema.

## Commands

```bash
# Validate the canonical fixture
python3 scripts/validate_campaign.py \
  fixtures/campaigns/valid/minimal-owned-range.json

# Print its computed digest
python3 scripts/validate_campaign.py \
  fixtures/campaigns/valid/minimal-owned-range.json --digest

# Emit canonical bytes
python3 scripts/validate_campaign.py campaign.json --canonical

# Validate a transition
python3 scripts/validate_campaign.py current.json --previous previous.json

# Run the complete contract suite
python3 -m unittest discover -v
```

Invalid `*.case.json` fixtures are deterministic mutations over the valid
fixture. Tests materialize each mutation and prove rejection for its declared
reason, avoiding large near-identical Campaign copies.
