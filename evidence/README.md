# Evidence

Immutable Campaign replay bundles and receipts belong here only when sanitized
for repository storage. Raw secrets, real endpoints, packet captures,
credentials, personal network evidence, and large raw experiment traces remain
outside Git.

Sanitized experiment evidence belongs under [`experiments/`](experiments/) when
it contains:

- exact experiment and implementation identity or file digests;
- aggregate results that do not erase individual Trial references;
- source Artifact and trace digests;
- explicit authority and external-effect boundaries;
- limitations, null results, and retain/reduce/delete decisions.

Round 1 evidence:

- [`experiments/round1-20260730.json`](experiments/round1-20260730.json)
