---
schema_version: 1
id: security.archive.round1.system
title: Round 1 system freeze
profile: engineering
type: archive
lifecycle: historical
source_role: supporting
visibility: public
owners:
  - ordivon-security
updated: 2026-08-04
summary: Exact revision, test baseline, evidence digests, and claim boundary for the removed single-Actor Security experiment and evaluation framework.
evidence_status: verified
readiness: ARCHIVED
applies_to:
  - ordivon-security-round1
---
# Round 1 system freeze

The former active Security framework is preserved by Git revision:

```text
92c0f9497741c3cde542c347318d2372fb884e30
```

Baseline verification at that revision:

```text
python3 -m unittest discover -v
29 tests passed
1 optional CAGE 4 test skipped because external source was not configured
0 failures
```

Retained evidence digests:

```text
sha256:14744575eee63145e015fae7b3bcaa09904f318eaac31318b5a493df49dae6f0
  evidence/experiments/round1-20260730.json

sha256:9d32a31b3f020f73a0ddae864e8e75cd4ac3124ce5cfe09cb089c699e64fdcc4
  evidence/r-a-control-boundary/report.json
```

The system established useful distinctions: exact Trial identity, actor-specific observation, hidden evaluation records, independent scoring, immutable evidence, and bounded evaluator/control attacks. It did not provide a true multi-Actor Contest, autonomous Red/Blue control, Campaign execution, an authoritative cyber Range, or real-world capability evidence.

The code was removed from the active tree because there are no stable consumers and its single-Actor execution shape would obstruct the new architecture. Restore or inspect it through Git rather than reintroducing compatibility layers.
