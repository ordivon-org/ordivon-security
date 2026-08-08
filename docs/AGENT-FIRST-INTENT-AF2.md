---
schema_version: 1
id: security.agent-first-intent-af2
title: Agent-first Intent Surface AF2
type: decision
profile: engineering
lifecycle: active
source_role: canonical
visibility: public
owners: [ordivon-security]
updated: 2026-08-08
summary: Minimal reusable Range-intent surface graduating C1-A autonomy without Contest ticks, action menus, exactly-one-action rules, or ownership of the Agent cognition loop.
evidence_status: verified
readiness: ACCEPTED
related:
  - security.agent-first-structure-af1
  - security.autonomous-intent-c1a
  - security.range-session-s0
---
# Agent-first Intent Surface AF2

AF2 graduates only the minimum autonomy already forced by C1-A.

The reusable contract is:

```text
visible observation snapshot
+ objective
+ exact authority snapshots
+ declared effect interfaces
→ zero or more RangeEffectRequest values
```

The surface consists of `RangeEffectInterface`, `RangeIntentContext`, and `RangeIntentDecision`. A zero-request decision is an explicit non-action. Multiple requests are representable. There is no tick, action catalog, exactly-one proposal rule, Host Task, Runtime Job, Provider policy, or generic reasoning state in the contract.

`RangeIntentContext` snapshots the visible observation and authority values into canonical bytes so later mutation of the caller's objects cannot rewrite the Agent's retained decision context. It validates that every exposed effect interface is actually covered by one exact visible authority grant.

`RangeIntentDecision` snapshots zero or more `RangeEffectRequest` values and binds them to the exact context digest. It rejects requests for another Actor or an effect interface that was not declared in the context. The decision still does not admit or execute an effect.

The optional `DeepSeekRangeIntentDriver` lives under `ordivon_security.integrations`, not in the core contract. It uses Ordivon Harness to produce zero or more requests and returns both the Security decision and provider/Harness evidence. Security does not own the model loop.

AF2 intentionally does not define memory, planning, trust, delegation, communication, long-horizon continuity, retries, compensation, or effect execution. Higher-order experiments must force those semantics if they need them.

AF3 has now physically consumed both branches of this surface through the current real Harness/DeepSeek path: one deceptive-claim case produced a zero-request hold, while one independently verified compromise produced one effect request that then passed separate Security admission. AF3 also exposed and corrected two integration assumptions (missing Harness bridge identity and historical positional `RunBudget` drift). See [`AGENT-FIRST-DECEPTION-AF3.md`](AGENT-FIRST-DECEPTION-AF3.md).
