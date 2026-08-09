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
updated: 2026-08-09
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

## Zero-effect closure and Harness status

AE1 forced a sharper boundary between Security intent and Harness run closure. Positive effects remain explicit: if an Agent wants a consequential effect, it must submit that effect through `submit_range_intents` so Security receives an exact `RangeEffectRequest` that can later pass separate authority admission. Security never infers a positive effect from natural-language conclusion text.

A zero-effect decision is different. It may be represented either by an explicit empty `submit_range_intents` call or by a Harness conclusion with no effect Tool call. In both cases the Security meaning is simply `effectRequests=()`. This removes a ceremonial Tool requirement without weakening effect authority:

```text
positive effect => explicit Tool request
no explicit effect request => no effect
```

AE1 also showed that `needs_input` can be the correct closure for a complete current Security decision when external world information is still pending. `candidate_completed` and `needs_input` are therefore both valid bounded decision closures when their Security intent is well defined. This yields:

```text
complete current Security decision
!=
complete world knowledge
```

Harness conclusion status and whether a zero-effect decision used an empty Tool call are retained in turn evidence only. They are not part of `RangeIntentDecision` metadata and therefore do not redefine Security effect-intent identity. See [`ADVERSARIAL-EPISTEMICS-AE1.md`](ADVERSARIAL-EPISTEMICS-AE1.md).

## Pre-admission intent revision forced by AC2

AC2 exposed a real integration assumption that AF2 had never physically justified: the first `submit_range_intents` call was treated as immutable even though the Tool had performed neither Security admission nor effect execution. In the verified-disclosure mismatch world, the Agent's later conclusion correctly rejected activation after the first Tool call, but the integration had no legal revision path. The minimum correction keeps the core `RangeIntentDecision` unchanged and makes Harness-side intent explicitly pending before admission. A later `submit_range_intents` call completely replaces the earlier pending request set; an empty set may retract a positive pending intent; all revisions are retained in turn evidence; only the final set enters the Security decision. Prompt revision `security-agent-first-range-intent-af2-v3` additionally reports `pendingIntentReplaceableBeforeAdmission=true`.

This does **not** make natural-language conclusion text authoritative. The final AC2 run still demonstrates why: the Agent explicitly says it must retract activation but emits no second Tool call. Security therefore correctly retains the latest Tool intent. AC2 leaves a new unresolved integration boundary: pending intent and finalized Agent intent need an explicit Tool-level distinction if practice continues to show post-Tool self-correction. No already-admitted or executed effect is revisable through this mechanism.

## IF0–IF2: deliberation before effect authority

AC2 and IF0–IF2 expose a further distinction inside Agent intent. IF0 proves an explicit Tool finalization boundary can separate pending cognition from effect authority, but its Agent finalizes `shared.activate` before later reasoning correctly prefers hold. IF1 adds exact readback plus digest-bound commit and is falsified the same way. IF2 then adds one no-effect-authority deliberation turn before opening IF1 Tools; on the exact AC2 mismatch context the deliberation derives an empty candidate request set and the later Tool-authoritative decision remains empty through readback/finalization.

The supported candidate is narrow: in this consumer, consequence Tools became useful **after** non-authoritative deliberation rather than as the first model-shaped response. Security still owns neither generic cognition nor strategy scoring. The no-effect record is Agent cognition evidence, not world truth or effect authority. Provider calls are stateless; continuity is explicit through the exact retained deliberation record. IF2 does not yet justify making readback/finalization universal. The next experiment should remove that ceremony while retaining deliberation-before-authority; only repeated consumers should force a shared Harness primitive.
