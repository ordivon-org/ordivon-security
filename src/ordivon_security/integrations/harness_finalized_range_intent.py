from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json
from ordivon_security.actors.autonomous import RangeIntentContext, RangeIntentDecision
from ordivon_security.integrations.harness_range_intent import (
    DeepSeekRangeIntentConfig,
    RangeIntentHarnessFailure,
    _git_revision,
    _insert_sources,
    _project_version,
)
from ordivon_security.range import RangeEffectRequest

_PENDING_TOOL = "submit_range_intents"
_FINALIZE_TOOL = "finalize_range_intent"
_DOMAIN_ID = "domain:security-agent-first-range-intent-finalization-if0"
_PROMPT_REVISION = "security-agent-first-range-intent-finalization-if0-v1"


@dataclass(frozen=True, slots=True)
class FinalizedRangeIntentConfig:
    base: DeepSeekRangeIntentConfig
    max_intent_revisions: int = 4

    def __post_init__(self) -> None:
        if not 1 <= self.max_intent_revisions <= 16:
            raise ValueError("IF0 max intent revisions must be between 1 and 16")


class _FinalizedRangeIntentBridge:
    def __init__(
        self,
        *,
        catalog: Any,
        observation_type: Any,
        max_effect_requests: int,
        max_intent_revisions: int,
        bridge_identity: JsonObject,
        tool_bridge_error_type: Any,
        model_correctable_kind: Any,
    ) -> None:
        self.catalog = catalog
        self.observation_type = observation_type
        self.max_effect_requests = max_effect_requests
        self.max_intent_revisions = max_intent_revisions
        self.bridge_identity = bridge_identity
        self.tool_bridge_error_type = tool_bridge_error_type
        self.model_correctable_kind = model_correctable_kind
        validate_json(self.bridge_identity)
        self.pending_requests: list[JsonObject] | None = None
        self.intent_revisions: list[list[JsonObject]] = []
        self.finalized_revision: int | None = None
        self.finalized_requests: list[JsonObject] | None = None

    @property
    def finalized(self) -> bool:
        return self.finalized_revision is not None

    def _error(self, message: str) -> Exception:
        return self.tool_bridge_error_type(message, kind=self.model_correctable_kind)

    def _parse_requests(self, raw_requests: object) -> list[JsonObject]:
        if not isinstance(raw_requests, list):
            raise ValueError("IF0 pending intent requests must be a list")
        if len(raw_requests) > self.max_effect_requests:
            raise ValueError("IF0 pending intent request count exceeds configured bound")
        expected = {"authorityId", "zoneRef", "capability", "effectType", "payload"}
        parsed: list[JsonObject] = []
        for index, item in enumerate(raw_requests):
            if not isinstance(item, dict) or set(item) != expected:
                raise ValueError(f"IF0 pending intent request {index} differs from exact schema")
            for key in ("authorityId", "zoneRef", "capability", "effectType"):
                value = item.get(key)
                if not isinstance(value, str) or not value or value != value.strip():
                    raise ValueError(f"IF0 pending intent request {index} {key} is invalid")
            payload = item.get("payload")
            if not isinstance(payload, dict):
                raise ValueError(f"IF0 pending intent request {index} payload must be an object")
            value = cast(JsonObject, dict(item))
            validate_json(value)
            parsed.append(value)
        return parsed

    def execute(self, call: Any, *, step_id: str) -> Any:
        name = getattr(call, "name", None)
        arguments = getattr(call, "arguments", None)
        if not isinstance(arguments, dict):
            raise ValueError("IF0 Tool arguments must be an object")

        if name == _PENDING_TOOL:
            if set(arguments) != {"requests"}:
                raise ValueError("IF0 pending Tool arguments differ from exact schema")
            if self.finalized:
                raise self._error(
                    "Finalized intent is already sealed for this bounded decision; pending intent "
                    "cannot be revised after Tool-level finalization."
                )
            if len(self.intent_revisions) >= self.max_intent_revisions:
                raise self._error("IF0 pending intent revision bound is exhausted")
            parsed = self._parse_requests(arguments.get("requests"))
            previous_present = self.pending_requests is not None
            self.pending_requests = parsed
            self.intent_revisions.append(parsed)
            revision = len(self.intent_revisions)
            return self.observation_type(
                tool_call_id=call.tool_call_id,
                tool_name=_PENDING_TOOL,
                status="observed",
                structured_content={
                    "pendingIntentRecorded": True,
                    "pendingIntentRevision": revision,
                    "pendingIntentRequestCount": len(parsed),
                    "replacedPreviousPendingIntent": previous_present,
                    "pendingIntentReplaceable": True,
                    "intentFinalized": False,
                    "securityAdmissionPerformed": False,
                    "effectExecuted": False,
                    "nextRequiredBoundary": "finalize-range-intent",
                    "stepId": step_id,
                },
            )

        if name == _FINALIZE_TOOL:
            if set(arguments) != {"expectedRevision"}:
                raise ValueError("IF0 finalize Tool arguments differ from exact schema")
            expected_revision = arguments.get("expectedRevision")
            if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
                raise ValueError("IF0 expectedRevision must be an integer")
            if self.finalized:
                raise self._error("IF0 intent is already finalized")
            if self.pending_requests is None:
                raise self._error(
                    "No pending Tool intent exists. Submit the complete pending request set first; "
                    "use an empty requests list to represent zero consequential effects."
                )
            current_revision = len(self.intent_revisions)
            if expected_revision != current_revision:
                raise self._error(
                    f"Cannot finalize stale pending intent revision {expected_revision}; current "
                    f"revision is {current_revision}. Review the latest pending intent and finalize "
                    "that exact revision."
                )
            self.finalized_revision = current_revision
            self.finalized_requests = [cast(JsonObject, dict(item)) for item in self.pending_requests]
            return self.observation_type(
                tool_call_id=call.tool_call_id,
                tool_name=_FINALIZE_TOOL,
                status="observed",
                structured_content={
                    "intentFinalized": True,
                    "finalizedRevision": current_revision,
                    "finalizedRequestCount": len(self.finalized_requests),
                    "securityAdmissionPerformed": False,
                    "effectExecuted": False,
                    "finalizationIsPreAdmission": True,
                    "stepId": step_id,
                },
            )

        raise ValueError(f"IF0 received an unexpected Harness Tool: {name}")


class DeepSeekFinalizedRangeIntentDriver:
    """Experimental two-phase Harness integration for pending then finalized Range intent.

    This driver is intentionally separate from DeepSeekRangeIntentDriver until IF0 physically
    validates that Tool-level finalization improves intent convergence. No Security admission or
    effect execution occurs inside the driver.
    """

    def __init__(self, config: FinalizedRangeIntentConfig) -> None:
        self.config = config

    def decide(
        self,
        context: RangeIntentContext,
        *,
        label: str,
    ) -> tuple[RangeIntentDecision, JsonObject]:
        if not label or label != label.strip():
            raise ValueError("IF0 turn label must be non-empty and trimmed")
        base = self.config.base
        _insert_sources(harness_source=base.harness_source, protocol_source=base.protocol_source)
        domain_module = importlib.import_module("ordivon_harness.domain_tools")
        deepseek_module = importlib.import_module("ordivon_harness.ordivon.deepseek")
        version_module = importlib.import_module("ordivon_harness.version")
        harness_revision = _git_revision(base.harness_source, "Harness")
        protocol_revision = _git_revision(base.protocol_repository, "Computing protocol")
        harness_version = _project_version(base.harness_source, "Harness")
        settings = deepseek_module.DeepSeekSettings.from_secret_file(
            base.secret_path,
            timeout_seconds=base.provider_timeout_seconds,
            max_output_tokens=base.max_output_tokens,
        )
        if not settings.credential_scope_id.startswith("credential-scope:"):
            raise ValueError("IF0 requires explicit credentialScopeId")
        adapter = deepseek_module.DeepSeekTurnAdapter(settings)

        request_item_schema: JsonObject = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "authorityId": {"type": "string"},
                "zoneRef": {"type": "string"},
                "capability": {"type": "string"},
                "effectType": {"type": "string"},
                "payload": {"type": "object"},
            },
            "required": ["authorityId", "zoneRef", "capability", "effectType", "payload"],
        }
        pending_tool = domain_module.AgentToolDefinition(
            _PENDING_TOOL,
            (
                "Set or completely replace the pending Security Range effect-intent request set. "
                "This is a draft/pending state only: it performs no Security admission and executes "
                "no consequence. You may revise it until finalization. Use an empty requests list "
                "for a finalized zero-effect decision."
            ),
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "requests": {
                        "type": "array",
                        "maxItems": base.max_effect_requests,
                        "items": request_item_schema,
                    }
                },
                "required": ["requests"],
            },
        )
        finalize_tool = domain_module.AgentToolDefinition(
            _FINALIZE_TOOL,
            (
                "Seal the latest pending Range intent revision as your final Tool-authoritative "
                "intent for this bounded decision. Pass the exact current pending revision number. "
                "Finalization is still pre-admission and pre-execution, but after finalization the "
                "pending request set cannot be revised in this turn."
            ),
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"expectedRevision": {"type": "integer", "minimum": 1}},
                "required": ["expectedRevision"],
            },
        )
        catalog = domain_module.DomainToolCatalog(
            domain_id=_DOMAIN_ID,
            revision=_PROMPT_REVISION,
            tools=(pending_tool, finalize_tool),
        )
        bridge = _FinalizedRangeIntentBridge(
            catalog=catalog,
            observation_type=domain_module.ToolObservation,
            max_effect_requests=base.max_effect_requests,
            max_intent_revisions=self.config.max_intent_revisions,
            bridge_identity={
                "schemaVersion": 1,
                "kind": "ordivon.security.if0-finalized-range-intent-bridge",
                "actorId": context.actor_id,
                "contextDigest": context.digest,
                "promptRevision": _PROMPT_REVISION,
            },
            tool_bridge_error_type=domain_module.ToolBridgeError,
            model_correctable_kind=domain_module.ToolBridgeErrorKind.MODEL_CORRECTABLE,
        )
        runner = domain_module.DomainToolLoopRunner(adapter, bridge)
        budget = domain_module.RunBudget(
            max_model_calls=5,
            max_tool_calls=5,
            max_observation_bytes=131_072,
            max_wall_time_ms=180_000,
            max_total_tokens=1_000_000,
            max_model_retries=1,
            max_tool_corrections=2,
            max_observation_only_turns=1,
            max_no_progress_turns=2,
            max_model_observation_bytes=262_144,
        )
        context_value = context.to_dict()
        context_digest = context.digest
        token = context_digest.removeprefix("sha256:")[:16]
        plan = domain_module.DomainToolLoopPlan(
            harness_run_id=f"harness-run:security-if0-{label}:{token}",
            assignment_id=f"assignment:security-if0-{label}:{token}",
            context_digest=context_digest,
            initial_messages=(
                {
                    "role": "system",
                    "content": (
                        "You are one autonomous principal inside an explicitly authorized Security "
                        "Range. Authority is permission, not instruction. Use only the visible "
                        "observation, objective, authority snapshots and declared effect interfaces. "
                        "This experiment separates pending intent from finalized intent. First call "
                        "submit_range_intents with the complete request set you currently intend. The "
                        "Tool response tells you the pending revision number. Review that pending state "
                        "against all visible evidence. If your decision changes, call "
                        "submit_range_intents again with a complete replacement request set; an empty "
                        "set means no consequential effect. When and only when the latest pending set "
                        "matches your final decision, call finalize_range_intent with its exact revision. "
                        "Do not conclude before finalization. Finalization itself does not perform "
                        "Security admission or execute any effect. After the finalize Tool observation, "
                        "submit a concise candidate_completed conclusion. Never infer that a requested "
                        "effect happened."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        context_value,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                },
            ),
            allowed_tools=(_PENDING_TOOL, _FINALIZE_TOOL),
            budget=budget,
        )
        result = runner.run(plan)
        stop_code = str(getattr(result.stop_code, "value", result.stop_code))
        trace = cast(JsonObject, result.trace.to_dict())
        usage = cast(JsonObject, dict(result.usage))
        effective_raw = usage.get("effectiveModelIds")
        effective = (
            [item for item in effective_raw if isinstance(item, str)]
            if isinstance(effective_raw, list)
            else []
        )
        execution_identity = cast(JsonObject, runner.execution_identity(plan))

        common_evidence: JsonObject = {
            "schemaVersion": 1,
            "label": label,
            "contextDigest": context_digest,
            "trace": trace,
            "traceDigest": canonical_digest(trace),
            "usage": usage,
            "requestedModelId": str(adapter.model_id),
            "effectiveModelIds": effective or [str(adapter.model_id)],
            "credentialScopeId": str(settings.credential_scope_id),
            "harness": {
                "sourceRevision": harness_revision,
                "declaredVersion": harness_version,
                "runtimeMetadataVersion": str(version_module.package_version()),
                "protocolSourceRevision": protocol_revision,
            },
            "loopExecutionIdentity": execution_identity,
            "pendingIntentRevisionCount": len(bridge.intent_revisions),
            "pendingIntentRevisions": bridge.intent_revisions,
            "intentFinalized": bridge.finalized,
            "finalizedRevision": bridge.finalized_revision,
        }
        valid_stop = stop_code == "candidate_completed"
        if not valid_stop or result.conclusion is None or not bridge.finalized:
            failure: JsonObject = {
                **common_evidence,
                "kind": "ordivon.security.if0-finalized-range-intent-harness-failure",
                "stopCode": stop_code,
                "failureReason": (
                    "harness-stop-before-candidate-completed"
                    if not valid_stop
                    else "candidate-completed-before-tool-finalization"
                    if not bridge.finalized
                    else "candidate-completed-without-conclusion"
                ),
            }
            validate_json(failure)
            raise RangeIntentHarnessFailure(stop_code, failure)
        assert bridge.finalized_requests is not None

        effect_requests: list[RangeEffectRequest] = []
        for index, item in enumerate(bridge.finalized_requests):
            effect_requests.append(
                RangeEffectRequest(
                    request_id=f"range-effect-request:if0-{token}-{index}",
                    actor_id=context.actor_id,
                    authority_id=cast(str, item["authorityId"]),
                    zone_ref=cast(str, item["zoneRef"]),
                    capability=cast(str, item["capability"]),
                    effect_type=cast(str, item["effectType"]),
                    payload=cast(JsonObject, item["payload"]),
                )
            )
        decision = context.decision(
            tuple(effect_requests),
            metadata={
                "source": "deepseek-via-ordivon-harness",
                "promptRevision": _PROMPT_REVISION,
            },
        )
        if effective and any(item != adapter.model_id for item in effective):
            raise RuntimeError("IF0 effective model differs from requested model")
        evidence: JsonObject = {
            **common_evidence,
            "kind": "ordivon.security.if0-finalized-range-intent-turn",
            "stopCode": stop_code,
            "decisionDigest": decision.digest,
            "decision": decision.to_dict(),
            "modelRequestCount": len(effect_requests),
            "conclusionStatus": str(result.conclusion.status),
            "conclusionSummary": str(result.conclusion.summary),
        }
        validate_json(evidence)
        return decision, evidence


__all__ = [
    "DeepSeekFinalizedRangeIntentDriver",
    "FinalizedRangeIntentConfig",
    "RangeIntentHarnessFailure",
]
