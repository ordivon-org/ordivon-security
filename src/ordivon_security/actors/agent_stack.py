from __future__ import annotations

import importlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from ordivon_security._canonical import (
    JsonObject,
    JsonValue,
    canonical_digest,
    validate_json,
)
from ordivon_security.contest.model import ActorActionResult, ActorObservation
from ordivon_security.identity import security_source_identity

from .protocol import ActorProposalFailureCode

PROMPT_REVISION = "security-cage-team-plan-v1"
BACKEND_ID = "backend:native-harness-deepseek-v1"
DOMAIN_ID = "domain:ordivon-security-cage-team-plan"
TOOL_NAME = "select_team_plan"
DEFAULT_ALLOWED_ACTIONS = (
    "cage.team.native-policy",
    "cage.team.sleep",
)


def _text(value: str, label: str, *, prefix: str | None = None) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty and trimmed")
    if len(value.encode("utf-8")) > 500:
        raise ValueError(f"{label} exceeds 500 UTF-8 bytes")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _digest(value: str, label: str) -> str:
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _json_object_copy(value: object) -> JsonObject:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    decoded = json.loads(encoded)
    if not isinstance(decoded, dict):
        raise TypeError("JSON copy did not produce an object")
    validate_json(decoded)
    return cast(JsonObject, decoded)


@dataclass(frozen=True, slots=True)
class AgentLayerBinding:
    component_id: str
    revision: str
    mode: str
    consumed: bool
    configuration: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.component_id, "Agent layer component identity")
        _text(self.revision, "Agent layer revision")
        _text(self.mode, "Agent layer mode")
        validate_json(self.configuration)

    def to_dict(self) -> JsonObject:
        return {
            "componentId": self.component_id,
            "revision": self.revision,
            "mode": self.mode,
            "consumed": self.consumed,
            "configuration": self.configuration,
        }


@dataclass(frozen=True, slots=True)
class HarnessBudgetConfig:
    max_model_calls: int = 3
    max_tool_calls: int = 1
    max_observation_bytes: int = 131_072
    max_wall_time_ms: int = 180_000
    max_total_tokens: int = 16_384
    max_model_retries: int = 1
    max_tool_corrections: int = 1
    max_observation_only_turns: int = 1
    max_no_progress_turns: int = 1
    max_model_observation_bytes: int = 65_536

    def __post_init__(self) -> None:
        primary = (
            self.max_model_calls,
            self.max_tool_calls,
            self.max_observation_bytes,
            self.max_wall_time_ms,
            self.max_total_tokens,
            self.max_model_observation_bytes,
        )
        secondary = (
            self.max_model_retries,
            self.max_tool_corrections,
            self.max_observation_only_turns,
            self.max_no_progress_turns,
        )
        if min(primary) < 1 or min(secondary) < 0:
            raise ValueError("Harness budget values are invalid")

    def to_dict(self) -> JsonObject:
        return {
            "maxModelCalls": self.max_model_calls,
            "maxToolCalls": self.max_tool_calls,
            "maxObservationBytes": self.max_observation_bytes,
            "maxWallTimeMs": self.max_wall_time_ms,
            "maxTotalTokens": self.max_total_tokens,
            "maxModelRetries": self.max_model_retries,
            "maxToolCorrections": self.max_tool_corrections,
            "maxObservationOnlyTurns": self.max_observation_only_turns,
            "maxNoProgressTurns": self.max_no_progress_turns,
            "maxModelObservationBytes": self.max_model_observation_bytes,
        }


@dataclass(frozen=True, slots=True)
class AgentTurnEvidence:
    harness_run_id: str
    assignment_id: str
    context_digest: str
    selected_action: str
    rationale: str
    stop_code: str
    trace: JsonObject
    trace_digest: str
    usage: JsonObject
    requested_model_id: str
    effective_model_ids: tuple[str, ...]
    credential_scope_id: str

    def __post_init__(self) -> None:
        _text(self.harness_run_id, "Harness Run identity", prefix="harness-run")
        _text(self.assignment_id, "Assignment identity", prefix="assignment")
        _digest(self.context_digest, "Agent turn Context digest")
        _text(self.selected_action, "Agent selected action")
        _text(self.rationale, "Agent rationale")
        _text(self.stop_code, "Harness stop code")
        validate_json(self.trace)
        _digest(self.trace_digest, "Harness Trace digest")
        validate_json(self.usage)
        _text(self.requested_model_id, "requested model identity")
        _text(self.credential_scope_id, "credential scope identity", prefix="credential-scope")
        if not self.effective_model_ids:
            raise ValueError("Agent turn requires an effective model identity")
        for model_id in self.effective_model_ids:
            _text(model_id, "effective model identity")

    def to_dict(self, *, include_trace: bool) -> JsonObject:
        value: JsonObject = {
            "harnessRunId": self.harness_run_id,
            "assignmentId": self.assignment_id,
            "contextDigest": self.context_digest,
            "selectedAction": self.selected_action,
            "rationale": self.rationale,
            "stopCode": self.stop_code,
            "traceDigest": self.trace_digest,
            "usage": self.usage,
            "requestedModelId": self.requested_model_id,
            "effectiveModelIds": list(self.effective_model_ids),
            "credentialScopeId": self.credential_scope_id,
        }
        if include_trace:
            value["trace"] = self.trace
        return value


class AgentTurnDriver(Protocol):
    @property
    def execution_identity(self) -> JsonObject: ...

    @property
    def credential_scope_id(self) -> str: ...

    @property
    def requested_model_id(self) -> str: ...

    @property
    def allowed_actions(self) -> tuple[str, ...]: ...

    def run_turn(
        self,
        *,
        actor_id: str,
        side: str,
        objective: str,
        observation: ActorObservation,
        prior_results: tuple[ActorActionResult, ...],
    ) -> AgentTurnEvidence: ...


class AgentTurnDriverError(RuntimeError):
    def __init__(
        self,
        code: ActorProposalFailureCode,
        message: str,
        *,
        details: JsonObject | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = {} if details is None else details


class _PlanSelectionBridge:
    def __init__(
        self,
        *,
        catalog: Any,
        observation_type: Any,
        bridge_identity: JsonObject,
        allowed_actions: tuple[str, ...],
    ) -> None:
        self.catalog = catalog
        self.observation_type = observation_type
        self.bridge_identity = bridge_identity
        self.allowed_actions = frozenset(allowed_actions)
        self.selected_action: str | None = None

    def execute(self, call: Any, *, step_id: str) -> Any:
        if getattr(call, "name", None) != TOOL_NAME:
            raise ValueError("Security Harness Bridge received another Tool")
        arguments = getattr(call, "arguments", None)
        if not isinstance(arguments, dict):
            raise ValueError("Security plan Tool arguments must be an object")
        plan = arguments.get("plan")
        if not isinstance(plan, str) or plan not in self.allowed_actions:
            raise ValueError("Security plan Tool selected an ungranted action")
        if self.selected_action is not None:
            raise ValueError("Security plan Tool may be executed only once per tick")
        self.selected_action = plan
        return self.observation_type(
            tool_call_id=call.tool_call_id,
            tool_name=TOOL_NAME,
            status="observed",
            structured_content={
                "admitted": True,
                "selectedPlan": plan,
                "stepId": step_id,
            },
        )


class DeepSeekHarnessTurnDriver:
    """One Security plan-selection turn through Ordivon Harness and DeepSeek."""

    def __init__(
        self,
        *,
        secret_path: Path,
        harness_source_revision: str,
        harness_declared_version: str,
        harness_protocol_revision: str,
        host_binding: AgentLayerBinding,
        runtime_binding: AgentLayerBinding,
        allowed_actions: tuple[str, ...] = DEFAULT_ALLOWED_ACTIONS,
        budget: HarnessBudgetConfig | None = None,
        timeout_seconds: float = 90.0,
        max_response_bytes: int = 4_194_304,
        max_output_tokens: int = 4_096,
    ) -> None:
        if len(allowed_actions) < 2 or len(allowed_actions) != len(set(allowed_actions)):
            raise ValueError("Security model Actor requires unique competing actions")
        for action in allowed_actions:
            _text(action, "Security model Actor action")
        if host_binding.consumed or runtime_binding.consumed:
            raise ValueError("domain-loop baseline cannot claim Host or Runtime consumption")
        _text(harness_source_revision, "Harness source revision")
        _text(harness_declared_version, "Harness declared version")
        _text(harness_protocol_revision, "Harness protocol revision")
        self._allowed_actions = allowed_actions
        self.budget = HarnessBudgetConfig() if budget is None else budget
        self.harness_source_revision = harness_source_revision
        self.harness_declared_version = harness_declared_version
        self.harness_protocol_revision = harness_protocol_revision
        self.host_binding = host_binding
        self.runtime_binding = runtime_binding

        try:
            domain_module = importlib.import_module("ordivon_harness.domain_tools")
            deepseek_module = importlib.import_module("ordivon_harness.ordivon.deepseek")
            version_module = importlib.import_module("ordivon_harness.version")
        except ImportError as error:
            raise RuntimeError(
                "ordivon-harness and its pinned Host/Protocol dependencies are required"
            ) from error
        settings_type = deepseek_module.DeepSeekSettings
        adapter_type = deepseek_module.DeepSeekTurnAdapter
        self._domain_module = domain_module
        self._settings = settings_type.from_secret_file(
            secret_path,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            max_output_tokens=max_output_tokens,
        )
        if self._settings.model != "deepseek-v4-flash":
            raise ValueError("Security P0 admits DeepSeek Flash only")
        if not self._settings.credential_scope_id.startswith("credential-scope:"):
            raise ValueError("DeepSeek secret requires an explicit credentialScopeId")
        self._adapter = adapter_type(self._settings)
        package_version = version_module.package_version
        self._harness_runtime_metadata_version = str(package_version())

    @property
    def credential_scope_id(self) -> str:
        return cast(str, self._settings.credential_scope_id)

    @property
    def requested_model_id(self) -> str:
        return cast(str, self._adapter.model_id)

    @property
    def allowed_actions(self) -> tuple[str, ...]:
        return self._allowed_actions

    @property
    def execution_identity(self) -> JsonObject:
        identity: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security-agent-stack-identity",
            "provider": {
                "providerId": "provider:deepseek",
                "adapterId": str(self._adapter.adapter_id),
                "requestedModelId": self.requested_model_id,
                "credentialScopeId": self.credential_scope_id,
                "baseUrl": str(self._settings.base_url),
                "timeoutSeconds": float(self._settings.timeout_seconds),
                "maxResponseBytes": int(self._settings.max_response_bytes),
                "maxOutputTokens": int(self._settings.max_output_tokens),
                "thinking": "disabled",
            },
            "harness": {
                "componentId": "ordivon-harness",
                "sourceRevision": self.harness_source_revision,
                "declaredVersion": self.harness_declared_version,
                "runtimeMetadataVersion": self._harness_runtime_metadata_version,
                "protocolSourceRevision": self.harness_protocol_revision,
                "mode": "domain-tool-loop-v1",
                "sessionMode": "fresh-per-tick",
                "memoryMode": "explicit-prior-results",
                "budget": self.budget.to_dict(),
            },
            "host": self.host_binding.to_dict(),
            "runtime": self.runtime_binding.to_dict(),
            "security": {
                "component": security_source_identity(),
                "actorBackendId": BACKEND_ID,
                "promptRevision": PROMPT_REVISION,
                "domainId": DOMAIN_ID,
                "toolName": TOOL_NAME,
                "allowedActions": list(self.allowed_actions),
                "observationBoundary": "actor-specific-visible-state-only",
            },
        }
        validate_json(identity)
        return identity

    def _catalog(self) -> Any:
        tool_definition = self._domain_module.AgentToolDefinition
        catalog_type = self._domain_module.DomainToolCatalog
        return catalog_type(
            domain_id=DOMAIN_ID,
            revision=PROMPT_REVISION,
            tools=(
                tool_definition(
                    TOOL_NAME,
                    "Select exactly one admitted CAGE team plan for this observation.",
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "plan": {
                                "type": "string",
                                "enum": list(self.allowed_actions),
                            }
                        },
                        "required": ["plan"],
                    },
                ),
            ),
        )

    def _run_budget(self) -> Any:
        budget_type = self._domain_module.RunBudget
        return budget_type(
            self.budget.max_model_calls,
            self.budget.max_tool_calls,
            self.budget.max_observation_bytes,
            self.budget.max_wall_time_ms,
            self.budget.max_total_tokens,
            self.budget.max_model_retries,
            self.budget.max_tool_corrections,
            self.budget.max_observation_only_turns,
            self.budget.max_no_progress_turns,
            self.budget.max_model_observation_bytes,
        )

    def run_turn(
        self,
        *,
        actor_id: str,
        side: str,
        objective: str,
        observation: ActorObservation,
        prior_results: tuple[ActorActionResult, ...],
    ) -> AgentTurnEvidence:
        if observation.actor_id != actor_id:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.MALFORMED,
                "Harness driver received another Actor's observation",
            )
        context: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security-agent-turn-context",
            "promptRevision": PROMPT_REVISION,
            "actorId": actor_id,
            "side": side,
            "objective": objective,
            "observation": observation.to_dict(),
            "priorActionResults": [result.to_dict() for result in prior_results[-4:]],
            "rules": {
                "hiddenTruthAvailable": False,
                "mustUseGrantedTool": True,
                "mustChooseExactlyOnePlan": True,
                "mustNotInventActions": True,
            },
        }
        context_digest = canonical_digest(context)
        token = context_digest.removeprefix("sha256:")[:16]
        actor_token = actor_id.removeprefix("actor:")
        assignment_id = f"assignment:security:{actor_token}:tick-{observation.tick}:{token}"
        harness_run_id = f"harness-run:security:{actor_token}:tick-{observation.tick}:{token}"
        catalog = self._catalog()
        observation_type = self._domain_module.ToolObservation
        bridge = _PlanSelectionBridge(
            catalog=catalog,
            observation_type=observation_type,
            bridge_identity={
                "bridgeId": "bridge:security-cage-team-plan-v1",
                "promptRevision": PROMPT_REVISION,
                "actorId": actor_id,
                "side": side,
                "contextDigest": context_digest,
                "agentStackIdentityDigest": canonical_digest(self.execution_identity),
            },
            allowed_actions=self.allowed_actions,
        )
        runner_type = self._domain_module.DomainToolLoopRunner
        plan_type = self._domain_module.DomainToolLoopPlan
        runner = runner_type(self._adapter, bridge)
        messages: tuple[dict[str, JsonValue], ...] = (
            {
                "role": "system",
                "content": (
                    "You are one bounded actor in an authorized adversarial simulation. "
                    "Use only the actor-specific visible observation. Never infer hidden "
                    "world truth. Call select_team_plan exactly once, then submit a "
                    "candidate_completed conclusion explaining the decision."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    context,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )
        plan = plan_type(
            harness_run_id=harness_run_id,
            assignment_id=assignment_id,
            context_digest=context_digest,
            initial_messages=messages,
            allowed_tools=(TOOL_NAME,),
            budget=self._run_budget(),
        )
        try:
            result = runner.run(plan)
        except TimeoutError as error:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.TIMEOUT,
                "Harness model turn timed out",
            ) from error
        except Exception as error:  # noqa: BLE001 - dynamic Provider boundary.
            details: JsonObject = {"errorType": type(error).__name__}
            failure_code = getattr(error, "failure_code", None)
            dispatch_safety = getattr(error, "dispatch_safety", None)
            if failure_code is not None:
                details["providerFailureCode"] = str(getattr(failure_code, "value", failure_code))
            if dispatch_safety is not None:
                details["providerDispatchSafety"] = str(
                    getattr(dispatch_safety, "value", dispatch_safety)
                )
            raise AgentTurnDriverError(
                ActorProposalFailureCode.PROVIDER_ERROR,
                f"Harness model turn failed: {type(error).__name__}",
                details=details,
            ) from error
        stop_code = str(getattr(result.stop_code, "value", result.stop_code))
        if stop_code != "candidate_completed":
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                f"Harness stopped before a candidate action: {stop_code}",
                details={
                    "stopCode": stop_code,
                    "usage": _json_object_copy(result.usage),
                },
            )
        if bridge.selected_action is None:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.MALFORMED,
                "Harness concluded without selecting a team plan",
            )
        if result.conclusion is None:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.MALFORMED,
                "Harness candidate completion omitted its conclusion",
            )
        trace = _json_object_copy(result.trace.to_dict())
        usage = _json_object_copy(result.usage)
        raw_effective = usage.get("effectiveModelIds", [])
        effective_models = (
            tuple(item for item in raw_effective if isinstance(item, str))
            if isinstance(raw_effective, list)
            else ()
        )
        if not effective_models:
            effective_models = (self.requested_model_id,)
        if any(model != self.requested_model_id for model in effective_models):
            raise AgentTurnDriverError(
                ActorProposalFailureCode.PROVIDER_ERROR,
                "DeepSeek effective model differs from the requested model",
                details={
                    "requestedModelId": self.requested_model_id,
                    "effectiveModelIds": list(effective_models),
                },
            )
        return AgentTurnEvidence(
            harness_run_id=harness_run_id,
            assignment_id=assignment_id,
            context_digest=context_digest,
            selected_action=bridge.selected_action,
            rationale=str(result.conclusion.summary),
            stop_code=stop_code,
            trace=trace,
            trace_digest=canonical_digest(trace),
            usage=usage,
            requested_model_id=self.requested_model_id,
            effective_model_ids=effective_models,
            credential_scope_id=self.credential_scope_id,
        )


__all__ = [
    "AgentLayerBinding",
    "AgentTurnDriver",
    "AgentTurnDriverError",
    "AgentTurnEvidence",
    "BACKEND_ID",
    "DEFAULT_ALLOWED_ACTIONS",
    "DeepSeekHarnessTurnDriver",
    "HarnessBudgetConfig",
    "PROMPT_REVISION",
]
