from __future__ import annotations

import importlib
import json
import math
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest, validate_json
from ordivon_security.contest.model import ActorActionResult, ActorObservation

from .agent_stack import (
    PROMPT_REVISION,
    TOOL_NAME,
    AgentLayerBinding,
    AgentTurnDriverError,
    AgentTurnEvidence,
    DeepSeekHarnessTurnDriver,
    _json_object_copy,
)
from .protocol import ActorProposalFailureCode


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


def _host_json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Host Context cannot encode non-finite floating-point values")
        return {
            "kind": "ordivon.canonical-float",
            "decimal": format(value, ".17g"),
        }
    if isinstance(value, (list, tuple)):
        return [_host_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("Host Context object keys must be strings")
            normalized[key] = _host_json_value(item)
        return normalized
    raise TypeError(f"unsupported Host Context value: {type(value).__name__}")


def _host_json_object(value: JsonObject) -> JsonObject:
    normalized = _host_json_value(value)
    if not isinstance(normalized, dict):
        raise TypeError("Host Context normalization did not produce an object")
    return normalized


def _model_context_from_compiled(
    compiled_context: Any,
    *,
    context_object_digest: str,
) -> JsonObject:
    _digest(context_object_digest, "Host Context object digest")
    value = compiled_context.to_dict()
    if not isinstance(value, dict):
        raise TypeError("compiled Host Context must encode as an object")
    payload = value.get("payload")
    manifest = value.get("manifest")
    if not isinstance(payload, dict) or not isinstance(manifest, dict):
        raise ValueError("compiled Host Context lacks payload or manifest")
    task_contract_digest = payload.get("taskContractDigest")
    if not isinstance(task_contract_digest, str):
        raise ValueError("compiled Host Context Task Contract identity is malformed")
    _digest(task_contract_digest, "compiled Host Task Contract digest")

    blocks = payload.get("blocks")
    selected_ids = manifest.get("selectedBlockIds")
    if (
        not isinstance(blocks, list)
        or not blocks
        or not isinstance(selected_ids, list)
        or any(not isinstance(item, str) for item in selected_ids)
    ):
        raise ValueError("compiled Host Context selection is malformed")
    selected: list[JsonValue] = []
    seen: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("compiled Host Context block is malformed")
        block_id = block.get("blockId")
        payload_value = block.get("payload")
        payload_digest = block.get("payloadDigest")
        if (
            not isinstance(block_id, str)
            or not isinstance(payload_value, dict)
            or not isinstance(payload_digest, str)
        ):
            raise ValueError("compiled Host Context block identity is malformed")
        _text(block_id, "compiled Host Context block identity", prefix="context-block")
        _digest(payload_digest, "compiled Host Context block payload digest")
        objective = payload_value.get("objective")
        observation = payload_value.get("observationProjection")
        prior_results = payload_value.get("priorActionResults")
        rules = payload_value.get("rules")
        if (
            not isinstance(objective, str)
            or not isinstance(observation, dict)
            or not isinstance(prior_results, list)
            or not isinstance(rules, dict)
        ):
            raise ValueError("selected Host Context block lacks model semantics")
        validate_json(observation)
        validate_json(prior_results)
        validate_json(rules)
        seen.append(block_id)
        selected.append(
            {
                "objective": objective,
                "observation": observation,
                "priorActionResults": prior_results,
                "rules": rules,
            }
        )
    if seen != selected_ids:
        raise ValueError("compiled Host Context blocks differ from its selection manifest")
    model_context: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security-host-model-context",
        "selectedContext": selected,
    }
    validate_json(model_context)
    return model_context


def _candidate_completed_conclusion(evidence: AgentTurnEvidence) -> JsonObject:
    """Retain Harness structured unknowns instead of flattening them to an empty array.

    Completion-with-unknowns is epistemically distinct from completion-with-no-
    unknowns; discarding ``unresolved_unknowns`` would manufacture certainty and
    violate the Security constitutional rule to preserve epistemic uncertainty.
    """
    return {
        "status": "candidate_completed",
        "summary": evidence.rationale,
        "unresolved_unknowns": list(evidence.unresolved_unknowns),
    }


class HostAssignedDeepSeekHarnessTurnDriver:
    """P0-B: Host owns the durable lifecycle around one bounded DeepSeek Harness turn."""

    def __init__(
        self,
        *,
        delegate: DeepSeekHarnessTurnDriver,
        host_state_root: Path,
        host_state_namespace: str,
        host_source_revision: str,
        context_token_budget: int = 12_000,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        _text(host_state_namespace, "Host state namespace", prefix="host-state")
        _text(host_source_revision, "Host source revision")
        if context_token_budget < 1:
            raise ValueError("Host Context token budget must be positive")
        if host_state_root.exists() and host_state_root.is_symlink():
            raise ValueError("Host state root cannot be a symlink")
        baseline_identity = delegate.execution_identity
        baseline_host = baseline_identity.get("host")
        baseline_runtime = baseline_identity.get("runtime")
        if not isinstance(baseline_host, dict) or baseline_host.get("consumed") is not False:
            raise ValueError("P0-B delegate must begin from a non-Host baseline")
        if not isinstance(baseline_runtime, dict) or baseline_runtime.get("consumed") is not False:
            raise ValueError("P0-B must preserve Runtime as an unconsumed variable")

        try:
            host_module = importlib.import_module("ordivon_host")
            host_cognition_module = importlib.import_module("ordivon_host.cognition")
            harness_module = importlib.import_module("ordivon_harness")
            harness_ordivon_module = importlib.import_module("ordivon_harness.ordivon")
        except ImportError as error:
            raise RuntimeError(
                "P0-B requires the pinned Host and Harness source packages"
            ) from error

        self._host_module = host_module
        self._host_cognition_module = host_cognition_module
        self._harness_module = harness_module
        self._harness_ordivon_module = harness_ordivon_module
        self.delegate = delegate
        self.host_state_root = host_state_root
        self.host_state_namespace = host_state_namespace
        self.host_source_revision = host_source_revision
        self.context_token_budget = context_token_budget
        self.clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self.host_binding = AgentLayerBinding(
            component_id="ordivon-host",
            revision=host_source_revision,
            mode="durable-task-assignment-completion-v1",
            consumed=True,
            configuration={
                "experimentalVariant": "security-host-harness-provider",
                "stateNamespaceId": host_state_namespace,
                "contextCompiler": "HarnessContextCompiler",
                "modelInputProjection": "host-selected-semantics-v1",
                "assignmentMode": "external-no-runtime-v1",
                "completionVerifier": "security-cage-team-plan-verifier-v1",
                "ownedLifecycle": [
                    "task",
                    "task-contract",
                    "context-selection",
                    "assignment",
                    "run-receipt",
                    "completion-proposal",
                    "completion-decision",
                ],
            },
        )

    @property
    def credential_scope_id(self) -> str:
        return self.delegate.credential_scope_id

    @property
    def requested_model_id(self) -> str:
        return self.delegate.requested_model_id

    @property
    def allowed_actions(self) -> tuple[str, ...]:
        return self.delegate.allowed_actions

    @property
    def execution_identity(self) -> JsonObject:
        identity = _json_object_copy(self.delegate.execution_identity)
        identity["host"] = self.host_binding.to_dict()
        harness = identity.get("harness")
        security = identity.get("security")
        if not isinstance(harness, dict) or not isinstance(security, dict):
            raise ValueError("P0-B delegate Agent stack identity is malformed")
        harness["mode"] = "host-assigned-domain-tool-loop-v1"
        harness["contextMode"] = "host-compiled-context-v1"
        harness["assignmentMode"] = "external-no-runtime-v1"
        security["experimentVariant"] = "security-host-harness-provider"
        validate_json(identity)
        return identity

    def _host_failure_details(
        self,
        *,
        task_id: str,
        assignment: Any | None = None,
        error: BaseException | None = None,
    ) -> JsonObject:
        details: JsonObject = {
            "hostTaskId": task_id,
            "hostStateNamespaceId": self.host_state_namespace,
        }
        if assignment is not None:
            details.update(
                {
                    "hostAssignmentId": str(assignment.assignment.assignment_id),
                    "hostAssignmentDigest": str(assignment.assignment.digest),
                    "hostTaskRevision": int(assignment.task_revision),
                }
            )
        if error is not None:
            details["errorType"] = type(error).__name__
        validate_json(details)
        return details

    def _security_context(
        self,
        *,
        actor_id: str,
        side: str,
        objective: str,
        observation: ActorObservation,
        prior_results: tuple[ActorActionResult, ...],
    ) -> JsonObject:
        if observation.actor_id != actor_id:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.MALFORMED,
                "Host-assigned driver received another Actor's observation",
            )
        try:
            from .agent_stack import project_cage_team_plan_observation

            projection = project_cage_team_plan_observation(observation)
        except ValueError as error:
            raise AgentTurnDriverError(
                ActorProposalFailureCode.MALFORMED,
                "Security Context Projection rejected the Actor observation",
                details={"errorType": type(error).__name__},
            ) from error
        context: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security-agent-turn-context",
            "promptRevision": PROMPT_REVISION,
            "contextProjectionRevision": projection["projectionRevision"],
            "actorId": actor_id,
            "side": side,
            "objective": objective,
            "sourceObservationDigest": canonical_digest(observation.to_dict()),
            "observationProjection": projection,
            "observationProjectionDigest": canonical_digest(projection),
            "priorActionResults": [result.to_dict() for result in prior_results[-4:]],
            "rules": {
                "hiddenTruthAvailable": False,
                "mustUseGrantedTool": True,
                "mustChooseExactlyOnePlan": True,
                "mustNotInventActions": True,
            },
        }
        validate_json(context)
        return context

    def _run_model(
        self,
        *,
        actor_id: str,
        side: str,
        model_context: JsonObject,
        context_digest: str,
        assignment_id: str,
        harness_run_id: str,
        host_task_id: str | None = None,
        host_task_revision: int | None = None,
        host_task_attempt_id: str | None = None,
        host_task_contract_digest: str | None = None,
        host_assignment_digest: str | None = None,
        host_assignment_generation: int | None = None,
    ) -> AgentTurnEvidence:
        _digest(context_digest, "Host-assigned Context digest")
        _text(assignment_id, "Host Assignment identity", prefix="assignment")
        _text(harness_run_id, "Host-assigned Harness Run identity", prefix="harness-run")
        catalog = self.delegate._catalog()
        observation_type = self.delegate._domain_module.ToolObservation
        from .agent_stack import _PlanSelectionBridge

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
        runner = self.delegate._domain_module.DomainToolLoopRunner(self.delegate._adapter, bridge)
        messages: tuple[dict[str, JsonValue], ...] = (
            {
                "role": "system",
                "content": (
                    "You are one bounded actor in an authorized adversarial simulation. "
                    "Use only the actor-specific Context selected and compiled by Host. "
                    "Finite CAGE floating-point values are represented as canonical-float "
                    "objects whose decimal field preserves the source value. Never infer "
                    "hidden world truth. Call select_team_plan exactly once, then submit a "
                    "candidate_completed conclusion explaining the decision. "
                    "The model proposes completion; Host independently decides durable "
                    "Task completion. Record genuine residual uncertainty honestly in "
                    "unresolved_unknowns; never manufacture certainty. Leave it empty only "
                    "when the decision is fully determined."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    model_context,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )
        plan = self.delegate._domain_module.DomainToolLoopPlan(
            harness_run_id=harness_run_id,
            assignment_id=assignment_id,
            context_digest=context_digest,
            initial_messages=messages,
            allowed_tools=(TOOL_NAME,),
            budget=self.delegate._run_budget(),
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
        trace = _json_object_copy(result.trace.to_dict())
        trace_digest = canonical_digest(trace)
        usage = _json_object_copy(result.usage)
        raw_effective = usage.get("effectiveModelIds", [])
        effective_models = (
            tuple(item for item in raw_effective if isinstance(item, str))
            if isinstance(raw_effective, list)
            else ()
        )
        if stop_code != "candidate_completed":
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                f"Harness stopped before a candidate action: {stop_code}",
                details={
                    "harnessRunId": harness_run_id,
                    "assignmentId": assignment_id,
                    "contextDigest": context_digest,
                    "stopCode": stop_code,
                    "selectedAction": bridge.selected_action,
                    "trace": trace,
                    "traceDigest": trace_digest,
                    "usage": usage,
                    "requestedModelId": self.requested_model_id,
                    "effectiveModelIds": list(effective_models),
                    "credentialScopeId": self.credential_scope_id,
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
            trace_digest=trace_digest,
            usage=usage,
            requested_model_id=self.requested_model_id,
            effective_model_ids=effective_models,
            credential_scope_id=self.credential_scope_id,
            unresolved_unknowns=tuple(
                str(item) for item in result.conclusion.unresolved_unknowns
            ),
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
        security_context = self._security_context(
            actor_id=actor_id,
            side=side,
            objective=objective,
            observation=observation,
            prior_results=prior_results,
        )
        runtime_layer = self.execution_identity.get("runtime")
        runtime_consumed = bool(
            isinstance(runtime_layer, dict) and runtime_layer.get("consumed") is True
        )
        experiment_variant = (
            "security-host-runtime-harness-provider"
            if runtime_consumed
            else "security-host-harness-provider"
        )
        source_observation_digest = canonical_digest(observation.to_dict())
        token = source_observation_digest.removeprefix("sha256:")[:16]
        namespace_token = canonical_digest(
            {"hostStateNamespaceId": self.host_state_namespace}
        ).removeprefix("sha256:")[:12]
        actor_token = actor_id.removeprefix("actor:")
        task_id = (
            f"task:security-host:{namespace_token}:{actor_token}:tick-{observation.tick}:{token}"
        )
        goal_id = f"goal:security-host:{namespace_token}:{actor_token}:{side}"
        node_id = (
            f"node:security-host:{namespace_token}:{actor_token}:tick-{observation.tick}:decide"
        )
        event_id = (
            f"event:security-host:{namespace_token}:{actor_token}:"
            f"tick-{observation.tick}:create:{token}"
        )
        contract_id = (
            f"task-contract:security-host:{namespace_token}:{actor_token}:"
            f"tick-{observation.tick}:{token}"
        )
        assignment: Any | None = None
        try:
            with self._host_module.HostStorage(self.host_state_root) as storage:
                existing = storage.journal.get_task(task_id)
                if existing is not None:
                    raise AgentTurnDriverError(
                        ActorProposalFailureCode.ACTOR_STOPPED,
                        "P0-B Host Task already exists; provider replay is blocked",
                        details={
                            "hostTaskId": task_id,
                            "hostTaskState": str(existing.state.value),
                            "hostTaskRevision": int(existing.revision),
                            "hostStateNamespaceId": self.host_state_namespace,
                        },
                    )
                self._host_module.HostKernel(
                    storage,
                    clock_ms=self.clock_ms,
                    owner_id=f"host:security-p0b:{actor_token}:task",
                ).create_task(
                    event_id=event_id,
                    kind=self._host_module.EventKind.TASK_CREATED,
                    task_id=task_id,
                    goal_id=goal_id,
                    payload={
                        "experimentVariant": experiment_variant,
                        "actorId": actor_id,
                        "side": side,
                        "tick": observation.tick,
                        "sourceObservationDigest": source_observation_digest,
                    },
                    frontier=(node_id,),
                )
                task_contract = self._harness_module.TaskContract(
                    contract_id=contract_id,
                    task_id=task_id,
                    objective={
                        "summary": objective,
                        "actorId": actor_id,
                        "side": side,
                        "tick": observation.tick,
                        "sourceObservationDigest": source_observation_digest,
                    },
                    acceptance_criteria={
                        "allowedActionTypes": list(self.allowed_actions),
                        "requireHarnessTrace": True,
                        "requireHostCompletionDecision": True,
                        "runtimeConsumed": runtime_consumed,
                    },
                    constraints=(
                        "Use only the deterministic Security Context Projection selected by Host.",
                        "Choose exactly one admitted team plan.",
                        (
                            (
                                "Bind physical Harness execution to one Runtime Job without "
                                "granting Runtime semantic completion authority."
                            )
                            if runtime_consumed
                            else (
                                "Do not claim Runtime execution or durable completion from "
                                "the model turn."
                            )
                        ),
                    ),
                )
                lifecycle = self._harness_module.HarnessHost(
                    storage,
                    clock_ms=self.clock_ms,
                    owner_id=f"host:security-p0b:{actor_token}:harness",
                )
                attempt = lifecycle.start_attempt(task_id, task_contract=task_contract)
                block = self._host_cognition_module.ContextBlock(
                    block_id=(
                        f"context-block:security-host:{actor_token}:tick-{observation.tick}:{token}"
                    ),
                    kind=self._host_cognition_module.BlockKind.TASK,
                    priority=100,
                    required=True,
                    freshness=self._host_cognition_module.Freshness.CURRENT,
                    source_digest=source_observation_digest,
                    payload=_host_json_object(security_context),
                )
                compiled_context = self._harness_ordivon_module.HarnessContextCompiler().compile(
                    attempt.descriptor,
                    self._harness_ordivon_module.HarnessContextRequest(
                        task_contract=task_contract,
                        blocks=(block,),
                    ),
                    token_budget=self.context_token_budget,
                )
                context_object = storage.put_object(
                    compiled_context.to_dict(), kind="compiled-context"
                )
                model_context = _model_context_from_compiled(
                    compiled_context,
                    context_object_digest=context_object.digest,
                )
                catalog = self.delegate._catalog()
                manifest = self._harness_ordivon_module.ordivon_harness_manifest()
                assignment = lifecycle.assign(
                    attempt,
                    manifest=manifest,
                    context_object_digest=context_object.digest,
                    tool_catalog_digest=str(catalog.digest),
                    required_capabilities=("tool_events", "usage"),
                    budget=self.delegate.budget.to_dict(),
                )
                run_id = (
                    f"harness-run:security-host:{actor_token}:tick-{observation.tick}:"
                    f"g{assignment.assignment.generation}:{token}"
                )
                started_at_ms = self.clock_ms()
                try:
                    evidence = self._run_model(
                        actor_id=actor_id,
                        side=side,
                        model_context=model_context,
                        context_digest=assignment.assignment.context_object_digest,
                        assignment_id=assignment.assignment.assignment_id,
                        harness_run_id=run_id,
                        host_task_id=task_id,
                        host_task_revision=assignment.task_revision,
                        host_task_attempt_id=attempt.descriptor.task_attempt_id,
                        host_task_contract_digest=task_contract.digest,
                        host_assignment_digest=assignment.assignment.digest,
                        host_assignment_generation=assignment.assignment.generation,
                    )
                except AgentTurnDriverError as error:
                    details = _json_object_copy(error.details)
                    details["hostLifecycle"] = self._host_failure_details(
                        task_id=task_id,
                        assignment=assignment,
                        error=error,
                    )
                    raise AgentTurnDriverError(error.code, str(error), details=details) from error
                finished_at_ms = max(started_at_ms, self.clock_ms())
                run_receipt = self._harness_module.HarnessRunReceipt(
                    harness_run_id=evidence.harness_run_id,
                    assignment_id=assignment.assignment.assignment_id,
                    assignment_generation=assignment.assignment.generation,
                    harness_id=assignment.assignment.target_harness_id,
                    harness_revision=self.delegate.harness_source_revision,
                    manifest_digest=assignment.assignment.harness_manifest_digest,
                    session_ref=None,
                    started_at_ms=started_at_ms,
                    finished_at_ms=finished_at_ms,
                    stop_reason="completed",
                    event_digest=evidence.trace_digest,
                    context_digest=assignment.assignment.context_object_digest,
                    tool_catalog_digest=assignment.assignment.tool_catalog_digest,
                    runtime_job_refs=(
                        () if evidence.runtime_job_id is None else (evidence.runtime_job_id,)
                    ),
                    artifact_refs=(),
                    usage=evidence.usage,
                    termination_code=evidence.stop_code,
                )
                recorded = lifecycle.record_run(
                    assignment,
                    run_receipt,
                    trace=evidence.trace,
                    conclusion=_candidate_completed_conclusion(evidence),
                )
                proposed = lifecycle.propose_completion(
                    recorded,
                    summary=evidence.rationale,
                    acceptance_results={
                        "actionType": evidence.selected_action,
                        "allowedActionTypes": list(self.allowed_actions),
                        "sourceObservationDigest": source_observation_digest,
                        "harnessTraceDigest": evidence.trace_digest,
                        "runtimeConsumed": runtime_consumed,
                    },
                    usage=evidence.usage,
                )

                def verify(proposal: Any) -> tuple[bool, str | None, JsonValue]:
                    results = proposal.acceptance_results
                    action = results.get("actionType")
                    accepted = bool(
                        isinstance(action, str)
                        and action in self.allowed_actions
                        and results.get("sourceObservationDigest") == source_observation_digest
                        and results.get("harnessTraceDigest") == evidence.trace_digest
                        and results.get("runtimeConsumed") is runtime_consumed
                        and (evidence.runtime_job_id is not None) is runtime_consumed
                        and proposal.harness_run_id == evidence.harness_run_id
                    )
                    return (
                        accepted,
                        None if accepted else "Security team-plan acceptance verification failed",
                        {
                            "verifier": "security-cage-team-plan-verifier-v1",
                            "accepted": accepted,
                            "actionType": action,
                            "sourceObservationDigest": source_observation_digest,
                            "harnessTraceDigest": evidence.trace_digest,
                        },
                    )

                decision = lifecycle.adjudicate_completion(
                    proposed,
                    artifact_exists=lambda _: True,
                    acceptance_verifier=verify,
                    verification_method="security-cage-team-plan-verifier-v1",
                )
                if not decision.decision.accepted:
                    raise AgentTurnDriverError(
                        ActorProposalFailureCode.ACTOR_STOPPED,
                        "Host rejected the Security CompletionProposal",
                        details={
                            "hostTaskId": task_id,
                            "completionDecisionDigest": decision.decision.digest,
                            "completionReasonCode": decision.decision.reason_code,
                        },
                    )
                return replace(
                    evidence,
                    host_task_id=task_id,
                    host_task_revision=decision.task_revision,
                    host_task_contract_digest=task_contract.digest,
                    host_context_object_digest=context_object.digest,
                    host_assignment_digest=assignment.assignment.digest,
                    host_run_receipt_digest=recorded.receipt.digest,
                    host_completion_proposal_digest=proposed.proposal.digest,
                    host_completion_decision_digest=decision.decision.digest,
                    host_completion_accepted=True,
                )
        except AgentTurnDriverError:
            raise
        except Exception as error:  # noqa: BLE001 - dynamic Host/Harness boundary.
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                f"Host lifecycle failed: {type(error).__name__}",
                details=self._host_failure_details(
                    task_id=task_id,
                    assignment=assignment,
                    error=error,
                ),
            ) from error


__all__ = ["HostAssignedDeepSeekHarnessTurnDriver"]
