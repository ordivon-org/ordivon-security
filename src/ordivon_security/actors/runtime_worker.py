from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

from .agent_stack import (
    AgentLayerBinding,
    AgentTurnDriverError,
    DeepSeekHarnessTurnDriver,
    HarnessBudgetConfig,
)
from .host_assigned import HostAssignedDeepSeekHarnessTurnDriver

_RESULT_MARKER = "ORDIVON_SECURITY_RUNTIME_RESULT="


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty trimmed text")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a positive number")
    result = float(value)
    if result <= 0:
        raise ValueError(f"{label} must be a positive number")
    return result


def _layer(value: object, label: str) -> AgentLayerBinding:
    data = _object(value, label)
    consumed = data.get("consumed")
    if not isinstance(consumed, bool):
        raise ValueError(f"{label}.consumed must be boolean")
    return AgentLayerBinding(
        component_id=_text(data.get("componentId"), f"{label}.componentId"),
        revision=_text(data.get("revision"), f"{label}.revision"),
        mode=_text(data.get("mode"), f"{label}.mode"),
        consumed=consumed,
        configuration=_object(data.get("configuration"), f"{label}.configuration"),
    )


def _budget(value: object) -> HarnessBudgetConfig:
    data = _object(value, "delegate budget")
    return HarnessBudgetConfig(
        max_model_calls=_integer(data.get("maxModelCalls"), "maxModelCalls", minimum=1),
        max_tool_calls=_integer(data.get("maxToolCalls"), "maxToolCalls", minimum=1),
        max_observation_bytes=_integer(
            data.get("maxObservationBytes"), "maxObservationBytes", minimum=1
        ),
        max_wall_time_ms=_integer(data.get("maxWallTimeMs"), "maxWallTimeMs", minimum=1),
        max_total_tokens=_integer(data.get("maxTotalTokens"), "maxTotalTokens", minimum=1),
        max_model_retries=_integer(data.get("maxModelRetries"), "maxModelRetries"),
        max_tool_corrections=_integer(data.get("maxToolCorrections"), "maxToolCorrections"),
        max_observation_only_turns=_integer(
            data.get("maxObservationOnlyTurns"), "maxObservationOnlyTurns"
        ),
        max_no_progress_turns=_integer(data.get("maxNoProgressTurns"), "maxNoProgressTurns"),
        max_model_observation_bytes=_integer(
            data.get("maxModelObservationBytes"),
            "maxModelObservationBytes",
            minimum=1,
        ),
    )


class _WorkerHostDriver(HostAssignedDeepSeekHarnessTurnDriver):
    def __init__(self, *, execution_identity: JsonObject, **kwargs: Any) -> None:
        self._worker_execution_identity = execution_identity
        super().__init__(**kwargs)

    @property
    def execution_identity(self) -> JsonObject:
        return self._worker_execution_identity


def _load_request(path: Path) -> JsonObject:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Runtime worker request must be a regular non-symlink file")
    value = json.loads(path.read_text(encoding="utf-8"))
    request = _object(value, "Runtime worker request")
    if request.get("schemaVersion") != 1:
        raise ValueError("Runtime worker request schemaVersion must be 1")
    if request.get("kind") != "ordivon.security-runtime-model-turn-request":
        raise ValueError("Runtime worker request kind is invalid")
    payload = _object(request.get("payload"), "Runtime worker payload")
    digest = _text(request.get("payloadDigest"), "Runtime worker payload digest")
    if canonical_digest(payload) != digest:
        raise ValueError("Runtime worker payload digest does not match")
    return request


def _execute(request: JsonObject, request_path: Path) -> JsonObject:
    payload = _object(request.get("payload"), "Runtime worker payload")
    delegate_config = _object(payload.get("delegate"), "delegate config")
    host_config = _object(payload.get("host"), "Host config")
    turn = _object(payload.get("turn"), "turn config")
    execution_identity = _object(payload.get("executionIdentity"), "execution identity")
    raw_actions = delegate_config.get("allowedActions")
    if not isinstance(raw_actions, list) or any(not isinstance(item, str) for item in raw_actions):
        raise ValueError("delegate allowedActions must be a string array")
    baseline = DeepSeekHarnessTurnDriver(
        secret_path=Path(_text(delegate_config.get("secretPath"), "delegate secretPath")),
        harness_source_revision=_text(
            delegate_config.get("harnessSourceRevision"), "Harness source revision"
        ),
        harness_declared_version=_text(
            delegate_config.get("harnessDeclaredVersion"), "Harness declared version"
        ),
        harness_protocol_revision=_text(
            delegate_config.get("harnessProtocolRevision"), "Harness protocol revision"
        ),
        host_binding=_layer(delegate_config.get("hostBinding"), "Host baseline binding"),
        runtime_binding=_layer(delegate_config.get("runtimeBinding"), "Runtime baseline binding"),
        allowed_actions=tuple(cast(list[str], raw_actions)),
        budget=_budget(delegate_config.get("budget")),
        timeout_seconds=_positive_number(delegate_config.get("timeoutSeconds"), "timeoutSeconds"),
        max_response_bytes=_integer(
            delegate_config.get("maxResponseBytes"), "maxResponseBytes", minimum=1
        ),
        max_output_tokens=_integer(
            delegate_config.get("maxOutputTokens"), "maxOutputTokens", minimum=1
        ),
    )
    driver = _WorkerHostDriver(
        execution_identity=execution_identity,
        delegate=baseline,
        host_state_root=request_path.parent / ".worker-host-unused",
        host_state_namespace=_text(host_config.get("stateNamespaceId"), "Host state namespace"),
        host_source_revision=_text(host_config.get("sourceRevision"), "Host source revision"),
        context_token_budget=_integer(
            host_config.get("contextTokenBudget"), "Host Context token budget", minimum=1
        ),
    )
    model_context = _object(turn.get("modelContext"), "model Context")
    evidence = driver._run_model(
        actor_id=_text(turn.get("actorId"), "Actor identity"),
        side=_text(turn.get("side"), "Actor side"),
        model_context=model_context,
        context_digest=_text(turn.get("contextDigest"), "Context digest"),
        assignment_id=_text(turn.get("assignmentId"), "Assignment identity"),
        harness_run_id=_text(turn.get("harnessRunId"), "Harness Run identity"),
    )
    result: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security-runtime-model-turn-result",
        "status": "succeeded",
        "requestPayloadDigest": request["payloadDigest"],
        "evidence": evidence.to_dict(include_trace=True),
    }
    validate_json(result)
    return result


def _emit(value: JsonObject) -> None:
    print(
        _RESULT_MARKER
        + json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Execute one P0-C Harness model turn")
    parser.add_argument("--request", type=Path, required=True)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        request = _load_request(args.request)
        result = _execute(request, args.request)
    except AgentTurnDriverError as error:
        code = getattr(error.code, "value", error.code)
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security-runtime-model-turn-result",
            "status": "actor-failed",
            "failureCode": str(code),
            "message": str(error),
            "details": error.details,
        }
        validate_json(result)
        _emit(result)
        raise SystemExit(2) from error
    except Exception as error:  # noqa: BLE001 - executable process boundary.
        result = {
            "schemaVersion": 1,
            "kind": "ordivon.security-runtime-model-turn-result",
            "status": "worker-failed",
            "failureCode": "runtime-worker-error",
            "message": f"Runtime worker failed: {type(error).__name__}",
            "details": {"errorType": type(error).__name__},
        }
        validate_json(result)
        _emit(result)
        raise SystemExit(3) from error
    _emit(result)


if __name__ == "__main__":
    main()


__all__ = ["build_parser", "main"]
