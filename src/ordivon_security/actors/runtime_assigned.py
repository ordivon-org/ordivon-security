from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json

from .agent_stack import (
    AgentLayerBinding,
    AgentTurnDriverError,
    AgentTurnEvidence,
    DeepSeekHarnessTurnDriver,
)
from .agent_stack import (
    copy_json_object as _json_object_copy,
)
from .host_assigned import HostAssignedDeepSeekHarnessTurnDriver
from .protocol import ActorProposalFailureCode
from .runtime_mcp import RuntimeMcpClient, RuntimeMcpError, read_runtime_token

_RESULT_MARKER = "ORDIVON_SECURITY_RUNTIME_RESULT="
_RUNTIME_DELIVERY_DISPOSITIONS = {
    "in_progress",
    "committed",
    "reconciliation_required",
    "unknown",
}


def _runtime_delivery_state(payload: JsonObject) -> str:
    """Classify the safe next action from exact Runtime execution/delivery truth."""

    execution_terminal = payload.get("executionTerminal")
    execution_disposition = payload.get("executionDisposition")
    delivery_disposition = payload.get("deliveryDisposition")
    recovery_required = payload.get("recoveryRequired")
    result_available = payload.get("resultAvailable")
    semantic_completion_evaluated = payload.get("semanticCompletionEvaluated")

    if not isinstance(execution_terminal, bool):
        raise RuntimeMcpError("Runtime observation omitted executionTerminal")
    if execution_disposition is not None and not isinstance(execution_disposition, str):
        raise RuntimeMcpError("Runtime executionDisposition is invalid")
    if delivery_disposition not in _RUNTIME_DELIVERY_DISPOSITIONS:
        raise RuntimeMcpError("Runtime deliveryDisposition is invalid")
    if not isinstance(recovery_required, bool):
        raise RuntimeMcpError("Runtime observation omitted recoveryRequired")
    if not isinstance(result_available, bool):
        raise RuntimeMcpError("Runtime observation omitted resultAvailable")
    if semantic_completion_evaluated is not False:
        raise RuntimeMcpError("Runtime must not claim Security/domain semantic completion")

    if recovery_required or delivery_disposition == "reconciliation_required":
        return "reconcile"
    if delivery_disposition == "unknown":
        if not execution_terminal or execution_disposition != "lost" or not result_available:
            raise RuntimeMcpError("Runtime unknown delivery projection is inconsistent")
        return "unknown"
    if delivery_disposition == "in_progress":
        if execution_terminal or execution_disposition is not None or result_available:
            raise RuntimeMcpError("Runtime in-progress projection is inconsistent")
        return "reconcile"
    if not execution_terminal or execution_disposition is None or not result_available:
        raise RuntimeMcpError("Runtime committed terminal projection is incomplete")
    return "terminal"


def _text(value: object, label: str, *, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty trimmed text")
    if prefix is not None and not value.startswith(prefix + ":"):
        raise ValueError(f"{label} must start with {prefix}:")
    return value


def _digest(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 71 or not text.startswith("sha256:"):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    validate_json(value)
    return cast(JsonObject, value)


def _private_directory(path: Path) -> Path:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise ValueError("Runtime request root must be a private directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path.resolve()


def _read_artifact(
    client: RuntimeMcpClient,
    *,
    job_id: str,
    descriptor: JsonObject,
) -> str:
    artifact_id = _text(descriptor.get("artifactId"), "Runtime Artifact identity")
    expected_digest = _digest(descriptor.get("digest"), "Runtime Artifact digest")
    retained = descriptor.get("retainedBytes")
    if not isinstance(retained, int) or isinstance(retained, bool) or retained < 0:
        raise RuntimeMcpError("Runtime Artifact retained byte count is invalid")
    if descriptor.get("truncated") is True:
        raise RuntimeMcpError("P0-C Runtime Artifact was truncated")
    offset = 0
    chunks: list[str] = []
    while True:
        result = client.call_tool(
            "artifact.read",
            {
                "schemaVersion": 1,
                "jobId": job_id,
                "artifactId": artifact_id,
                "offset": offset,
                "maxBytes": min(4_194_304, max(1, retained - offset)),
            },
        )
        if _digest(result.get("digest"), "Runtime read Artifact digest") != expected_digest:
            raise RuntimeMcpError("Runtime Artifact descriptor and read digest differ")
        content = result.get("content")
        next_offset = result.get("nextOffset")
        eof = result.get("eof")
        if not isinstance(content, str) or not isinstance(next_offset, int) or next_offset < offset:
            raise RuntimeMcpError("Runtime Artifact read projection is malformed")
        chunks.append(content)
        offset = next_offset
        if eof is True:
            if offset != retained:
                raise RuntimeMcpError(
                    "Runtime Artifact read byte count differs from its descriptor"
                )
            break
        if offset >= retained:
            raise RuntimeMcpError("Runtime Artifact read stopped without EOF")
    return "".join(chunks)


def _parse_worker_result(stdout: str) -> JsonObject:
    marked = [
        line[len(_RESULT_MARKER) :]
        for line in stdout.splitlines()
        if line.startswith(_RESULT_MARKER)
    ]
    if len(marked) != 1:
        raise RuntimeMcpError("Runtime worker stdout lacks one canonical result marker")
    try:
        value = json.loads(marked[0])
    except json.JSONDecodeError as error:
        raise RuntimeMcpError("Runtime worker result is invalid JSON") from error
    return _object(value, "Runtime worker result")


def _evidence_from_worker(value: JsonObject) -> AgentTurnEvidence:
    effective = value.get("effectiveModelIds")
    if not isinstance(effective, list) or any(not isinstance(item, str) for item in effective):
        raise RuntimeMcpError("Runtime worker effective model identities are malformed")
    trace = _object(value.get("trace"), "Runtime worker Harness Trace")
    usage = _object(value.get("usage"), "Runtime worker usage")
    return AgentTurnEvidence(
        harness_run_id=_text(
            value.get("harnessRunId"), "Harness Run identity", prefix="harness-run"
        ),
        assignment_id=_text(value.get("assignmentId"), "Assignment identity", prefix="assignment"),
        context_digest=_digest(value.get("contextDigest"), "Context digest"),
        selected_action=_text(value.get("selectedAction"), "selected action"),
        rationale=_text(value.get("rationale"), "rationale"),
        stop_code=_text(value.get("stopCode"), "stop code"),
        trace=trace,
        trace_digest=_digest(value.get("traceDigest"), "Harness Trace digest"),
        usage=usage,
        requested_model_id=_text(value.get("requestedModelId"), "requested model identity"),
        effective_model_ids=tuple(cast(list[str], effective)),
        credential_scope_id=_text(
            value.get("credentialScopeId"), "credential scope identity", prefix="credential-scope"
        ),
    )


class RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver(HostAssignedDeepSeekHarnessTurnDriver):
    """P0-C: Runtime owns physical execution of one Host-assigned Harness turn."""

    def __init__(
        self,
        *,
        delegate: DeepSeekHarnessTurnDriver,
        host_state_root: Path,
        host_state_namespace: str,
        host_source_revision: str,
        runtime_source_revision: str,
        runtime_endpoint: str,
        runtime_token_file: Path,
        runtime_request_root: Path,
        security_source_repo: Path,
        security_source_revision: str,
        harness_source: Path,
        host_source: Path,
        protocol_source: Path,
        python_executable: Path,
        context_token_budget: int = 12_000,
        runtime_timeout_ms: int = 300_000,
        client_factory: Callable[..., RuntimeMcpClient] = RuntimeMcpClient,
    ) -> None:
        super().__init__(
            delegate=delegate,
            host_state_root=host_state_root,
            host_state_namespace=host_state_namespace,
            host_source_revision=host_source_revision,
            context_token_budget=context_token_budget,
        )
        _text(runtime_source_revision, "Runtime source revision")
        _text(security_source_revision, "Security source revision")
        if runtime_timeout_ms < 1:
            raise ValueError("Runtime timeout must be positive")
        if not security_source_repo.is_absolute() or not security_source_repo.is_dir():
            raise ValueError("Security source repository must be an absolute directory")
        for path, label in (
            (harness_source, "Harness source"),
            (host_source, "Host source"),
            (protocol_source, "Protocol source"),
        ):
            if not path.is_absolute() or not (path / "src").is_dir():
                raise ValueError(f"{label} must be an absolute package source")
        if not python_executable.is_absolute() or not python_executable.is_file():
            raise ValueError("Runtime Python executable must be an absolute file")
        self.runtime_source_revision = runtime_source_revision
        self.runtime_endpoint = runtime_endpoint
        self.runtime_token_file = runtime_token_file.resolve()
        self.runtime_request_root = _private_directory(runtime_request_root)
        self.security_source_repo = security_source_repo.resolve()
        self.security_source_revision = security_source_revision
        self.harness_source = harness_source.resolve()
        self.host_source = host_source.resolve()
        self.protocol_source = protocol_source.resolve()
        self.python_executable = python_executable.resolve()
        self.runtime_timeout_ms = runtime_timeout_ms
        self.client_factory = client_factory
        self.runtime_binding = AgentLayerBinding(
            component_id="ordivon-runtime",
            revision=runtime_source_revision,
            mode="host-assignment-runtime-job-v1",
            consumed=True,
            configuration={
                "experimentalVariant": "security-host-runtime-harness-provider",
                "transport": "mcp-http-loopback",
                "executionProfile": "trusted_local",
                "worker": "ordivon.security-runtime-model-turn-v1",
                "foreignReferenceBinding": "host-task-attempt-assignment-harness-run-v1",
                "ownedLifecycle": [
                    "workspace",
                    "job",
                    "attempt",
                    "process-exit",
                    "stdout-artifact",
                    "terminal-evidence",
                    "exact-request-replay",
                    "job-recovery-lookup",
                ],
                "semanticCompletionAuthority": False,
            },
        )

    @property
    def execution_identity(self) -> JsonObject:
        identity = _json_object_copy(super().execution_identity)
        identity["runtime"] = self.runtime_binding.to_dict()
        harness = identity.get("harness")
        security = identity.get("security")
        if not isinstance(harness, dict) or not isinstance(security, dict):
            raise ValueError("P0-C Agent stack identity is malformed")
        harness["mode"] = "host-assigned-runtime-executed-domain-tool-loop-v1"
        harness["assignmentMode"] = "external-runtime-job-v1"
        host = identity.get("host")
        if not isinstance(host, dict):
            raise ValueError("P0-C Host identity is malformed")
        host_configuration = host.get("configuration")
        if not isinstance(host_configuration, dict):
            raise ValueError("P0-C Host configuration is malformed")
        host_configuration["assignmentMode"] = "external-runtime-job-v1"
        host_configuration["experimentalVariant"] = "security-host-runtime-harness-provider"
        security["experimentVariant"] = "security-host-runtime-harness-provider"
        validate_json(identity)
        return identity

    def _worker_request(
        self,
        *,
        actor_id: str,
        side: str,
        model_context: JsonObject,
        context_digest: str,
        assignment_id: str,
        harness_run_id: str,
    ) -> JsonObject:
        payload: JsonObject = {
            "delegate": {
                "secretPath": str(self.delegate.secret_path),
                "harnessSourceRevision": self.delegate.harness_source_revision,
                "harnessDeclaredVersion": self.delegate.harness_declared_version,
                "harnessProtocolRevision": self.delegate.harness_protocol_revision,
                "hostBinding": self.delegate.host_binding.to_dict(),
                "runtimeBinding": self.delegate.runtime_binding.to_dict(),
                "allowedActions": list(self.delegate.allowed_actions),
                "budget": self.delegate.budget.to_dict(),
                "timeoutSeconds": self.delegate.timeout_seconds,
                "maxResponseBytes": self.delegate.max_response_bytes,
                "maxOutputTokens": self.delegate.max_output_tokens,
            },
            "host": {
                "stateNamespaceId": self.host_state_namespace,
                "sourceRevision": self.host_source_revision,
                "contextTokenBudget": self.context_token_budget,
            },
            "turn": {
                "actorId": actor_id,
                "side": side,
                "modelContext": model_context,
                "contextDigest": context_digest,
                "assignmentId": assignment_id,
                "harnessRunId": harness_run_id,
            },
            "executionIdentity": self.execution_identity,
        }
        request: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security-runtime-model-turn-request",
            "payload": payload,
            "payloadDigest": canonical_digest(payload),
        }
        validate_json(request)
        return request

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
        required = (
            host_task_id,
            host_task_revision,
            host_task_attempt_id,
            host_task_contract_digest,
            host_assignment_digest,
            host_assignment_generation,
        )
        if any(value is None for value in required):
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                "P0-C Runtime execution lacks complete Host foreign references",
            )
        assert host_task_id is not None
        assert host_task_revision is not None
        assert host_task_attempt_id is not None
        assert host_task_contract_digest is not None
        assert host_assignment_digest is not None
        assert host_assignment_generation is not None
        request = self._worker_request(
            actor_id=actor_id,
            side=side,
            model_context=model_context,
            context_digest=context_digest,
            assignment_id=assignment_id,
            harness_run_id=harness_run_id,
        )
        request_digest = _digest(request["payloadDigest"], "Runtime worker request digest")
        token = request_digest.removeprefix("sha256:")[:16]
        actor_token = actor_id.removeprefix("actor:")
        request_path = self.runtime_request_root / f"{actor_token}-{token}.json"
        if request_path.exists():
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                "P0-C Runtime worker request path already exists; replay is blocked",
                details={"runtimeRequestDigest": request_digest},
            )
        file_descriptor = os.open(
            request_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    request,
                    stream,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                stream.write("\n")
        except Exception:
            request_path.unlink(missing_ok=True)
            raise

        workspace_id = f"security-p0c-{actor_token}-{token}"
        client_request_id = (
            f"request:security-p0c:{actor_token}:g{host_assignment_generation}:{token}"
        )
        runtime_job_id: str | None = None
        runtime_attempt_id: str | None = None
        terminal_observed = False
        dispatch_attempted = False
        try:
            token_value = read_runtime_token(self.runtime_token_file)
            client = self.client_factory(
                self.runtime_endpoint,
                token_value,
                f"ordivon-security-p0c-{actor_token}",
                timeout_seconds=30.0,
            )
            tool_catalog_digest = client.discover_tool_catalog_digest()
            opened = client.call_tool(
                "workspace.open",
                {
                    "schemaVersion": 1,
                    "workspaceId": workspace_id,
                    "sourceRepo": str(self.security_source_repo),
                    "sourceRevision": self.security_source_revision,
                },
            )
            if opened.get("workspaceId") != workspace_id:
                raise RuntimeMcpError("Runtime opened a different Workspace identity")
            if opened.get("sourceRevision") != self.security_source_revision:
                raise RuntimeMcpError("Runtime Workspace source revision differs from P0-C")
            python_path = ":".join(
                (
                    "src",
                    str(self.protocol_source / "src"),
                    str(self.host_source / "src"),
                    str(self.harness_source / "src"),
                )
            )
            execution: JsonObject = {
                "workspaceId": workspace_id,
                "executable": str(self.python_executable),
                "args": [
                    "-m",
                    "ordivon_security.actors.runtime_worker",
                    "--request",
                    str(request_path),
                ],
                "cwdRelative": ".",
                "env": {
                    "PYTHONPATH": python_path,
                    "PYTHONNOUSERSITE": "1",
                },
                "timeoutMs": self.runtime_timeout_ms,
                "stdoutLimitBytes": 4_194_304,
                "stderrLimitBytes": 262_144,
                "budget": {
                    "memoryMaxBytes": 2_147_483_648,
                    "tasksMax": 256,
                    "cpuQuotaPercent": 400,
                },
                "executionProfile": "trusted_local",
                "foreignReferences": [
                    {
                        "namespace": "ordivon.host",
                        "type": "task",
                        "id": host_task_id,
                        "generation": str(host_task_revision),
                        "digest": host_task_contract_digest,
                    },
                    {
                        "namespace": "ordivon.host",
                        "type": "task-attempt",
                        "id": host_task_attempt_id,
                        "generation": "1",
                    },
                    {
                        "namespace": "ordivon.host",
                        "type": "assignment",
                        "id": assignment_id,
                        "generation": str(host_assignment_generation),
                        "digest": host_assignment_digest,
                    },
                    {
                        "namespace": "ordivon.harness",
                        "type": "run",
                        "id": harness_run_id,
                        "generation": str(host_assignment_generation),
                        "digest": request_digest,
                    },
                ],
            }
            run_request: JsonObject = {
                "schemaVersion": 1,
                "clientRequestId": client_request_id,
                "execution": execution,
                "waitMs": 0,
                "stdoutTailBytes": 4096,
                "stderrTailBytes": 4096,
            }
            dispatch_attempted = True
            try:
                submitted = client.call_tool("workspace.exec", run_request)
            except RuntimeMcpError:
                listed = client.call_tool(
                    "task.list",
                    {"limit": 20, "clientRequestId": client_request_id},
                )
                jobs = listed.get("jobs")
                matching = (
                    [
                        item
                        for item in jobs
                        if isinstance(item, dict)
                        and isinstance(jobs, list)
                        and item.get("clientRequestId") == client_request_id
                    ]
                    if isinstance(jobs, list)
                    else []
                )
                if len(matching) != 1:
                    raise
                submitted = _object(matching[0], "recovered Runtime Job")
            runtime_job_id = _text(submitted.get("jobId"), "Runtime Job identity")
            runtime_attempt_id = _text(submitted.get("attemptId"), "Runtime Attempt identity")
            if not runtime_job_id.startswith("job-"):
                raise RuntimeMcpError("Runtime Job identity does not use the Runtime form")
            if not runtime_attempt_id.startswith("attempt-"):
                raise RuntimeMcpError("Runtime Attempt identity does not use the Runtime form")
            replay = client.call_tool("workspace.exec", run_request)
            exact_replay_confirmed = bool(
                replay.get("jobId") == runtime_job_id
                and replay.get("attemptId") == runtime_attempt_id
            )
            if not exact_replay_confirmed:
                raise RuntimeMcpError("Runtime exact request replay produced another Job")
            listed = client.call_tool(
                "task.list",
                {"limit": 20, "clientRequestId": client_request_id},
            )
            jobs = listed.get("jobs")
            matches = (
                [
                    item
                    for item in jobs
                    if isinstance(item, dict) and item.get("jobId") == runtime_job_id
                ]
                if isinstance(jobs, list)
                else []
            )
            recovery_lookup_confirmed = len(matches) == 1
            if not recovery_lookup_confirmed:
                raise RuntimeMcpError("Runtime Job recovery lookup was not unique")
            deadline = time.monotonic() + self.runtime_timeout_ms / 1000 + 30
            terminal = submitted
            while True:
                delivery_state = _runtime_delivery_state(terminal)
                if delivery_state == "terminal":
                    break
                if delivery_state == "unknown":
                    raise RuntimeMcpError("Runtime Job terminal delivery is unknown")
                if time.monotonic() >= deadline:
                    raise RuntimeMcpError("Runtime Job observation exceeded P0-C deadline")
                terminal = client.call_tool(
                    "task.observe",
                    {
                        "schemaVersion": 1,
                        "jobId": runtime_job_id,
                        "waitMs": 30_000,
                        "waitUntil": "change_or_terminal",
                        "stdoutTailBytes": 4096,
                        "stderrTailBytes": 4096,
                    },
                )
            terminal_observed = True
            if terminal.get("attemptId") != runtime_attempt_id:
                raise RuntimeMcpError("Runtime terminal Attempt identity changed")
            artifacts = terminal.get("artifacts")
            if not isinstance(artifacts, list):
                raise RuntimeMcpError("Runtime terminal observation omitted Artifacts")
            stdout_descriptor = next(
                (
                    _object(item, "Runtime stdout descriptor")
                    for item in artifacts
                    if isinstance(item, dict) and item.get("kind") == "stdout"
                ),
                None,
            )
            terminal_descriptor = next(
                (
                    _object(item, "Runtime terminal descriptor")
                    for item in artifacts
                    if isinstance(item, dict) and item.get("kind") == "terminal_evidence"
                ),
                None,
            )
            if stdout_descriptor is None or terminal_descriptor is None:
                raise RuntimeMcpError("Runtime terminal evidence lacks stdout or terminal Artifact")
            stdout = _read_artifact(client, job_id=runtime_job_id, descriptor=stdout_descriptor)
            _read_artifact(client, job_id=runtime_job_id, descriptor=terminal_descriptor)
            worker_result = _parse_worker_result(stdout)
            response_digest = canonical_digest(worker_result)
            status = worker_result.get("status")
            if status != "succeeded":
                raw_code = worker_result.get("failureCode")
                try:
                    code = ActorProposalFailureCode(str(raw_code))
                except ValueError:
                    code = ActorProposalFailureCode.ACTOR_STOPPED
                failure_details = _object(
                    worker_result.get("details", {}), "Runtime worker failure details"
                )
                failure_details.update(
                    {
                        "runtimeJobId": runtime_job_id,
                        "runtimeAttemptId": runtime_attempt_id,
                        "runtimeClientRequestId": client_request_id,
                        "runtimeTerminalStatus": terminal.get("status"),
                        "runtimeResponseDigest": response_digest,
                    }
                )
                validate_json(failure_details)
                raise AgentTurnDriverError(
                    code,
                    _text(worker_result.get("message"), "Runtime worker failure message"),
                    details=failure_details,
                )
            if (
                _runtime_delivery_state(terminal) != "terminal"
                or terminal.get("executionDisposition") != "succeeded"
                or terminal.get("deliveryDisposition") != "committed"
                or terminal.get("recoveryRequired") is not False
                or terminal.get("resultAvailable") is not True
                or terminal.get("exitCode") != 0
            ):
                raise RuntimeMcpError(
                    "Runtime Job did not converge to committed success "
                    "despite worker success result"
                )
            if worker_result.get("requestPayloadDigest") != request_digest:
                raise RuntimeMcpError("Runtime worker result belongs to another request")
            evidence_value = _object(worker_result.get("evidence"), "Runtime worker evidence")
            evidence = _evidence_from_worker(evidence_value)
            if (
                evidence.harness_run_id != harness_run_id
                or evidence.assignment_id != assignment_id
                or evidence.context_digest != context_digest
            ):
                raise RuntimeMcpError("Runtime worker evidence differs from Host Assignment")
            close_result = client.call_tool(
                "workspace.close",
                {"schemaVersion": 1, "workspaceId": workspace_id, "force": False},
            )
            if close_result.get("workspaceId") != workspace_id:
                raise RuntimeMcpError("Runtime closed a different Workspace")
            return replace(
                evidence,
                runtime_job_id=runtime_job_id,
                runtime_attempt_id=runtime_attempt_id,
                runtime_client_request_id=client_request_id,
                runtime_workspace_id=workspace_id,
                runtime_source_revision=self.runtime_source_revision,
                runtime_terminal_evidence_digest=_digest(
                    terminal_descriptor.get("digest"), "Runtime terminal evidence digest"
                ),
                runtime_stdout_artifact_digest=_digest(
                    stdout_descriptor.get("digest"), "Runtime stdout Artifact digest"
                ),
                runtime_tool_catalog_digest=tool_catalog_digest,
                runtime_response_digest=response_digest,
                runtime_exact_replay_confirmed=exact_replay_confirmed,
                runtime_recovery_lookup_confirmed=recovery_lookup_confirmed,
            )
        except AgentTurnDriverError:
            raise
        except Exception as error:  # noqa: BLE001 - Runtime transport and process boundary.
            details: JsonObject = {
                "errorType": type(error).__name__,
                "errorMessage": str(error)[:500],
                "runtimeClientRequestId": client_request_id,
                "runtimeWorkspaceId": workspace_id,
                "runtimeRequestDigest": request_digest,
            }
            if runtime_job_id is not None:
                details["runtimeJobId"] = runtime_job_id
            if runtime_attempt_id is not None:
                details["runtimeAttemptId"] = runtime_attempt_id
            validate_json(details)
            raise AgentTurnDriverError(
                ActorProposalFailureCode.ACTOR_STOPPED,
                f"Runtime-backed Harness turn failed: {type(error).__name__}",
                details=details,
            ) from error
        finally:
            if terminal_observed or not dispatch_attempted:
                request_path.unlink(missing_ok=True)


__all__ = ["RuntimeBackedHostAssignedDeepSeekHarnessTurnDriver"]
