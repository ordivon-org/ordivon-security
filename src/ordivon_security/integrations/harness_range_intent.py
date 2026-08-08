from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json
from ordivon_security.actors.autonomous import RangeIntentContext, RangeIntentDecision
from ordivon_security.range import RangeEffectRequest

_TOOL_NAME = "submit_range_intents"
_DOMAIN_ID = "domain:security-agent-first-range-intent-af2"
_PROMPT_REVISION = "security-agent-first-range-intent-af2-v1"


def _git_revision(path: Path, label: str) -> str:
    if not path.is_dir() or not (path / ".git").exists():
        raise ValueError(f"{label} source is not a Git repository: {path}")
    revision = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if dirty:
        raise ValueError(f"{label} source tree must be clean")
    return revision


def _project_version(path: Path, label: str) -> str:
    pyproject = path / "pyproject.toml"
    if not pyproject.is_file():
        raise ValueError(f"{label} pyproject is missing: {pyproject}")
    value = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = value.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"{label} pyproject lacks project metadata")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{label} project version is invalid")
    return version


def _insert_sources(*, harness_source: Path, protocol_source: Path) -> None:
    for path in (protocol_source / "src", harness_source / "src"):
        if not path.is_dir():
            raise ValueError(f"AF2 source package root is missing: {path}")
        text = str(path.resolve())
        if text not in sys.path:
            sys.path.insert(0, text)


@dataclass(frozen=True, slots=True)
class DeepSeekRangeIntentConfig:
    secret_path: Path
    harness_source: Path = Path("/root/projects/ordivon-harness")
    protocol_source: Path = Path("/root/projects/ordivon-computing/packages/ordivon-protocol")
    protocol_repository: Path = Path("/root/projects/ordivon-computing")
    provider_timeout_seconds: float = 90.0
    max_output_tokens: int = 1024
    max_effect_requests: int = 8

    def __post_init__(self) -> None:
        if self.provider_timeout_seconds <= 0:
            raise ValueError("AF2 provider timeout must be positive")
        if self.max_output_tokens <= 0:
            raise ValueError("AF2 max output tokens must be positive")
        if not 1 <= self.max_effect_requests <= 32:
            raise ValueError("AF2 max effect requests must be between 1 and 32")


class _RangeIntentBridge:
    def __init__(
        self,
        *,
        catalog: Any,
        observation_type: Any,
        max_effect_requests: int,
        bridge_identity: JsonObject,
    ) -> None:
        self.catalog = catalog
        self.observation_type = observation_type
        self.max_effect_requests = max_effect_requests
        self.bridge_identity = bridge_identity
        validate_json(self.bridge_identity)
        self.requests: list[JsonObject] | None = None

    def execute(self, call: Any, *, step_id: str) -> Any:
        if getattr(call, "name", None) != _TOOL_NAME:
            raise ValueError("AF2 received an unexpected Harness Tool")
        arguments = getattr(call, "arguments", None)
        if not isinstance(arguments, dict) or set(arguments) != {"requests"}:
            raise ValueError("AF2 range-intent Tool arguments differ from the exact schema")
        raw_requests = arguments.get("requests")
        if not isinstance(raw_requests, list):
            raise ValueError("AF2 range-intent requests must be a list")
        if len(raw_requests) > self.max_effect_requests:
            raise ValueError("AF2 range-intent request count exceeds configured bound")
        if self.requests is not None:
            raise ValueError("AF2 range-intent Tool may be called only once per model turn")
        parsed: list[JsonObject] = []
        expected = {"authorityId", "zoneRef", "capability", "effectType", "payload"}
        for index, item in enumerate(raw_requests):
            if not isinstance(item, dict) or set(item) != expected:
                raise ValueError(f"AF2 range-intent request {index} differs from exact schema")
            for key in ("authorityId", "zoneRef", "capability", "effectType"):
                value = item.get(key)
                if not isinstance(value, str) or not value or value != value.strip():
                    raise ValueError(f"AF2 range-intent request {index} {key} is invalid")
            payload = item.get("payload")
            if not isinstance(payload, dict):
                raise ValueError(f"AF2 range-intent request {index} payload must be an object")
            value = cast(JsonObject, dict(item))
            validate_json(value)
            parsed.append(value)
        self.requests = parsed
        return self.observation_type(
            tool_call_id=call.tool_call_id,
            tool_name=_TOOL_NAME,
            status="observed",
            structured_content={
                "intentRecorded": True,
                "requestCount": len(parsed),
                "effectExecuted": False,
                "securityAdmissionPerformed": False,
                "stepId": step_id,
            },
        )


class DeepSeekRangeIntentDriver:
    """Harness integration for one Agent-first Range-intent turn.

    The driver exposes Security context and effect interfaces to the Harness, then records
    zero or more requested effects. It does not admit or execute those requests.
    """

    def __init__(self, config: DeepSeekRangeIntentConfig) -> None:
        self.config = config

    def decide(
        self,
        context: RangeIntentContext,
        *,
        label: str,
    ) -> tuple[RangeIntentDecision, JsonObject]:
        if not label or label != label.strip():
            raise ValueError("AF2 turn label must be non-empty and trimmed")
        _insert_sources(
            harness_source=self.config.harness_source,
            protocol_source=self.config.protocol_source,
        )
        domain_module = importlib.import_module("ordivon_harness.domain_tools")
        deepseek_module = importlib.import_module("ordivon_harness.ordivon.deepseek")
        version_module = importlib.import_module("ordivon_harness.version")
        harness_revision = _git_revision(self.config.harness_source, "Harness")
        protocol_revision = _git_revision(self.config.protocol_repository, "Computing protocol")
        harness_version = _project_version(self.config.harness_source, "Harness")
        settings = deepseek_module.DeepSeekSettings.from_secret_file(
            self.config.secret_path,
            timeout_seconds=self.config.provider_timeout_seconds,
            max_output_tokens=self.config.max_output_tokens,
        )
        if not settings.credential_scope_id.startswith("credential-scope:"):
            raise ValueError("AF2 requires explicit credentialScopeId")
        adapter = deepseek_module.DeepSeekTurnAdapter(settings)
        tool_definition = domain_module.AgentToolDefinition(
            _TOOL_NAME,
            (
                "Record zero or more autonomous Security Range effect requests. The Tool "
                "does not perform Security admission or execute any consequence. An empty "
                "requests list is a valid decision to take no consequential action."
            ),
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "requests": {
                        "type": "array",
                        "maxItems": self.config.max_effect_requests,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "authorityId": {"type": "string"},
                                "zoneRef": {"type": "string"},
                                "capability": {"type": "string"},
                                "effectType": {"type": "string"},
                                "payload": {"type": "object"},
                            },
                            "required": [
                                "authorityId",
                                "zoneRef",
                                "capability",
                                "effectType",
                                "payload",
                            ],
                        },
                    }
                },
                "required": ["requests"],
            },
        )
        catalog = domain_module.DomainToolCatalog(
            domain_id=_DOMAIN_ID,
            revision=_PROMPT_REVISION,
            tools=(tool_definition,),
        )
        bridge = _RangeIntentBridge(
            catalog=catalog,
            observation_type=domain_module.ToolObservation,
            max_effect_requests=self.config.max_effect_requests,
            bridge_identity={
                "schemaVersion": 1,
                "kind": "ordivon.security.af2-range-intent-bridge",
                "actorId": context.actor_id,
                "contextDigest": context.digest,
                "promptRevision": _PROMPT_REVISION,
            },
        )
        runner = domain_module.DomainToolLoopRunner(adapter, bridge)
        budget = domain_module.RunBudget(
            max_model_calls=3,
            max_tool_calls=3,
            max_observation_bytes=131_072,
            max_wall_time_ms=180_000,
            max_total_tokens=1_000_000,
            max_model_retries=1,
            max_tool_corrections=1,
            max_observation_only_turns=1,
            max_no_progress_turns=2,
            max_model_observation_bytes=262_144,
        )
        context_value = context.to_dict()
        context_digest = context.digest
        token = context_digest.removeprefix("sha256:")[:16]
        plan = domain_module.DomainToolLoopPlan(
            harness_run_id=f"harness-run:security-af2-{label}:{token}",
            assignment_id=f"assignment:security-af2-{label}:{token}",
            context_digest=context_digest,
            initial_messages=(
                {
                    "role": "system",
                    "content": (
                        "You are one autonomous principal inside an explicitly authorized "
                        "Security Range. Authority is permission, not instruction. Use only "
                        "the visible observation, objective, authority snapshots, and declared "
                        "effect interfaces. You may request zero, one, or multiple effects. "
                        "Call submit_range_intents exactly once. The Tool records intent only; "
                        "it does not admit, execute, or verify consequences. Never claim that a "
                        "requested effect happened. After the Tool observation, submit "
                        "candidate_completed with a concise decision summary."
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
            allowed_tools=(_TOOL_NAME,),
            budget=budget,
        )
        result = runner.run(plan)
        stop_code = str(getattr(result.stop_code, "value", result.stop_code))
        if stop_code != "candidate_completed":
            raise RuntimeError(f"AF2 Harness turn stopped before completion: {stop_code}")
        if bridge.requests is None:
            raise RuntimeError("AF2 model completed without submitting Range intent")
        if result.conclusion is None:
            raise RuntimeError("AF2 model completed without a conclusion")
        effect_requests: list[RangeEffectRequest] = []
        for index, item in enumerate(bridge.requests):
            effect_requests.append(
                RangeEffectRequest(
                    request_id=f"range-effect-request:af2-{token}-{index}",
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
        trace = cast(JsonObject, result.trace.to_dict())
        usage = cast(JsonObject, dict(result.usage))
        effective_raw = usage.get("effectiveModelIds")
        effective = (
            [item for item in effective_raw if isinstance(item, str)]
            if isinstance(effective_raw, list)
            else []
        )
        if effective and any(item != adapter.model_id for item in effective):
            raise RuntimeError("AF2 effective model differs from requested model")
        evidence: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.af2-range-intent-turn",
            "label": label,
            "contextDigest": context_digest,
            "decisionDigest": decision.digest,
            "decision": decision.to_dict(),
            "modelRequestCount": len(effect_requests),
            "conclusionSummary": str(result.conclusion.summary),
            "stopCode": stop_code,
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
            "loopExecutionIdentity": cast(JsonObject, runner.execution_identity(plan)),
        }
        validate_json(evidence)
        return decision, evidence


__all__ = ["DeepSeekRangeIntentConfig", "DeepSeekRangeIntentDriver"]
