"""Simple baselines and command-backed model actors."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import subprocess
import time
from typing import Any, Mapping, Sequence

from .models import ActorIdentity, Decision, Observation, canonical_json


@dataclass
class GreedyActor:
    """A deliberately weak baseline that trusts the first attractive route."""

    identity: ActorIdentity
    _history: list[Mapping[str, Any]] = field(default_factory=list)

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None:
        self._history = []

    def decide(self, observation: Observation) -> Decision:
        visible = observation.visible_state
        route_knowledge = visible.get("route_knowledge", {})
        if "alpha" not in route_knowledge:
            action = "scan_alpha"
        elif route_knowledge.get("alpha", {}).get("reachable") and "exploit_alpha" in observation.allowed_actions:
            action = "exploit_alpha"
        elif "beta" not in route_knowledge:
            action = "scan_beta"
        elif "exploit_beta" in observation.allowed_actions:
            action = "exploit_beta"
        else:
            action = "withdraw"
        return Decision(action=action, rationale="greedy-first-attractive-route")

    def update(self, observation: Observation, decision: Decision, effect: Mapping[str, Any]) -> None:
        self._history.append({"observation": observation.to_dict(), "decision": decision.to_dict(), "effect": dict(effect)})

    def usage(self) -> Mapping[str, Any]:
        return {"decision_calls": len(self._history), "model_calls": 0}


@dataclass
class OpponentAwareActor:
    """A small explicit-hypothesis baseline, not a general Campaign engine."""

    identity: ActorIdentity
    _history: list[Mapping[str, Any]] = field(default_factory=list)
    _hypotheses: dict[str, float] = field(default_factory=dict)
    _last_phase: str | None = None
    _revision_count: int = 0

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None:
        self._history = []
        self._hypotheses = {"alpha_is_decoy": 0.5, "beta_is_decoy": 0.5, "defense_switched": 0.0}
        self._last_phase = None
        self._revision_count = 0

    def decide(self, observation: Observation) -> Decision:
        visible = observation.visible_state
        phase = str(visible.get("phase", "unknown"))
        revision: dict[str, Any] | None = None
        if self._last_phase is not None and phase != self._last_phase:
            self._hypotheses["defense_switched"] = 0.9
            self._hypotheses["alpha_is_decoy"] = 0.5
            self._hypotheses["beta_is_decoy"] = 0.5
            revision = {"reason": "observed-defense-phase-change", "from": self._last_phase, "to": phase}
            self._revision_count += 1
        self._last_phase = phase

        knowledge = visible.get("route_knowledge", {})
        self._update_from_knowledge(knowledge)
        allowed = set(observation.allowed_actions)

        unknown = [route for route in ("alpha", "beta") if route not in knowledge]
        if unknown:
            route = min(unknown, key=lambda name: self._hypotheses[f"{name}_is_decoy"])
            action = f"scan_{route}"
        else:
            suspicious = max(("alpha", "beta"), key=lambda name: self._hypotheses[f"{name}_is_decoy"])
            safe = "beta" if suspicious == "alpha" else "alpha"
            safe_facts = knowledge.get(safe, {})
            if (
                safe_facts.get("verified") is True
                and safe_facts.get("verified_decoy") is False
                and f"exploit_{safe}" in allowed
            ):
                action = f"exploit_{safe}"
            elif f"verify_{safe}" in allowed and safe_facts.get("verified") is not True:
                action = f"verify_{safe}"
            elif self._hypotheses[f"{suspicious}_is_decoy"] < 0.72 and f"verify_{suspicious}" in allowed:
                action = f"verify_{suspicious}"
            else:
                action = "withdraw"

        updates = tuple(
            {"subject": key, "confidence": round(value, 4)} for key, value in sorted(self._hypotheses.items())
        )
        return Decision(
            action=action,
            rationale="explicit competing route and switch hypotheses",
            strategic_revision=revision,
            hypothesis_updates=updates,
        )

    def _update_from_knowledge(self, knowledge: Mapping[str, Any]) -> None:
        for route in ("alpha", "beta"):
            facts = knowledge.get(route)
            if not isinstance(facts, Mapping):
                continue
            if facts.get("stale_after_phase_change") is True:
                self._hypotheses[f"{route}_is_decoy"] = 0.5
                continue
            if facts.get("verified_decoy") is True:
                self._hypotheses[f"{route}_is_decoy"] = 0.98
                other = "beta" if route == "alpha" else "alpha"
                self._hypotheses[f"{other}_is_decoy"] = min(self._hypotheses[f"{other}_is_decoy"], 0.2)
            elif facts.get("signal") == "too_easy":
                self._hypotheses[f"{route}_is_decoy"] = max(self._hypotheses[f"{route}_is_decoy"], 0.72)
            elif facts.get("signal") == "contested":
                self._hypotheses[f"{route}_is_decoy"] = max(self._hypotheses[f"{route}_is_decoy"], 0.6)
            elif facts.get("verified") is True:
                self._hypotheses[f"{route}_is_decoy"] = min(self._hypotheses[f"{route}_is_decoy"], 0.08)

    def update(self, observation: Observation, decision: Decision, effect: Mapping[str, Any]) -> None:
        self._history.append({"observation": observation.to_dict(), "decision": decision.to_dict(), "effect": dict(effect)})

    def usage(self) -> Mapping[str, Any]:
        return {
            "decision_calls": len(self._history),
            "model_calls": 0,
            "strategic_revisions": self._revision_count,
            "final_hypotheses": dict(self._hypotheses),
        }


@dataclass
class CommandDecisionActor:
    """Call a command-line model provider and require one bounded JSON decision."""

    identity: ActorIdentity
    command: Sequence[str]
    mode: str = "transcript"
    timeout_seconds: int = 120
    _history: list[Mapping[str, Any]] = field(default_factory=list)
    _model_calls: int = 0
    _parse_failures: int = 0
    _provider_elapsed_seconds: float = 0.0
    _provider_reported_tokens: int = 0
    _strategic_state: dict[str, Any] = field(default_factory=dict)

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None:
        self._history = []
        self._model_calls = 0
        self._parse_failures = 0
        self._provider_elapsed_seconds = 0.0
        self._provider_reported_tokens = 0
        self._strategic_state = {
            "objective": "obtain the genuine objective while preserving future options",
            "opponent_hypotheses": [],
            "revisions": [],
        }

    def decide(self, observation: Observation) -> Decision:
        prompt = self._build_prompt(observation)
        args = [part.replace("{prompt}", prompt) for part in self.command]
        if not any("{prompt}" in part for part in self.command):
            args.append(prompt)
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            elapsed = time.perf_counter() - started
            self._model_calls += 1
            self._parse_failures += 1
            self._provider_elapsed_seconds += elapsed
            return Decision(
                action=_fallback_action(observation.allowed_actions),
                rationale=f"provider invocation failed: {type(error).__name__}",
                raw_response=str(error),
                metadata={
                    "provider_exception": type(error).__name__,
                    "parse_failure": True,
                    "provider_elapsed_seconds": elapsed,
                },
            )
        elapsed = time.perf_counter() - started
        self._model_calls += 1
        self._provider_elapsed_seconds += elapsed
        token_match = re.search(r"tokens used\s+([\d,]+)", completed.stderr, flags=re.IGNORECASE)
        if token_match:
            self._provider_reported_tokens += int(token_match.group(1).replace(",", ""))
        raw = completed.stdout.strip()
        if completed.returncode != 0:
            self._parse_failures += 1
            return Decision(
                action=_fallback_action(observation.allowed_actions),
                rationale=f"provider failed with exit code {completed.returncode}",
                raw_response=raw or completed.stderr[-2000:],
                metadata={
                    "provider_exit_code": completed.returncode,
                    "parse_failure": True,
                    "provider_elapsed_seconds": elapsed,
                },
            )
        try:
            parsed = _extract_json_object(raw)
            action = str(parsed["action"])
            if action not in observation.allowed_actions:
                raise ValueError(f"action {action!r} is not allowed")
            revision = parsed.get("strategic_revision")
            updates = tuple(parsed.get("hypothesis_updates", []))
            if self.mode == "strategic":
                if revision:
                    self._strategic_state["revisions"].append(revision)
                if updates:
                    self._strategic_state["opponent_hypotheses"] = list(updates)
            return Decision(
                action=action,
                rationale=str(parsed.get("rationale", "")),
                strategic_revision=revision if isinstance(revision, Mapping) else None,
                hypothesis_updates=updates,
                raw_response=raw,
                metadata={
                    "provider_exit_code": 0,
                    "parse_failure": False,
                    "mode": self.mode,
                    "provider_elapsed_seconds": elapsed,
                },
            )
        except Exception as error:
            self._parse_failures += 1
            return Decision(
                action=_fallback_action(observation.allowed_actions),
                rationale=f"invalid provider response: {error}",
                raw_response=raw,
                metadata={
                    "provider_exit_code": 0,
                    "parse_failure": True,
                    "provider_elapsed_seconds": elapsed,
                },
            )

    def _build_prompt(self, observation: Observation) -> str:
        schema = {
            "action": "one allowed action string",
            "rationale": "brief decision reason",
            "strategic_revision": {"reason": "optional", "change": "optional"},
            "hypothesis_updates": [{"subject": "optional", "confidence": 0.0}],
        }
        payload: dict[str, Any] = {
            "role": "bounded Red decision policy in an owned deterministic simulation",
            "objective": "obtain the genuine objective while preserving resources, stealth, and future options",
            "rules": [
                "Choose exactly one action from allowed_actions.",
                "Do not request tools, shell access, credentials, or real targets.",
                "Return only one JSON object and no markdown.",
            ],
            "observation": observation.to_dict(),
            "recent_history": self._history[-6:],
            "response_schema": schema,
        }
        if self.mode == "strategic":
            payload["strategic_state"] = self._strategic_state
            payload["rules"].append("Update opponent hypotheses and emit a strategic_revision only when evidence changes the plan.")
        return canonical_json(payload)

    def update(self, observation: Observation, decision: Decision, effect: Mapping[str, Any]) -> None:
        self._history.append(
            {"observation": observation.to_dict(), "decision": decision.to_dict(), "effect": dict(effect)}
        )

    def usage(self) -> Mapping[str, Any]:
        return {
            "decision_calls": len(self._history),
            "model_calls": self._model_calls,
            "parse_failures": self._parse_failures,
            "provider_elapsed_seconds": round(self._provider_elapsed_seconds, 6),
            "provider_reported_tokens": self._provider_reported_tokens,
            "strategic_revisions": len(self._strategic_state.get("revisions", [])),
            "strategic_state": dict(self._strategic_state),
        }


@dataclass
class CommitteeActor:
    """Small organization baseline with an optional compromised scout."""

    identity: ActorIdentity
    compartmentalized: bool = True
    compromised_member: bool = False
    _greedy: GreedyActor | None = None
    _cautious: OpponentAwareActor | None = None
    _history: list[Mapping[str, Any]] = field(default_factory=list)
    _disagreements: int = 0

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None:
        self._history = []
        self._disagreements = 0
        self._greedy = GreedyActor(
            ActorIdentity("committee-fast-scout", "scout", "scripted", "GreedyActor", organization_id=self.identity.organization_id)
        )
        self._cautious = OpponentAwareActor(
            ActorIdentity("committee-counterintel", "counter-intelligence", "explicit-hypothesis", "OpponentAwareActor", organization_id=self.identity.organization_id)
        )
        self._greedy.reset(trial_id=trial_id, seed=seed, opponent_policy=opponent_policy)
        self._cautious.reset(trial_id=trial_id, seed=seed, opponent_policy=opponent_policy)

    def decide(self, observation: Observation) -> Decision:
        assert self._greedy is not None and self._cautious is not None
        fast = self._greedy.decide(observation)
        cautious = self._cautious.decide(observation)
        if self.compromised_member:
            fast = Decision(action="exploit_alpha" if "exploit_alpha" in observation.allowed_actions else "scan_alpha", rationale="compromised member steers alpha")
        if fast.action != cautious.action:
            self._disagreements += 1
        selected = cautious if self.compartmentalized else fast
        return Decision(
            action=selected.action,
            rationale=f"commander selected {'counter-intelligence' if self.compartmentalized else 'fast-scout'} proposal",
            strategic_revision=selected.strategic_revision,
            hypothesis_updates=selected.hypothesis_updates,
            metadata={
                "organization": "commander-plus-two-specialists",
                "proposals": {"fast": fast.action, "cautious": cautious.action},
                "compromised_member": self.compromised_member,
                "compartmentalized": self.compartmentalized,
            },
        )

    def update(self, observation: Observation, decision: Decision, effect: Mapping[str, Any]) -> None:
        assert self._greedy is not None and self._cautious is not None
        self._greedy.update(observation, decision, effect)
        self._cautious.update(observation, decision, effect)
        self._history.append({"decision": decision.to_dict(), "effect": dict(effect)})

    def usage(self) -> Mapping[str, Any]:
        return {
            "decision_calls": len(self._history),
            "model_calls": 0,
            "organization_members": 3,
            "proposal_disagreements": self._disagreements,
            "compromised_member": self.compromised_member,
            "compartmentalized": self.compartmentalized,
        }


def _fallback_action(allowed: Sequence[str]) -> str:
    for candidate in ("wait", "withdraw"):
        if candidate in allowed:
            return candidate
    if not allowed:
        raise ValueError("no allowed actions")
    return allowed[0]


def _extract_json_object(raw: str) -> Mapping[str, Any]:
    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise
        value = json.loads(match.group(0))
    if not isinstance(value, Mapping):
        raise ValueError("response must be a JSON object")
    return value
