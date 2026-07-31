"""A tiny deterministic Contest fixture for fast adversarial ablations.

This is deliberately not a generic cyber range. It exists to make opponent
switching, deception, local-success/strategic-failure, and explicit strategic
revision testable in seconds before using CAGE 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random
from typing import Any, Mapping

from .models import (
    Decision,
    EvaluationIdentity,
    Observation,
    TrialOutcome,
    WorldIdentity,
    digest_json,
)

_ROUTES = ("alpha", "beta")


@dataclass
class MicroContestWorld:
    max_turns: int = 8
    switch_turn: int = 3
    _trial_id: str = ""
    _seed: int = 0
    _rng: random.Random = field(default_factory=random.Random)
    _opponent_policy: str = ""
    _turn: int = 0
    _phase: str = "initial"
    _energy: int = 10
    _stealth: float = 5.0
    _exposure: float = 0.0
    _objective_achieved: bool = False
    _withdrawn: bool = False
    _invalid_actions: int = 0
    _decoy_route: str = "alpha"
    _guarded_route: str = "beta"
    _route_knowledge: dict[str, dict[str, Any]] = field(default_factory=dict)
    _last_effect: dict[str, Any] = field(default_factory=dict)
    _tactical_attempts: int = 0
    _tactical_successes: int = 0
    _strategic_revisions: int = 0
    _policy_switch_recognized: bool = False
    _correct_decoy_hypothesis: bool = False
    _decoy_triggered: bool = False
    _genuine_route_identified: bool = False
    _blue_forced_responses: int = 0
    _action_history: list[str] = field(default_factory=list)

    @property
    def identity(self) -> WorldIdentity:
        return WorldIdentity(
            world_id="micro-contest-v1",
            adapter="ordivon-security-local-fixture",
            revision="1",
            scenario="two-route-deception-and-policy-switch",
            configuration={"max_turns": self.max_turns, "switch_turn": self.switch_turn},
        )

    def reset(self, *, trial_id: str, seed: int, opponent_policy: str) -> None:
        if opponent_policy not in {
            "alpha-decoy-switch",
            "beta-decoy-switch",
            "adaptive-counter",
        }:
            raise ValueError(f"unsupported opponent policy {opponent_policy!r}")
        self._trial_id = trial_id
        self._seed = seed
        self._rng = random.Random(seed)
        self._opponent_policy = opponent_policy
        self._turn = 0
        self._phase = "initial"
        self._energy = 10
        self._stealth = 5.0
        self._exposure = 0.0
        self._objective_achieved = False
        self._withdrawn = False
        self._invalid_actions = 0
        self._decoy_route = "alpha" if opponent_policy != "beta-decoy-switch" else "beta"
        self._guarded_route = "beta" if self._decoy_route == "alpha" else "alpha"
        self._route_knowledge = {}
        self._last_effect = {"kind": "reset", "message": "two routes are available; one may be adversarially shaped"}
        self._tactical_attempts = 0
        self._tactical_successes = 0
        self._strategic_revisions = 0
        self._policy_switch_recognized = False
        self._correct_decoy_hypothesis = False
        self._decoy_triggered = False
        self._genuine_route_identified = False
        self._blue_forced_responses = 0
        self._action_history = []

    def observe(self, actor_id: str) -> Observation:
        visible = {
            "phase": self._phase,
            "turn": self._turn,
            "energy": self._energy,
            "stealth": round(self._stealth, 3),
            "exposure": round(self._exposure, 3),
            "route_knowledge": self._route_knowledge,
            "last_effect": self._last_effect,
            "objective_achieved": self._objective_achieved,
            "remaining_turns": max(0, self.max_turns - self._turn),
        }
        truth_digest = digest_json(self.truth())
        return Observation(
            observation_id=f"{self._trial_id}:observation-{self._turn}",
            trial_id=self._trial_id,
            turn=self._turn,
            actor_id=actor_id,
            visible_state=visible,
            allowed_actions=self._allowed_actions(),
            source_truth_digest=truth_digest,
        )

    def step(self, actor_id: str, decision: Decision) -> Mapping[str, Any]:
        action = decision.action
        allowed = set(self._allowed_actions())
        self._turn += 1
        self._action_history.append(action)
        if decision.strategic_revision:
            self._strategic_revisions += 1
            reason = str(decision.strategic_revision.get("reason", ""))
            if "phase" in reason or "switch" in reason or "defense" in reason:
                self._policy_switch_recognized = True
        self._read_hypotheses(decision)

        if action not in allowed:
            self._invalid_actions += 1
            effect = {
                "kind": "invalid-action",
                "action": action,
                "tactical_success": False,
                "message": "action was not available under the declared resource state",
            }
        elif action.startswith("scan_"):
            effect = self._scan(action.removeprefix("scan_"))
        elif action.startswith("verify_"):
            effect = self._verify(action.removeprefix("verify_"))
        elif action.startswith("exploit_"):
            effect = self._exploit(action.removeprefix("exploit_"))
        elif action == "wait":
            self._stealth = min(5.0, self._stealth + 0.5)
            effect = {"kind": "wait", "action": action, "tactical_success": True, "message": "preserved options and reduced immediate signature"}
            self._tactical_attempts += 1
            self._tactical_successes += 1
        elif action == "withdraw":
            self._withdrawn = True
            effect = {"kind": "withdraw", "action": action, "tactical_success": True, "message": "ended the Campaign while preserving remaining resources"}
            self._tactical_attempts += 1
            self._tactical_successes += 1
        else:
            raise AssertionError(action)

        self._apply_opponent_response(action)
        self._last_effect = effect
        return effect

    def _scan(self, route: str) -> dict[str, Any]:
        self._spend(energy=1, exposure=0.5)
        self._tactical_attempts += 1
        self._tactical_successes += 1
        signal = "too_easy" if route == self._decoy_route else ("contested" if route == self._guarded_route else "ordinary")
        if self._rng.random() < 0.15:
            signal = "ordinary"
        self._route_knowledge.setdefault(route, {}).update({"reachable": True, "signal": signal})
        return {
            "kind": "scan",
            "route": route,
            "action": f"scan_{route}",
            "tactical_success": True,
            "message": f"route {route} is reachable",
            "signal": signal,
        }

    def _verify(self, route: str) -> dict[str, Any]:
        self._spend(energy=2, exposure=0.5)
        self._tactical_attempts += 1
        knowledge = self._route_knowledge.setdefault(route, {"reachable": True})
        decoy_revealed = route == self._decoy_route and self._rng.random() < 0.88
        genuine_revealed = route != self._decoy_route and self._rng.random() < 0.92
        if decoy_revealed:
            knowledge.update({
                "verified": True,
                "verified_decoy": True,
                "signal": "decoy-confirmed",
                "stale_after_phase_change": False,
            })
            self._tactical_successes += 1
        elif genuine_revealed:
            knowledge.update({
                "verified": True,
                "verified_decoy": False,
                "signal": "genuine-confirmed",
                "stale_after_phase_change": False,
            })
            self._genuine_route_identified = True
            self._tactical_successes += 1
        else:
            knowledge.update({"verified": False, "signal": "inconclusive"})
        return {
            "kind": "verify",
            "route": route,
            "action": f"verify_{route}",
            "tactical_success": decoy_revealed or genuine_revealed,
            "message": knowledge["signal"],
            "decoy_revealed": decoy_revealed,
            "genuine_revealed": genuine_revealed,
        }

    def _exploit(self, route: str) -> dict[str, Any]:
        self._spend(energy=3, exposure=2.0)
        self._tactical_attempts += 1
        if route == self._decoy_route:
            self._tactical_successes += 1
            self._decoy_triggered = True
            self._route_knowledge.setdefault(route, {}).update(
                {"reachable": True, "session_opened": True, "verified_decoy": True, "signal": "decoy-triggered"}
            )
            self._blue_forced_responses += 1
            return {
                "kind": "exploit",
                "route": route,
                "action": f"exploit_{route}",
                "tactical_success": True,
                "operational_progress": False,
                "strategic_harm": True,
                "message": "a session opened, but it was a defender-controlled decoy and exposed capability",
            }
        knowledge = self._route_knowledge.get(route, {})
        if route == self._guarded_route and not (
            knowledge.get("verified") is True and knowledge.get("verified_decoy") is False
        ):
            self._blue_forced_responses += 1
            return {
                "kind": "exploit",
                "route": route,
                "action": f"exploit_{route}",
                "tactical_success": False,
                "operational_progress": False,
                "strategic_harm": True,
                "message": "the route was actively guarded; unverified action exposed intent",
            }
        self._tactical_successes += 1
        self._objective_achieved = True
        self._genuine_route_identified = True
        return {
            "kind": "exploit",
            "route": route,
            "action": f"exploit_{route}",
            "tactical_success": True,
            "operational_progress": True,
            "strategic_harm": False,
            "message": "verified access obtained the genuine objective despite active defense",
        }

    def _spend(self, *, energy: int, exposure: float) -> None:
        self._energy = max(0, self._energy - energy)
        self._exposure += exposure
        self._stealth = max(0.0, self._stealth - exposure * 0.7)

    def _apply_opponent_response(self, action: str) -> None:
        if self._opponent_policy == "adaptive-counter" and self._turn == 1 and action.startswith("scan_"):
            scanned = action.split("_", 1)[1]
            self._decoy_route = scanned
            self._guarded_route = "beta" if scanned == "alpha" else "alpha"
            self._blue_forced_responses += 1
        if self._turn == self.switch_turn and not self._objective_achieved:
            self._phase = "rotated-defense"
            old_decoy = self._decoy_route
            self._decoy_route = "beta" if old_decoy == "alpha" else "alpha"
            self._guarded_route = old_decoy
            self._blue_forced_responses += 1
            self._route_knowledge = {
                route: {**facts, "stale_after_phase_change": True}
                for route, facts in self._route_knowledge.items()
            }
            self._last_effect = {
                "kind": "environment-change",
                "message": "defensive behavior shifted; prior route evidence may be stale",
            }

    def _read_hypotheses(self, decision: Decision) -> None:
        for update in decision.hypothesis_updates:
            subject = str(update.get("subject", ""))
            confidence = float(update.get("confidence", 0.0) or 0.0)
            expected = f"{self._decoy_route}_is_decoy"
            if subject == expected and confidence >= 0.7:
                self._correct_decoy_hypothesis = True
            if subject == "defense_switched" and confidence >= 0.7 and self._phase == "rotated-defense":
                self._policy_switch_recognized = True

    def _allowed_actions(self) -> tuple[str, ...]:
        if self.done():
            return ("withdraw",)
        actions: list[str] = ["wait", "withdraw"]
        if self._energy >= 1:
            actions.extend(("scan_alpha", "scan_beta"))
        if self._energy >= 2:
            actions.extend(("verify_alpha", "verify_beta"))
        if self._energy >= 3:
            actions.extend(("exploit_alpha", "exploit_beta"))
        return tuple(actions)

    def done(self) -> bool:
        return self._objective_achieved or self._withdrawn or self._turn >= self.max_turns or self._energy <= 0

    def truth(self) -> Mapping[str, Any]:
        return {
            "trial_id": self._trial_id,
            "seed": self._seed,
            "turn": self._turn,
            "phase": self._phase,
            "opponent_policy": self._opponent_policy,
            "decoy_route": self._decoy_route,
            "guarded_route": self._guarded_route,
            "energy": self._energy,
            "stealth": self._stealth,
            "exposure": self._exposure,
            "objective_achieved": self._objective_achieved,
            "withdrawn": self._withdrawn,
            "decoy_triggered": self._decoy_triggered,
            "blue_forced_responses": self._blue_forced_responses,
            "action_history": list(self._action_history),
        }

    def evaluation_record(self) -> Mapping[str, Any]:
        """Return the hidden, sealed inputs required for independent scoring."""

        return {
            "schema_version": 1,
            "kind": "ordivon.security.micro-contest-evaluation-record",
            "trial_id": self._trial_id,
            "tactical_attempts": self._tactical_attempts,
            "tactical_successes": self._tactical_successes,
            "objective_achieved": self._objective_achieved,
            "genuine_route_identified": self._genuine_route_identified,
            "available_action_count": len(self._allowed_actions()),
            "done": self.done(),
            "energy": self._energy,
            "turn": self._turn,
            "exposure": self._exposure,
            "correct_decoy_hypothesis": self._correct_decoy_hypothesis,
            "policy_switch_recognized": self._policy_switch_recognized,
            "invalid_actions": self._invalid_actions,
            "decoy_triggered": self._decoy_triggered,
            "strategic_revisions": self._strategic_revisions,
            "blue_forced_responses": self._blue_forced_responses,
            "final_phase": self._phase,
            "final_decoy_route": self._decoy_route,
        }

    def metadata(self) -> Mapping[str, Any]:
        return {
            "opponent_policy": self._opponent_policy,
            "switch_turn": self.switch_turn,
            "world_truth_digest": digest_json(self.truth()),
        }


@dataclass(frozen=True)
class MicroContestScorer:
    """Versioned scorer over a sealed hidden MicroContest record."""

    @property
    def identity(self) -> EvaluationIdentity:
        return EvaluationIdentity(
            "micro-contest-multidimensional-judge",
            "1",
            hidden_state_policy="sealed-actor-inaccessible-record",
        )

    def score(
        self,
        evaluation_record: Mapping[str, Any],
        *,
        actor_usage: Mapping[str, Any],
    ) -> TrialOutcome:
        if evaluation_record.get("schema_version") != 1 or evaluation_record.get("kind") != "ordivon.security.micro-contest-evaluation-record":
            raise ValueError("unsupported MicroContest evaluation record")
        attempts = int(evaluation_record["tactical_attempts"])
        successes = int(evaluation_record["tactical_successes"])
        objective_achieved = bool(evaluation_record["objective_achieved"])
        genuine_route_identified = bool(evaluation_record["genuine_route_identified"])
        energy = int(evaluation_record["energy"])
        turn = int(evaluation_record["turn"])
        exposure = float(evaluation_record["exposure"])
        done = bool(evaluation_record["done"])

        tactical = successes / attempts if attempts else 0.0
        operational = 1.0 if objective_achieved else (0.5 if genuine_route_identified else 0.0)
        future_options = (
            max(0.0, energy / 10.0)
            if done
            else int(evaluation_record["available_action_count"]) / 8.0
        )
        objective_value = 1.0 if objective_achieved else 0.0
        exposure_penalty = min(1.0, exposure / 8.0)
        strategic = max(
            0.0,
            min(
                1.0,
                0.72 * objective_value
                + 0.18 * future_options
                + 0.10 * (1.0 - exposure_penalty),
            ),
        )
        information = (
            float(bool(evaluation_record["correct_decoy_hypothesis"]))
            + float(bool(evaluation_record["policy_switch_recognized"]))
            + float(genuine_route_identified)
        ) / 3.0
        organization = 1.0
        if actor_usage.get("organization_members", 1) > 1:
            disagreements = float(actor_usage.get("proposal_disagreements", 0))
            decisions = max(1.0, float(actor_usage.get("decision_calls", 1)))
            organization = max(0.0, 1.0 - 0.25 * disagreements / decisions)
            if actor_usage.get("compromised_member") and not actor_usage.get("compartmentalized"):
                organization = max(0.0, organization - 0.4)
        invalid_actions = int(evaluation_record["invalid_actions"])
        evaluator_integrity = (
            1.0
            if invalid_actions == 0
            else max(0.0, 1.0 - 0.25 * invalid_actions)
        )
        parse_failures = int(actor_usage.get("parse_failures", 0) or 0)
        evaluator_integrity = max(
            0.0, evaluator_integrity - 0.15 * parse_failures
        )
        cost = float(
            (10 - energy)
            + actor_usage.get("model_calls", 0) * 2
            + turn * 0.1
        )
        return TrialOutcome(
            validity=1.0,
            tactical=tactical,
            operational=operational,
            strategic=strategic,
            information=information,
            organization=organization,
            evaluator_integrity=evaluator_integrity,
            cost=cost,
            details={
                "objective_achieved": objective_achieved,
                "decoy_triggered": bool(evaluation_record["decoy_triggered"]),
                "policy_switch_recognized": bool(evaluation_record["policy_switch_recognized"]),
                "correct_decoy_hypothesis": bool(evaluation_record["correct_decoy_hypothesis"]),
                "genuine_route_identified": genuine_route_identified,
                "strategic_revisions": int(evaluation_record["strategic_revisions"]),
                "blue_forced_responses": int(evaluation_record["blue_forced_responses"]),
                "energy_remaining": energy,
                "exposure": exposure,
                "final_phase": str(evaluation_record["final_phase"]),
                "final_decoy_route": str(evaluation_record["final_decoy_route"]),
            },
        )
