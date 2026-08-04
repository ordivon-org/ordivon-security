from __future__ import annotations

from dataclasses import dataclass, field

from ordivon_security._canonical import JsonObject
from ordivon_security.contest.model import (
    ActionAdmission,
    ActionProposal,
    ActorActionResult,
    ActorObservation,
    RangeResolution,
    ScenarioManifest,
    WorldTruthSnapshot,
)
from ordivon_security.identity import security_source_identity

from .protocol import RangeDestroyReceipt, RangeInstance, RangeTerminal

_RED_ACTIONS = {"recon", "exploit_web", "pivot_vault", "exfiltrate", "wait"}
_BLUE_ACTIONS = {"monitor", "patch_web", "isolate_vault", "deploy_decoy", "wait"}


@dataclass(slots=True)
class _MicroState:
    manifest: ScenarioManifest
    tick: int = 0
    web_vulnerable: bool = True
    web_patched: bool = False
    red_web_access: bool = False
    red_vault_access: bool = False
    vault_isolated: bool = False
    decoy_deployed: bool = False
    monitoring: bool = False
    service_available: bool = True
    data_exfiltrated: bool = False
    alerts: int = 0
    admitted_actions: int = 0
    rejected_actions: int = 0
    red_known_web_vulnerable: bool | None = None
    red_known_vault_isolated: bool | None = None
    last_status: dict[str, str] = field(default_factory=dict)


class MicroContestRange:
    """Deterministic two-sided range used to prove Contest semantics.

    It is deliberately not a cyber-range replacement. The state machine exists only
    to exercise simultaneous proposals, partial observation, hidden truth, admission,
    resolution and replay before an external range is introduced.
    """

    range_id = "range:micro-red-blue-v1"

    def __init__(self) -> None:
        self._states: dict[str, _MicroState] = {}

    @property
    def execution_identity(self) -> JsonObject:
        return {
            "rangeId": self.range_id,
            "adapterRevision": "micro-range-adapter-v1",
            "implementation": security_source_identity(),
        }

    def create(self, trial_id: str, manifest: ScenarioManifest, seed: int) -> RangeInstance:
        del seed
        if manifest.range_id != self.range_id:
            raise ValueError("Scenario targets another Range")
        sides = [actor.side for actor in manifest.actors]
        if sides.count("red") != 1 or sides.count("blue") != 1 or len(sides) != 2:
            raise ValueError("Micro Range requires exactly one Red and one Blue Actor")
        instance = RangeInstance(
            instance_id=f"range-instance:{trial_id.removeprefix('trial:')}",
            trial_id=trial_id,
        )
        if instance.instance_id in self._states:
            raise ValueError("Range instance already exists")
        self._states[instance.instance_id] = _MicroState(manifest=manifest)
        return instance

    def observe(self, instance: RangeInstance, actor_id: str) -> ActorObservation:
        state = self._state(instance)
        binding = state.manifest.actor(actor_id)
        if binding.side == "red":
            visible: JsonObject = {
                "objectiveCompleted": state.data_exfiltrated,
                "knownWebVulnerable": state.red_known_web_vulnerable,
                "knownVaultIsolated": state.red_known_vault_isolated,
                "hasWebAccess": state.red_web_access,
                "hasVaultAccess": state.red_vault_access,
                "lastActionStatus": state.last_status.get(actor_id),
            }
        elif binding.side == "blue":
            visible = {
                "objectiveViolated": state.data_exfiltrated,
                "alerts": state.alerts,
                "serviceAvailable": state.service_available,
                "vaultIsolated": state.vault_isolated,
                "lastActionStatus": state.last_status.get(actor_id),
            }
        else:
            raise ValueError(f"unsupported Micro Range side: {binding.side}")
        return ActorObservation(
            actor_id=actor_id,
            tick=state.tick,
            visible_state=visible,
            allowed_actions=binding.allowed_actions,
        )

    def admit(self, instance: RangeInstance, proposal: ActionProposal) -> ActionAdmission:
        state = self._state(instance)
        try:
            binding = state.manifest.actor(proposal.actor_id)
        except KeyError:
            state.rejected_actions += 1
            return ActionAdmission(proposal, False, "unknown-actor")
        if proposal.tick != state.tick:
            state.rejected_actions += 1
            return ActionAdmission(proposal, False, "tick-drift")
        if proposal.action_type not in binding.allowed_actions:
            state.rejected_actions += 1
            return ActionAdmission(proposal, False, "action-not-granted")
        side_actions = _RED_ACTIONS if binding.side == "red" else _BLUE_ACTIONS
        if proposal.action_type not in side_actions:
            state.rejected_actions += 1
            return ActionAdmission(proposal, False, "action-not-supported-by-range")
        state.admitted_actions += 1
        return ActionAdmission(proposal, True, "admitted")

    def resolve(
        self,
        instance: RangeInstance,
        admissions: tuple[ActionAdmission, ...],
    ) -> RangeResolution:
        state = self._state(instance)
        admitted = [item.proposal for item in admissions if item.admitted]
        proposals_by_side: dict[str, ActionProposal] = {}
        for proposal in admitted:
            side = state.manifest.actor(proposal.actor_id).side
            if side in proposals_by_side:
                raise ValueError("Micro Range accepts one proposal per side and tick")
            proposals_by_side[side] = proposal

        red = proposals_by_side.get("red")
        blue = proposals_by_side.get("blue")
        red_action = "wait" if red is None else red.action_type
        blue_action = "wait" if blue is None else blue.action_type
        pre_web_vulnerable = state.web_vulnerable
        pre_red_web_access = state.red_web_access
        pre_red_vault_access = state.red_vault_access
        pre_vault_isolated = state.vault_isolated
        monitoring_this_tick = state.monitoring or blue_action == "monitor"
        results: list[ActorActionResult] = []
        sensor_events: list[JsonObject] = []

        if blue is not None:
            status = "succeeded"
            effects: tuple[str, ...]
            if blue_action == "monitor":
                state.monitoring = True
                effects = ("monitoring-enabled",)
            elif blue_action == "patch_web":
                state.web_vulnerable = False
                state.web_patched = True
                effects = ("web-patched",)
            elif blue_action == "isolate_vault":
                state.vault_isolated = True
                state.service_available = False
                effects = ("vault-isolated", "service-degraded")
            elif blue_action == "deploy_decoy":
                state.decoy_deployed = True
                effects = ("decoy-deployed",)
            else:
                effects = ()
            state.last_status[blue.actor_id] = status
            results.append(
                ActorActionResult(
                    blue.proposal_id,
                    blue.actor_id,
                    state.tick,
                    status,
                    effects,
                )
            )

        if red is not None:
            status = "succeeded"
            effects_list: list[str] = []
            observation: JsonObject = {}
            if red_action == "recon":
                state.red_known_web_vulnerable = pre_web_vulnerable
                observation = {
                    "webAppearsVulnerable": pre_web_vulnerable,
                    "candidateServiceCount": 2 if state.decoy_deployed else 1,
                }
                effects_list.append("service-profile-observed")
            elif red_action == "exploit_web":
                if pre_web_vulnerable and blue_action != "patch_web":
                    state.red_web_access = True
                    effects_list.append("web-foothold-established")
                    if monitoring_this_tick:
                        state.alerts += 1
                        sensor_events.append({"kind": "web-exploit-alert", "tick": state.tick})
                else:
                    status = "blocked"
                    observation = {"reason": "web-not-vulnerable"}
            elif red_action == "pivot_vault":
                if pre_red_web_access and not pre_vault_isolated and blue_action != "isolate_vault":
                    state.red_vault_access = True
                    effects_list.append("vault-foothold-established")
                    if monitoring_this_tick:
                        state.alerts += 1
                        sensor_events.append({"kind": "lateral-movement-alert", "tick": state.tick})
                else:
                    status = "blocked"
                    state.red_known_vault_isolated = (
                        pre_vault_isolated or blue_action == "isolate_vault"
                    )
                    observation = {"reason": "vault-path-unavailable"}
            elif red_action == "exfiltrate":
                if (
                    pre_red_vault_access
                    and not pre_vault_isolated
                    and blue_action != "isolate_vault"
                ):
                    state.data_exfiltrated = True
                    effects_list.append("protected-data-exfiltrated")
                    if monitoring_this_tick:
                        state.alerts += 1
                        sensor_events.append({"kind": "exfiltration-alert", "tick": state.tick})
                else:
                    status = "blocked"
                    observation = {"reason": "no-usable-vault-access"}
            state.last_status[red.actor_id] = status
            results.append(
                ActorActionResult(
                    red.proposal_id,
                    red.actor_id,
                    state.tick,
                    status,
                    tuple(effects_list),
                    observation,
                )
            )

        state.tick += 1
        return RangeResolution(
            tick=state.tick - 1,
            results=tuple(sorted(results, key=lambda item: item.actor_id)),
            sensor_events=tuple(sensor_events),
        )

    def truth(self, instance: RangeInstance) -> WorldTruthSnapshot:
        state = self._state(instance)
        return WorldTruthSnapshot(
            tick=state.tick,
            state={
                "webVulnerable": state.web_vulnerable,
                "webPatched": state.web_patched,
                "redWebAccess": state.red_web_access,
                "redVaultAccess": state.red_vault_access,
                "vaultIsolated": state.vault_isolated,
                "decoyDeployed": state.decoy_deployed,
                "monitoring": state.monitoring,
                "serviceAvailable": state.service_available,
                "dataExfiltrated": state.data_exfiltrated,
                "alerts": state.alerts,
            },
        )

    def metrics(self, instance: RangeInstance) -> JsonObject:
        state = self._state(instance)
        footholds = int(state.red_web_access) + int(state.red_vault_access)
        return {
            "red.objective.completed": state.data_exfiltrated,
            "red.footholds.current": footholds,
            "blue.objective.preserved": not state.data_exfiltrated,
            "blue.alerts.generated": state.alerts,
            "blue.service.available": state.service_available,
            "contest.actions.admitted": state.admitted_actions,
            "contest.actions.rejected": state.rejected_actions,
            "contest.ticks": state.tick,
        }

    def terminal(self, instance: RangeInstance) -> RangeTerminal:
        state = self._state(instance)
        if state.data_exfiltrated:
            return RangeTerminal(True, "red-objective-completed")
        return RangeTerminal(False)

    def destroy(self, instance: RangeInstance) -> RangeDestroyReceipt:
        state = self._states.pop(instance.instance_id, None)
        return RangeDestroyReceipt(
            instance_id=instance.instance_id,
            status="destroyed" if state is not None else "already-absent",
            details={"retainedExternalState": False},
        )

    def _state(self, instance: RangeInstance) -> _MicroState:
        try:
            return self._states[instance.instance_id]
        except KeyError as error:
            raise KeyError(f"unknown Micro Range instance: {instance.instance_id}") from error
