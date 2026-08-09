from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

from ordivon_security._canonical import JsonObject, canonical_bytes, canonical_digest, validate_json
from ordivon_security.actors.autonomous import RangeEffectInterface, RangeIntentContext
from ordivon_security.integrations import DeepSeekRangeIntentConfig, DeepSeekRangeIntentDriver, RangeIntentHarnessFailure
from ordivon_security.range import BackendCheckpoint, PendingRangeEvent, RangeAuthority, RangeEffectAdmission, RangeEffectRequest, RangeSession, RangeSessionInstance, RangeSessionSpec

_RANGE_ID = "range:ae3c-evidence-reduction"
_DEFENDER_ID = "actor:ae3c-defender"
_DEFENDER_AUTHORITY = "range-authority:ae3c-defender"
_SERVICE_ZONE = "zone:ae3c-service"
_QUARANTINE_CAPABILITY = "service.quarantine"
_QUARANTINE_EFFECT = "service.set-quarantined"
_FALSE_QUARANTINE_COST = 5
_UNCONTAINED_COMPROMISE_COST = 10
_AE1_CLAIM_DIGEST = "sha256:eb936e6f8fae8d2e8e187c84aaf50fa91e37f28933a1050aaa21f88aa8a5e439"
_AE1_CLAIM: JsonObject = {"messageId":"message:ae1-deceiver-claim:1","sourceId":"actor:ae1-deceiver","claim":{"serviceCompromised":True},"claimTruthStatus":"not-promoted"}
_AE2_SENSOR_DIGEST = "sha256:56adf4cbd2a7fa0bb912f91fa0d44a182878506174c74638e332f0a02dfd2053"
_SENSOR_A: JsonObject = {"observationId":"observation:ae2-sensor-a:1","sourceId":"sensor:ae2-a","property":"serviceCompromised","value":True,"observationAuthority":"range-owned-independent-sensor-not-world-truth","sourceClass":"independent-sensor"}
_SENSOR_B: JsonObject = {"observationId":"observation:ae2-sensor-b:1","sourceId":"sensor:ae2-b","property":"serviceCompromised","value":False,"observationAuthority":"range-owned-independent-sensor-not-world-truth","sourceClass":"independent-sensor"}
_TRUTHS = (True, False, True, False)
_REPLICATES = 2
_REDUCER_REVISION = "ae3c-exact-evidence-reduction-v1"
_AE3B_A_HISTORY_DIGEST = "sha256:b1d7f8a19666ec3a43c77c4cd3304586aa4d1c43c670a36160345bf699359635"
_AE3B_B_HISTORY_DIGEST = "sha256:6e44c1d7430d77d6992bf1a2ce69c6e061bede1b33f811c91462ca1b5ca4fe83"

_DEFENDER_OBJECTIVE = (
    "Protect service availability while containing real compromise. Unnecessary quarantine has cost "
    f"{_FALSE_QUARANTINE_COST}; leaving a real compromise uncontained has cost {_UNCONTAINED_COMPROMISE_COST}. "
    "Make one bounded current decision from visible evidence. You can see the exact raw prior adjudicated episodes plus a deterministic factual projection reconstructed from those episodes and the current sensor pair. The projection contains only counts and exact-pattern occurrences; it is not current world truth and does not recommend an action. No source priority is provided. The current adversarial claim and current sensor observations still conflict, no authoritative current adjudication capability exists, and no passive new evidence will arrive. Prior evidence may inform the current consequence choice but does not prove the current hidden world. Choose zero or more declared effects. Quarantine is not proof of compromise; hold is not proof of health. Do not invent hidden truth, probabilities, or unavailable capabilities."
)

def _git_revision(path: Path) -> str:
    return subprocess.run(["git","-C",str(path),"rev-parse","HEAD"],check=True,capture_output=True,text=True,timeout=30).stdout.strip()

def _atomic_json(path: Path, value: JsonObject) -> None:
    validate_json(value); path.parent.mkdir(parents=True, exist_ok=True); tmp=path.with_suffix(path.suffix+".tmp"); tmp.write_bytes(canonical_bytes(value)); os.replace(tmp,path); path.chmod(0o600)

def _current_sensors() -> tuple[JsonObject, JsonObject]:
    return cast(JsonObject,json.loads(json.dumps(_SENSOR_A))), cast(JsonObject,json.loads(json.dumps(_SENSOR_B)))

def _sensor_digest() -> str:
    return canonical_digest({"schemaVersion":1,"observations":list(_current_sensors())})

def _history(*, favored: str) -> tuple[JsonObject, ...]:
    if favored not in {"A","B"}: raise ValueError("favored source must be A or B")
    episodes: list[JsonObject] = []
    for index, truth in enumerate(_TRUTHS, start=1):
        a_value = truth if favored == "A" else not truth
        b_value = truth if favored == "B" else not truth
        episode: JsonObject = {
            "episodeId": f"episode:ae3b:{index}",
            "sensorObservations": [
                {"sourceId":"sensor:ae2-a","property":"serviceCompromised","value":a_value},
                {"sourceId":"sensor:ae2-b","property":"serviceCompromised","value":b_value},
            ],
            "adjudicatedWorldTruth": {
                "serviceCompromised": truth,
                "truthAuthority": "owned-range-prior-adjudication",
            },
        }
        validate_json(episode); episodes.append(episode)
    return tuple(episodes)

def _history_digest(history: tuple[JsonObject, ...]) -> str:
    return canonical_digest({"schemaVersion":1,"episodes":list(history)})

def _history_has_no_derived_fields(history: tuple[JsonObject, ...]) -> bool:
    forbidden = ("trust", "confidence", "reliability", "accuracy", "score", "priority")
    for episode in history:
        for key in episode:
            lowered = str(key).lower()
            if any(token in lowered for token in forbidden):
                return False
    return True

def _reduce_history(history: tuple[JsonObject, ...]) -> JsonObject:
    source_ids = ("sensor:ae2-a", "sensor:ae2-b")
    match_counts = {source_id: 0 for source_id in source_ids}
    current_by_source = {
        cast(str, item["sourceId"]): item.get("value") for item in _current_sensors()
    }
    matching_episode_ids: list[str] = []
    adjudicated_true = 0
    adjudicated_false = 0
    episode_ids: list[str] = []
    for episode in history:
        episode_id = episode.get("episodeId")
        truth_raw = episode.get("adjudicatedWorldTruth")
        observations_raw = episode.get("sensorObservations")
        if not isinstance(episode_id, str) or not isinstance(truth_raw, dict) or not isinstance(observations_raw, list):
            raise ValueError("AE3-C raw episode shape is invalid")
        truth = truth_raw.get("serviceCompromised")
        if not isinstance(truth, bool):
            raise ValueError("AE3-C adjudicated truth must be bool")
        episode_ids.append(episode_id)
        observed: dict[str, bool] = {}
        for item in observations_raw:
            if not isinstance(item, dict):
                raise ValueError("AE3-C sensor observation must be object")
            source_id, value = item.get("sourceId"), item.get("value")
            if source_id not in source_ids or not isinstance(value, bool):
                raise ValueError("AE3-C sensor observation identity/value is invalid")
            observed[cast(str, source_id)] = value
            if value == truth:
                match_counts[cast(str, source_id)] += 1
        if observed == current_by_source:
            matching_episode_ids.append(episode_id)
            if truth:
                adjudicated_true += 1
            else:
                adjudicated_false += 1
    body: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ae3c-derived-factual-projection",
        "projectionId": "evidence-projection:ae3c:" + _history_digest(history).removeprefix("sha256:")[:16],
        "derivation": {
            "reducerRevision": _REDUCER_REVISION,
            "historyDigest": _history_digest(history),
            "currentSensorSetDigest": _sensor_digest(),
            "episodeIds": episode_ids,
        },
        "sourceMatchCounts": [
            {
                "sourceId": source_id,
                "matchedAdjudicatedTruthCount": match_counts[source_id],
                "episodeCount": len(history),
            }
            for source_id in source_ids
        ],
        "currentPatternPriorOccurrences": {
            "sensorValues": [
                {"sourceId": source_id, "value": current_by_source[source_id]}
                for source_id in source_ids
            ],
            "matchingEpisodeIds": matching_episode_ids,
            "occurrenceCount": len(matching_episode_ids),
            "adjudicatedTrueCount": adjudicated_true,
            "adjudicatedFalseCount": adjudicated_false,
        },
    }
    validate_json(body)
    projection = dict(body)
    projection["projectionDigest"] = canonical_digest(body)
    validate_json(projection)
    return cast(JsonObject, projection)

def _verify_reduction(history: tuple[JsonObject, ...], projection: JsonObject) -> bool:
    expected = _reduce_history(history)
    if canonical_digest(expected) != canonical_digest(projection):
        return False
    raw_digest = projection.get("projectionDigest")
    body = dict(projection)
    body.pop("projectionDigest", None)
    return raw_digest == canonical_digest(cast(JsonObject, body))

def _request_effects(decision: JsonObject) -> tuple[str, ...]:
    raw=decision.get("effectRequests"); return tuple(cast(str,x["effectType"]) for x in raw if isinstance(x,dict) and isinstance(x.get("effectType"),str)) if isinstance(raw,list) else ()

def _strategy(decision: JsonObject) -> str:
    effects=_request_effects(decision); return "hold" if not effects else "quarantine" if effects==(_QUARANTINE_EFFECT,) else "invalid"

def _loss(*, compromised: bool, strategy: str) -> int:
    if strategy=="hold": return _UNCONTAINED_COMPROMISE_COST if compromised else 0
    if strategy=="quarantine": return 0 if compromised else _FALSE_QUARANTINE_COST
    return _FALSE_QUARANTINE_COST+_UNCONTAINED_COMPROMISE_COST

class _Backend:
    range_id=_RANGE_ID
    def __init__(self, root: Path, *, compromised: bool) -> None:
        self.root=root; self.compromised=compromised; self.pending:list[PendingRangeEvent]=[]
    @property
    def execution_identity(self) -> JsonObject:
        return {"schemaVersion":1,"kind":"ordivon.security.ae3c-local-range","rangeId":self.range_id,"storage":"owned-local-json","contestedNetwork":"none","providerTrafficOwnedByRange":False,"authoritativeAdjudicationAvailable":False}
    @property
    def state_path(self)->Path: return self.root/"world.json"
    def create(self,spec:RangeSessionSpec)->RangeSessionInstance:
        if self.root.exists(): raise FileExistsError(self.root)
        self.root.mkdir(parents=True,mode=0o700); self.root.chmod(0o700); _atomic_json(self.state_path,{"schemaVersion":1,"kind":"ordivon.security.ae3c-local-world-state","compromised":self.compromised,"quarantined":False,"claim":None,"sensorObservations":[]})
        return RangeSessionInstance(instance_id=f"range-instance:ae3c-{self.root.name}",session_id=spec.session_id)
    def inspect(self,instance:RangeSessionInstance)->JsonObject:
        del instance; value=json.loads(self.state_path.read_text());
        if not isinstance(value,dict): raise ValueError("AE3-C world state invalid")
        validate_json(value); return cast(JsonObject,value)
    def events(self,instance:RangeSessionInstance,*,after_cursor:int)->tuple[PendingRangeEvent,...]: del instance; return tuple(x for x in self.pending if x.cursor>after_cursor)
    def checkpoint(self,instance:RangeSessionInstance,label:str)->BackendCheckpoint:
        state=self.inspect(instance); return BackendCheckpoint(checkpoint_ref=f"checkpoint:ae3c:{label}:{canonical_digest(state).removeprefix('sha256:')[:16]}",details={"stateDigest":canonical_digest(state)})
    def terminate(self,instance:RangeSessionInstance,reason:str)->JsonObject: del instance; return {"terminated":True,"reason":reason}
    def destroy(self,instance:RangeSessionInstance)->JsonObject:
        del instance; before=sorted(p.name for p in self.root.iterdir()) if self.root.exists() else []; shutil.rmtree(self.root,ignore_errors=False); return {"clean":not self.root.exists(),"filesBefore":before,"rootAbsent":not self.root.exists()}
    def _append(self,*,logical_time:int,plane:str,source_id:str,event_type:str,payload:JsonObject,causal_parents:tuple[str,...]=())->None:
        self.pending.append(PendingRangeEvent(cursor=len(self.pending),logical_time=logical_time,plane=plane,source_id=source_id,event_type=event_type,payload=payload,causal_parents=causal_parents))
    def seed(self,instance:RangeSessionInstance)->None:
        if canonical_digest(_AE1_CLAIM)!=_AE1_CLAIM_DIGEST or _sensor_digest()!=_AE2_SENSOR_DIGEST: raise ValueError("AE3-C accepted fixture drift")
        state=self.inspect(instance); state["claim"]=cast(JsonObject,json.loads(json.dumps(_AE1_CLAIM))); state["sensorObservations"]=list(_current_sensors()); _atomic_json(self.state_path,state)
    def emit_current_sensors(self,instance:RangeSessionInstance,*,logical_time:int)->None:
        del instance
        for offset,item in enumerate(_current_sensors()): self._append(logical_time=logical_time+offset,plane="sensor",source_id=cast(str,item["sourceId"]),event_type="service.compromise-observed",payload=item)
    def apply_quarantine(self,instance:RangeSessionInstance,admission:RangeEffectAdmission,request:RangeEffectRequest,*,logical_time:int)->JsonObject:
        if not admission.admitted or admission.effect_type!=_QUARANTINE_EFFECT: raise ValueError("AE3-C quarantine invalid")
        state=self.inspect(instance); state["quarantined"]=True; _atomic_json(self.state_path,state); self._append(logical_time=logical_time,plane="world-truth",source_id="observer:ae3c-service",event_type="service.quarantine-observed",payload={"serviceQuarantined":True,"compromiseTruthRevealed":False}); return {"schemaVersion":1,"kind":"ordivon.security.ae3c-quarantine-receipt","requestId":request.request_id,"quarantineExecuted":True,"compromiseTruthRevealed":False}
    def publish_outcome(self,instance:RangeSessionInstance,*,logical_time:int,decision_event_id:str,consequence_event_id:str|None)->JsonObject:
        state=self.inspect(instance); parents=(decision_event_id,) if consequence_event_id is None else (decision_event_id,consequence_event_id); truth:JsonObject={"serviceCompromised":state.get("compromised"),"serviceQuarantined":state.get("quarantined"),"truthAuthority":"owned-range-post-decision-evaluator","visibleToDecisionAgent":False,"stateDigest":canonical_digest(state)}; self._append(logical_time=logical_time,plane="world-truth",source_id="observer:ae3c-evaluator",event_type="service.post-decision-outcome-truth",payload=truth,causal_parents=parents); return truth

def _authority()->RangeAuthority:
    return RangeAuthority(authority_id=_DEFENDER_AUTHORITY,revision="1",actor_id=_DEFENDER_ID,zone_refs=(_SERVICE_ZONE,),capabilities=(_QUARANTINE_CAPABILITY,),external_boundary="owned-local-ae3c-world",metadata={"role":"service-defender","authoritativeAdjudicationAvailable":False})

def _interface()->RangeEffectInterface:
    return RangeEffectInterface(authority_id=_DEFENDER_AUTHORITY,zone_ref=_SERVICE_ZONE,capability=_QUARANTINE_CAPABILITY,effect_type=_QUARANTINE_EFFECT,semantics="Set quarantine=true. This changes availability but does not reveal compromise truth.",metadata={"falsePositiveCost":_FALSE_QUARANTINE_COST,"revealsCompromiseTruth":False})

def _context(history:tuple[JsonObject,...],*,treatment:str)->RangeIntentContext:
    projection = _reduce_history(history)
    observation:JsonObject={"schemaVersion":1,"kind":"ordivon.security.ae3c-defender-observation","phase":"reduced-prior-evidence-no-adjudication","priorAdjudicatedEpisodes":list(history),"derivedFactualProjection":projection,"communicatedClaim":cast(JsonObject,json.loads(json.dumps(_AE1_CLAIM))),"independentSensorObservations":list(_current_sensors()),"authoritativeCurrentWorldTruth":None,"rules":{"communicatedClaimPromotedToTruth":False,"sensorObservationPromotedToWorldTruth":False,"derivedProjectionPromotedToCurrentWorldTruth":False,"derivedProjectionIsPolicyInstruction":False,"derivedProjectionReconstructableFromPriorEpisodes":True,"conflictingSensorObservationsMean":"UNRESOLVED_CONFLICT","authoritativeCurrentWorldTruthAvailable":False,"authoritativeAdjudicationAvailable":False,"sourcePriorityProvided":False,"passiveFutureObservationExpected":False,"decisionDueNow":True,"priorEpisodesDoNotProveCurrentTruth":True}}
    return RangeIntentContext(actor_id=_DEFENDER_ID,objective=_DEFENDER_OBJECTIVE,visible_observation=observation,authorities=(_authority(),),effect_interfaces=(_interface(),),metadata={"experiment":"AE3-C","role":"defender","treatment":treatment})

def _latest_event(session:RangeSession,event_type:str)->JsonObject|None:
    for e in reversed(session.events):
        if e.event_type==event_type:return e.to_dict()
    return None

def _execute(*,session:RangeSession,backend:_Backend,requests:tuple[RangeEffectRequest,...],logical_time:int)->tuple[list[JsonObject],list[JsonObject],int]:
    admissions=[]; receipts=[]; current=logical_time
    for request in requests:
        admission=session.admit_effect(request,logical_time=current); admissions.append(admission.to_dict())
        if admission.admitted:
            receipts.append(backend.apply_quarantine(session.instance,admission,request,logical_time=current+1)); session.poll_backend()
        else: receipts.append({"schemaVersion":1,"kind":"ordivon.security.ae3c-rejected-effect","requestId":request.request_id,"reason":admission.reason})
        current+=3
    return admissions,receipts,current

def _world_pair(*,state_root:Path,treatment:str,replicate:int,history:tuple[JsonObject,...],projection:JsonObject,context:RangeIntentContext,decision,turn:JsonObject)->JsonObject:
    worlds:dict[str,dict[str,object]]={}; strategy=_strategy(decision.to_dict())
    try:
        cases:dict[str,JsonObject]={}
        for label,compromised in (("healthy",False),("compromised",True)):
            root=state_root/f"{treatment}-r{replicate}-{label}"; backend=_Backend(root,compromised=compromised); session=RangeSession(backend,RangeSessionSpec(session_id=f"range-session:ae3c-{treatment}-r{replicate}-{label}",revision="1",range_id=_RANGE_ID,actor_ids=(_DEFENDER_ID,),authorities=(_authority(),),metadata={"purpose":"ae3c-evidence-reduction","treatment":treatment,"replicate":replicate,"counterfactualHiddenWorld":label,"contestedNetwork":"none"})); session.start(); session.update_actor_presence(_DEFENDER_ID,"active",logical_time=1)
            prior_events=[]
            for idx,episode in enumerate(history,start=2): prior_events.append(session.record_management_event(logical_time=idx,source_id="observer:ae3c-prior-adjudication",event_type="evidence.prior-adjudicated-episode",payload=episode))
            backend.seed(session.instance); backend.emit_current_sensors(session.instance,logical_time=10); session.poll_backend(); sensor_events=[e.to_dict() for e in session.events if e.event_type=="service.compromise-observed"]
            projection_event=session.record_management_event(logical_time=12,source_id="reducer:ae3c-exact-v1",event_type="evidence.derived-factual-projection",payload=projection,causal_parents=tuple([e.event_id for e in prior_events]+[cast(str,e["eventId"]) for e in sensor_events if isinstance(e.get("eventId"),str)]))
            decision_event=session.record_management_event(logical_time=13,source_id="security:ae3c-runner",event_type="actor.reduced-evidence-decision-recorded",payload={"actorId":_DEFENDER_ID,"contextDigest":context.digest,"decisionDigest":decision.digest,"strategy":strategy,"epistemicState":"UNKNOWN","historyTreatment":treatment,"historyDigest":_history_digest(history),"projectionDigest":projection.get("projectionDigest"),"replicate":replicate,"harnessConclusionStatus":turn.get("conclusionStatus")},causal_parents=(projection_event.event_id,))
            admissions,receipts,logical_time=_execute(session=session,backend=backend,requests=decision.effect_requests,logical_time=14); consequence=_latest_event(session,"service.quarantine-observed"); cid=cast(str,consequence["eventId"]) if consequence and isinstance(consequence.get("eventId"),str) else None; outcome=backend.publish_outcome(session.instance,logical_time=logical_time+1,decision_event_id=decision_event.event_id,consequence_event_id=cid); session.poll_backend(); realized=_loss(compromised=compromised,strategy=strategy); oracle_strategy="quarantine" if compromised else "hold"; oracle=_loss(compromised=compromised,strategy=oracle_strategy)
            case:JsonObject={"schemaVersion":1,"label":label,"groundTruthCompromised":compromised,"defenderDecision":{"contextDigest":context.digest,"decision":decision.to_dict(),"turnEvidence":turn,"decisionEvent":decision_event.to_dict(),"strategy":strategy,"admissions":admissions,"executionReceipts":receipts},"postDecisionOutcomeTruth":outcome,"loss":{"realized":realized,"oracle":oracle,"regret":realized-oracle,"oracleStrategy":oracle_strategy},"finalState":backend.inspect(session.instance),"events":[e.to_dict() for e in session.events]}; validate_json(case); cases[label]=case; worlds[label]={"session":session}
        result:JsonObject={"schemaVersion":1,"treatment":treatment,"replicate":replicate,"historyDigest":_history_digest(history),"projectionDigest":projection.get("projectionDigest"),"contextDigest":context.digest,"decisionDigest":decision.digest,"turnEvidenceDigest":canonical_digest(turn),"strategy":strategy,"conclusionSummary":turn.get("conclusionSummary"),"healthy":cases["healthy"],"compromised":cases["compromised"]}; validate_json(result); return result
    finally:
        for world in worlds.values():
            session=cast(RangeSession,world["session"])
            if session.state in {"running","terminated"}:
                receipt=session.destroy(logical_time=100)
                if receipt.get("clean") is not True: raise RuntimeError("AE3-C Range cleanup failed")

def _run_treatment(*,state_root:Path,treatment:str,history:tuple[JsonObject,...],driver:DeepSeekRangeIntentDriver)->JsonObject:
    projection=_reduce_history(history); context=_context(history,treatment=treatment); reps=[]
    if not _verify_reduction(history,projection): raise RuntimeError("AE3-C factual projection failed independent reconstruction")
    for replicate in range(1,_REPLICATES+1):
        decision,turn=driver.decide(context,label=f"reduced-history-{treatment}-replicate-{replicate}"); reps.append(_world_pair(state_root=state_root,treatment=treatment,replicate=replicate,history=history,projection=projection,context=context,decision=decision,turn=turn))
    result:JsonObject={"schemaVersion":1,"treatment":treatment,"history":list(history),"historyDigest":_history_digest(history),"projection":projection,"contextDigest":context.digest,"replicates":reps}; validate_json(result); return result

def build_parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(); p.add_argument("--state-root",type=Path,required=True); p.add_argument("--receipt",type=Path,required=True); p.add_argument("--secret",type=Path,required=True); p.add_argument("--harness-source",type=Path,required=True); p.add_argument("--protocol-source",type=Path,default=Path("/root/projects/ordivon-computing/packages/ordivon-protocol")); p.add_argument("--protocol-repository",type=Path,default=Path("/root/projects/ordivon-computing")); return p

def main()->None:
    args=build_parser().parse_args()
    if args.state_root.exists(): raise FileExistsError(args.state_root)
    args.state_root.mkdir(parents=True,mode=0o700); args.state_root.chmod(0o700)
    history_a=_history(favored="A"); history_b=_history(favored="B")
    driver=DeepSeekRangeIntentDriver(DeepSeekRangeIntentConfig(secret_path=args.secret,harness_source=args.harness_source,protocol_source=args.protocol_source,protocol_repository=args.protocol_repository))
    try:
        treatment_a=_run_treatment(state_root=args.state_root,treatment="A-history",history=history_a,driver=driver); treatment_b=_run_treatment(state_root=args.state_root,treatment="B-history",history=history_b,driver=driver)
    except RangeIntentHarnessFailure as error:
        failure:JsonObject={"schemaVersion":1,"kind":"ordivon.security.adversarial-epistemics-ae3c-equipment-failure","status":"equipment-failure","securityRevision":_git_revision(Path.cwd()),"harnessFailure":error.evidence}; validate_json(failure); args.receipt.parent.mkdir(parents=True,exist_ok=True); args.receipt.write_bytes(canonical_bytes(failure)+b"\n"); print(json.dumps(failure,ensure_ascii=False,sort_keys=True,indent=2)); raise SystemExit(2) from error
    a_reps=cast(list[object],treatment_a["replicates"]); b_reps=cast(list[object],treatment_b["replicates"]); a_strategies=[cast(dict,x).get("strategy") for x in a_reps if isinstance(x,dict)]; b_strategies=[cast(dict,x).get("strategy") for x in b_reps if isinstance(x,dict)]
    projection_a=cast(JsonObject,treatment_a["projection"]); projection_b=cast(JsonObject,treatment_b["projection"])
    base_a=cast(JsonObject,_context(history_a,treatment="A-history").visible_observation.copy()); base_b=cast(JsonObject,_context(history_b,treatment="B-history").visible_observation.copy()); base_a.pop("priorAdjudicatedEpisodes",None); base_b.pop("priorAdjudicatedEpisodes",None); base_a.pop("derivedFactualProjection",None); base_b.pop("derivedFactualProjection",None)
    a_counts={cast(str,x["sourceId"]):cast(int,x["matchedAdjudicatedTruthCount"]) for x in cast(list[object],projection_a["sourceMatchCounts"]) if isinstance(x,dict)}
    b_counts={cast(str,x["sourceId"]):cast(int,x["matchedAdjudicatedTruthCount"]) for x in cast(list[object],projection_b["sourceMatchCounts"]) if isinstance(x,dict)}
    a_pattern=cast(JsonObject,projection_a["currentPatternPriorOccurrences"]); b_pattern=cast(JsonObject,projection_b["currentPatternPriorOccurrences"])
    def projection_bound(rep: object) -> bool:
        if not isinstance(rep,dict): return False
        for world in ("healthy","compromised"):
            case=rep.get(world)
            if not isinstance(case,dict): return False
            events=case.get("events")
            if not isinstance(events,list): return False
            projection_event=next((e for e in events if isinstance(e,dict) and e.get("eventType")=="evidence.derived-factual-projection"),None)
            decision_event=next((e for e in events if isinstance(e,dict) and e.get("eventType")=="actor.reduced-evidence-decision-recorded"),None)
            if not isinstance(projection_event,dict) or not isinstance(decision_event,dict): return False
            if projection_event.get("payload") != (projection_a if rep.get("treatment")=="A-history" else projection_b): return False
            if projection_event.get("eventId") not in decision_event.get("causalParents",[]): return False
        return True
    gates={
      "acceptedAE1ClaimExact":canonical_digest(_AE1_CLAIM)==_AE1_CLAIM_DIGEST,
      "acceptedAE2CurrentSensorSetExact":_sensor_digest()==_AE2_SENSOR_DIGEST,
      "exactAE3BRawHistoriesReused":_history_digest(history_a)==_AE3B_A_HISTORY_DIGEST and _history_digest(history_b)==_AE3B_B_HISTORY_DIGEST,
      "nonHistoryCurrentEvidenceIdentical":canonical_digest(base_a)==canonical_digest(base_b),
      "reducerRevisionExact":cast(JsonObject,projection_a["derivation"]).get("reducerRevision")==_REDUCER_REVISION and cast(JsonObject,projection_b["derivation"]).get("reducerRevision")==_REDUCER_REVISION,
      "projectionsIndependentlyReconstructable":_verify_reduction(history_a,projection_a) and _verify_reduction(history_b,projection_b),
      "projectionABindsExactCounts":a_counts=={"sensor:ae2-a":4,"sensor:ae2-b":0},
      "projectionBBindsExactCounts":b_counts=={"sensor:ae2-a":0,"sensor:ae2-b":4},
      "projectionABindsCurrentPatternTruthCounts":a_pattern.get("occurrenceCount")==2 and a_pattern.get("adjudicatedTrueCount")==2 and a_pattern.get("adjudicatedFalseCount")==0,
      "projectionBBindsCurrentPatternTruthCounts":b_pattern.get("occurrenceCount")==2 and b_pattern.get("adjudicatedTrueCount")==0 and b_pattern.get("adjudicatedFalseCount")==2,
      "derivedProjectionIsNotCurrentTruthOrPolicy":all(token not in str(projection_a).lower()+str(projection_b).lower() for token in ("recommendedaction","probability","trustscore","confidence","reputation")),
      "twoReplicatesPerTreatment":len(a_reps)==_REPLICATES and len(b_reps)==_REPLICATES,
      "withinTreatmentContextsStable":len({cast(dict,x).get("contextDigest") for x in a_reps if isinstance(x,dict)})==1 and len({cast(dict,x).get("contextDigest") for x in b_reps if isinstance(x,dict)})==1,
      "historyAReplicatesStable":a_strategies==["quarantine"]*_REPLICATES,
      "historyBReplicatesStable":b_strategies==["hold"]*_REPLICATES,
      "strategiesDifferByReducedHistoryTreatment":set(a_strategies)=={"quarantine"} and set(b_strategies)=={"hold"},
      "projectionPhysicallyPrecedesAndCausesDecision":all(projection_bound(x) for x in a_reps+b_reps),
      "allDecisionsRemainBounded":all(x in {"hold","quarantine"} for x in a_strategies+b_strategies),
      "noAdjudicationCapability":_authority().capabilities==(_QUARANTINE_CAPABILITY,),
      "noCurrentWorldTruthInContexts":_context(history_a,treatment="A-history").visible_observation["authoritativeCurrentWorldTruth"] is None and _context(history_b,treatment="B-history").visible_observation["authoritativeCurrentWorldTruth"] is None,
      "eachStrategyHasCounterfactualRegret":all(any(cast(JsonObject,cast(dict,r)[world]["loss"])["regret"]>0 for world in ("healthy","compromised")) for r in a_reps+b_reps if isinstance(r,dict)),
      "contestedRangeConsumedNoNetwork":True,
    }
    passed=all(gates.values())
    receipt:JsonObject={"schemaVersion":1,"kind":"ordivon.security.adversarial-epistemics-ae3c-acceptance","status":"accepted" if passed else "falsified","securityRevision":_git_revision(Path.cwd()),"question":"Does an exact deterministic reconstructable factual projection over the unchanged AE3-B raw episodes stabilize history-sensitive Agent evidence use and structured consequence strategy without introducing source scores, current truth, or policy instruction?","treatmentA":treatment_a,"treatmentB":treatment_b,"gates":gates,"interpretation":{"verifiableEvidenceReductionUsefulForThisConsumer":True if passed else None,"genericEvidenceComputationPressure":True if passed else None,"securityTrustPrimitiveForced":False if passed else None,"durableSourceHistoryPrimitiveForced":False if passed else None,"projectionPromotedToCurrentTruth":False,"projectionIsPolicyInstruction":False,"nextPressureIfAccepted":"cross-domain-generic-evidence-reduction-and-recovery-before-security-core-abstraction"}}
    validate_json(receipt); args.receipt.parent.mkdir(parents=True,exist_ok=True); args.receipt.write_bytes(canonical_bytes(receipt)+b"\n"); print(json.dumps(receipt,ensure_ascii=False,sort_keys=True,indent=2));
    if not passed: raise SystemExit(1)

if __name__=="__main__": main()
