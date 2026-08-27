from __future__ import annotations

from pathlib import Path

from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.ordinary_memory import (
    ROOT,
    security_ordinary_provider_currentness,
    security_ordinary_research_inspect,
)
from ordivon_security.surface import security_ordinary_surface_manifest

_REQUIRED_OWNER_MEMORY = (
    "research/corpus/seed-ca2-vulnerability.json",
    "research/corpus/seed-eicar-sample.json",
    "research/corpus/seed-caseb-sample-postedge.json",
    "research/corpus/k1/controlled-osv-old.json",
)
_REQUIRED_CURRENTNESS = (
    "research/corpus/k1/controlled-osv-old.json",
    "research/corpus/k1/controlled-osv-current.json",
)


def _files_present(root: Path, relative_paths: tuple[str, ...]) -> tuple[bool, list[str]]:
    missing = [relative for relative in relative_paths if not (root / relative).is_file()]
    return not missing, missing


def _operation(
    *,
    operation: str,
    eligibility: str,
    turn_addressable: bool,
    reason: str,
    basis: JsonObject,
) -> JsonObject:
    value: JsonObject = {
        "operation": operation,
        "mechanicalEligibility": eligibility,
        "turnAddressable": turn_addressable,
        "reason": reason,
        "basis": basis,
    }
    validate_json(value)
    return value


def security_ordinary_capability_preflight(
    *,
    record_id: str | None = None,
    root: Path = ROOT,
) -> JsonObject:
    """Compile current owner-local mechanics into turn-addressable Security operations.

    This is a read-only mechanical projection. It does not select a semantic task, grant
    Range/Evaluation authority, fetch external provider data, or execute an effect. The
    caller may use ``turnAddressableOwnerOperations`` to filter model-facing Tool schemas.
    """

    ordinary = security_ordinary_surface_manifest()
    declared = {
        str(item["operation"]): item
        for item in ordinary["ownerOperations"]
        if isinstance(item, dict)
    }

    memory_ready, memory_missing = _files_present(root, _REQUIRED_OWNER_MEMORY)
    currentness_ready, currentness_missing = _files_present(root, _REQUIRED_CURRENTNESS)

    operations: list[JsonObject] = []
    operations.append(
        _operation(
            operation="security.ordinary.research.query",
            eligibility="eligible" if memory_ready else "ineligible",
            turn_addressable=memory_ready,
            reason=(
                "Exact owner-memory seed sources are present; semantic query choice remains Agent-owned."
                if memory_ready
                else "Required owner-memory source files are absent; the query operation is withdrawn."
            ),
            basis={"requiredSourceCount": len(_REQUIRED_OWNER_MEMORY), "missingSources": memory_missing},
        )
    )

    inspect_eligible = False
    inspect_reason = "No exact recordId is currently selected; inspect is not turn-addressable yet."
    inspect_basis: JsonObject = {"recordIdSelected": record_id is not None}
    if record_id is not None:
        if not memory_ready:
            inspect_reason = "Owner-memory sources are unavailable; selected-record inspection is withdrawn."
            inspect_basis["missingSources"] = memory_missing
        else:
            try:
                inspection = security_ordinary_research_inspect(record_id, root=root)
            except (FileNotFoundError, KeyError, ValueError) as exc:
                inspect_reason = "The selected recordId is not mechanically inspectable in current owner memory."
                inspect_basis["recordId"] = record_id
                inspect_basis["failureClass"] = type(exc).__name__
            else:
                inspect_eligible = True
                inspect_reason = "The exact selected recordId resolves in current owner memory."
                inspect_basis["recordId"] = record_id
                inspected = inspection.get("inspection")
                if isinstance(inspected, dict):
                    inspect_basis["recordKind"] = inspected.get("recordKind")
    operations.append(
        _operation(
            operation="security.ordinary.research.inspect",
            eligibility=(
                "eligible"
                if inspect_eligible
                else ("input-required" if record_id is None and memory_ready else "ineligible")
            ),
            turn_addressable=inspect_eligible,
            reason=inspect_reason,
            basis=inspect_basis,
        )
    )

    currentness_eligible = False
    currentness_basis: JsonObject = {
        "requiredSourceCount": len(_REQUIRED_CURRENTNESS),
        "missingSources": currentness_missing,
    }
    currentness_reason = "Required exact provider snapshots are absent; currentness comparison is withdrawn."
    if currentness_ready:
        try:
            comparison = security_ordinary_provider_currentness(root=root)
        except (FileNotFoundError, KeyError, ValueError) as exc:
            currentness_basis["failureClass"] = type(exc).__name__
            currentness_reason = "Current owner snapshots exist but failed exact read-only comparison."
        else:
            currentness_eligible = True
            currentness_reason = "Exact retained and candidate provider snapshots support read-only comparison."
            candidate = comparison.get("comparison")
            if isinstance(candidate, dict):
                currentness_basis["comparisonStatus"] = candidate.get("status")
    operations.append(
        _operation(
            operation="security.ordinary.provider-currentness",
            eligibility="eligible" if currentness_eligible else "ineligible",
            turn_addressable=currentness_eligible,
            reason=currentness_reason,
            basis=currentness_basis,
        )
    )

    unknown = sorted({str(item["operation"]) for item in operations} - set(declared))
    if unknown:
        raise ValueError(f"capability preflight references undeclared ordinary operations: {unknown}")

    exposed = [str(item["operation"]) for item in operations if item["turnAddressable"] is True]
    withdrawn = [str(item["operation"]) for item in operations if item["turnAddressable"] is False]
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.ordinary-capability-preflight",
        "truthRole": "derived-owner-local-mechanical-eligibility-projection",
        "operations": operations,
        "turnAddressableOwnerOperations": exposed,
        "withdrawnOwnerOperations": withdrawn,
        "rules": [
            "mechanical admission occurs before model-facing disclosure",
            "semantic selection remains with the Agent/domain after mechanical admission",
            "an executable or declared operation is not automatically current or turn-addressable",
            "this projection never grants Range/Evaluation execution authority",
            "this projection performs no external provider fetch and no world mutation",
        ],
    }
    validate_json(value)
    return value


__all__ = ["security_ordinary_capability_preflight"]
