"""Campaign Manifest v0 canonicalization and semantic validation.

The committed JSON Schema is the portable structural contract. This module
uses only the Python standard library and adds bounded parsing plus the
cross-field and transition invariants JSON Schema cannot express.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.1.0"
CANONICALIZATION = "ordivon-canonical-json-v0"
MAX_MANIFEST_BYTES = 1_048_576
MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_NODES = 100_000
MAX_ERRORS = 100
MAX_INTEGER = 9_223_372_036_854_775_807
MIN_INTEGER = -MAX_INTEGER - 1

UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
RESOURCE_KEY_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas/campaign-manifest.schema.json"
)
SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "contains",
    "description",
    "enum",
    "items",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


class ContractError(ValueError):
    """One or more Campaign contract violations."""

    def __init__(self, errors: list[str]):
        self.errors = errors[:MAX_ERRORS]
        if len(errors) > MAX_ERRORS:
            self.errors[-1] = f"$: validation stopped after {MAX_ERRORS} errors"
        super().__init__("\n".join(self.errors))


def _append_error(errors: list[str], message: str) -> None:
    if len(errors) < MAX_ERRORS:
        errors.append(message)


def _schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    try:
        value = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError([f"$schema: cannot load committed schema: {exc}"]) from exc
    if not isinstance(value, dict):
        raise ContractError(["$schema: root must be an object"])
    _check_schema_vocabulary(value)
    return value


def _check_schema_vocabulary(schema: dict[str, Any], path: str = "$schema") -> None:
    for key, value in schema.items():
        if key not in SCHEMA_KEYWORDS:
            raise ContractError([f"{path}: unsupported schema keyword {key!r}"])
        if key in {"properties", "$defs"}:
            for name, child in value.items():
                _check_schema_vocabulary(child, f"{path}.{key}.{name}")
        elif key in {"items", "contains"} and isinstance(value, dict):
            _check_schema_vocabulary(value, f"{path}.{key}")
        elif key == "additionalProperties" and isinstance(value, dict):
            _check_schema_vocabulary(value, f"{path}.{key}")
        elif key == "oneOf":
            for index, child in enumerate(value):
                _check_schema_vocabulary(child, f"{path}.oneOf[{index}]")


def _display_path(path: str, key: str) -> str:
    if RESOURCE_KEY_RE.fullmatch(key):
        return f"{path}.{key}"
    return f"{path}[{key!r}]"


def _resolve_ref(pointer: str, root: dict[str, Any]) -> dict[str, Any]:
    if not pointer.startswith("#/"):
        raise ContractError([f"$schema: unsupported non-local reference {pointer!r}"])
    target: Any = root
    try:
        for token in pointer[2:].split("/"):
            target = target[token.replace("~1", "/").replace("~0", "~")]
    except (KeyError, TypeError) as exc:
        raise ContractError([f"$schema: unresolved reference {pointer!r}"]) from exc
    if not isinstance(target, dict):
        raise ContractError([f"$schema: reference {pointer!r} is not an object schema"])
    return target


def _schema_errors(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
    *,
    depth: int = 0,
) -> list[str]:
    """Evaluate the bounded JSON Schema vocabulary used by this contract."""

    errors: list[str] = []
    if depth > MAX_CANONICAL_DEPTH:
        return [f"{path}: exceeds maximum nesting depth {MAX_CANONICAL_DEPTH}"]
    if "$ref" in schema:
        return _schema_errors(
            value, _resolve_ref(schema["$ref"], root), root, path, depth=depth
        )
    if "oneOf" in schema:
        branches = [
            _schema_errors(value, branch, root, path, depth=depth)
            for branch in schema["oneOf"]
        ]
        if sum(not branch_errors for branch_errors in branches) != 1:
            return [f"{path}: must match exactly one allowed shape"]
        return []

    if "const" in schema and value != schema["const"]:
        _append_error(errors, f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        _append_error(errors, f"{path}: must be one of {schema['enum']!r}")
    expected_type = schema.get("type")
    if expected_type and not _schema_type_matches(value, expected_type):
        return [f"{path}: must be {expected_type}"]

    if isinstance(value, dict):
        maximum = schema.get("maxProperties")
        if maximum is not None and len(value) > maximum:
            return [f"{path}: must contain at most {maximum} properties"]
        required = set(schema.get("required", []))
        for name in sorted(required - value.keys()):
            _append_error(errors, f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, item in value.items():
            if len(errors) >= MAX_ERRORS:
                break
            item_path = _display_path(path, name)
            if name in properties:
                errors.extend(
                    _schema_errors(
                        item, properties[name], root, item_path, depth=depth + 1
                    )
                )
            elif additional is False:
                _append_error(errors, f"{path}: unexpected property {name!r}")
            elif isinstance(additional, dict):
                errors.extend(
                    _schema_errors(item, additional, root, item_path, depth=depth + 1)
                )
    elif isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(value) < minimum:
            _append_error(errors, f"{path}: must contain at least {minimum} item(s)")
        if maximum is not None and len(value) > maximum:
            return [f"{path}: must contain at most {maximum} item(s)"]
        if schema.get("uniqueItems"):
            seen: set[bytes] = set()
            for index, item in enumerate(value):
                marker = canonical_bytes(item)
                if marker in seen:
                    _append_error(errors, f"{path}[{index}]: duplicates an array item")
                seen.add(marker)
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                if len(errors) >= MAX_ERRORS:
                    break
                errors.extend(
                    _schema_errors(
                        item,
                        item_schema,
                        root,
                        f"{path}[{index}]",
                        depth=depth + 1,
                    )
                )
        contains = schema.get("contains")
        if isinstance(contains, dict) and not any(
            not _schema_errors(
                item, contains, root, f"{path}[{index}]", depth=depth + 1
            )
            for index, item in enumerate(value)
        ):
            _append_error(errors, f"{path}: does not contain the required item shape")
    elif isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and len(value) < minimum:
            _append_error(
                errors, f"{path}: must contain at least {minimum} character(s)"
            )
        if maximum is not None and len(value) > maximum:
            _append_error(
                errors, f"{path}: must contain at most {maximum} character(s)"
            )
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            _append_error(errors, f"{path}: does not match required pattern")
    elif isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            _append_error(errors, f"{path}: must be >= {minimum}")
        if maximum is not None and value > maximum:
            _append_error(errors, f"{path}: must be <= {maximum}")
    return errors[:MAX_ERRORS]


def validate_schema(manifest: dict[str, Any]) -> None:
    """Validate against the committed schema without third-party packages."""

    schema = _schema()
    errors = _schema_errors(manifest, schema, schema)
    if errors:
        raise ContractError(errors)


def _check_unicode_scalar(value: str, path: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ContractError([f"{path}: contains a lone Unicode surrogate"])


def _check_canonical_tree(
    value: Any,
    path: str = "$",
    *,
    depth: int = 0,
    active: set[int] | None = None,
    budget: list[int] | None = None,
) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise ContractError(
            [f"{path}: exceeds maximum nesting depth {MAX_CANONICAL_DEPTH}"]
        )
    if active is None:
        active = set()
    if budget is None:
        budget = [MAX_CANONICAL_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise ContractError(
            [f"{path}: exceeds canonical node limit {MAX_CANONICAL_NODES}"]
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise ContractError([f"{path}: integer is outside signed 64-bit range"])
        return
    if isinstance(value, float):
        raise ContractError(
            [f"{path}: floating-point values are not canonical v0 values"]
        )
    if isinstance(value, str):
        _check_unicode_scalar(value, path)
        return
    if not isinstance(value, (list, dict)):
        raise ContractError(
            [f"{path}: unsupported canonical value {type(value).__name__}"]
        )
    marker = id(value)
    if marker in active:
        raise ContractError([f"{path}: cyclic values are not canonical JSON"])
    active.add(marker)
    try:
        if isinstance(value, list):
            for index, item in enumerate(value):
                _check_canonical_tree(
                    item,
                    f"{path}[{index}]",
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
        else:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ContractError([f"{path}: object key is not a string"])
                _check_unicode_scalar(key, path)
                _check_canonical_tree(
                    item,
                    _display_path(path, key),
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
    finally:
        active.remove(marker)


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 bytes for ``ordivon-canonical-json-v0``."""

    _check_canonical_tree(value)
    parts: list[str] = []
    _emit_canonical(value, parts)
    return "".join(parts).encode("utf-8")


def _quote_string(value: str) -> str:
    escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    parts = ['"']
    for character in value:
        escaped = escapes.get(character)
        if escaped is not None:
            parts.append(escaped)
        elif ord(character) < 0x20:
            parts.append(f"\\u{ord(character):04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _emit_canonical(value: Any, parts: list[str]) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, int):
        parts.append(str(value))
    elif isinstance(value, str):
        parts.append(_quote_string(value))
    elif isinstance(value, list):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _emit_canonical(item, parts)
        parts.append("]")
    else:
        parts.append("{")
        for index, key in enumerate(sorted(value)):
            if index:
                parts.append(",")
            parts.append(_quote_string(key))
            parts.append(":")
            _emit_canonical(value[key], parts)
        parts.append("}")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def envelope_digest(envelope: dict[str, Any]) -> str:
    """Digest one orthogonal envelope, excluding only its digest slot."""

    return digest({key: value for key, value in envelope.items() if key != "digest"})


def manifest_digest(manifest: dict[str, Any]) -> str:
    """Digest a manifest, excluding only the self-referential digest slot."""

    payload = dict(manifest)
    identity = payload.get("identity")
    if isinstance(identity, dict):
        payload["identity"] = {
            key: value for key, value in identity.items() if key != "manifest_digest"
        }
    return digest(payload)


def _parse_integer(token: str) -> int:
    if len(token.lstrip("-")) > 19:
        raise ContractError(["$: integer token exceeds signed 64-bit range"])
    value = int(token)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise ContractError(["$: integer token exceeds signed 64-bit range"])
    return value


def _reject_float(_token: str) -> Any:
    raise ContractError(["$: floating-point values are not canonical v0 values"])


def _reject_constant(token: str) -> Any:
    raise ContractError([f"$: non-finite number {token!r} is not JSON"])


def load_json(path: str | Path) -> dict[str, Any]:
    """Load one bounded UTF-8 manifest and reject ambiguous JSON."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ContractError([f"$: duplicate JSON key {key!r}"])
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ContractError(
                [f"$: manifest exceeds {MAX_MANIFEST_BYTES} byte input limit"]
            )
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        _check_canonical_tree(value)
    except ContractError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError([f"$: cannot load JSON: {exc}"]) from exc
    if not isinstance(value, dict):
        raise ContractError(["$: Campaign manifest must be an object"])
    return value


class _Checks:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, path: str, message: str) -> None:
        _append_error(self.errors, f"{path}: {message}")


def _expect_id(checks: _Checks, value: str, path: str, prefix: str) -> None:
    if not value.startswith(prefix):
        checks.error(path, f"must use identity namespace {prefix!r}")


def _typed_ref(
    checks: _Checks, ref: dict[str, Any], path: str, expected_project: str
) -> None:
    project = ref["project"]
    if project != expected_project:
        checks.error(f"{path}.project", f"must be {expected_project!r}")
    id_project = ref["id"].split(":", 3)[2]
    if id_project != project:
        checks.error(f"{path}.id", f"namespace project must match {project!r}")


def _unique_ids(
    checks: _Checks, values: list[dict[str, Any]], path: str
) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(values):
        item_id = item["id"]
        if item_id in found:
            checks.error(f"{path}[{index}].id", f"duplicates identity {item_id!r}")
        else:
            found[item_id] = item
    return found


def _validate_envelope_ref(
    checks: _Checks,
    ref: dict[str, Any],
    envelope: dict[str, Any],
    path: str,
) -> None:
    for field in ("id", "revision", "digest"):
        if ref[field] != envelope[field]:
            checks.error(f"{path}.{field}", f"must equal envelope.{field}")


def _valid_utc_timestamp(value: str) -> bool:
    if UTC_TIMESTAMP_RE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def validate_campaign(manifest: dict[str, Any]) -> None:
    """Validate one fully materialized Campaign Manifest v0."""

    validate_schema(manifest)
    checks = _Checks()
    campaign = manifest["campaign"]
    world = manifest["world"]
    authority = manifest["authority"]
    actors = manifest["actors"]
    capability = manifest["capability_envelope"]
    consequence = manifest["consequence_envelope"]

    _expect_id(
        checks, campaign["id"], "$.campaign.id", "urn:ordivon:security:campaign:"
    )
    expected_campaign_revision = f"{campaign['id']}:revision-{campaign['revision']}"
    if campaign["revision_id"] != expected_campaign_revision:
        checks.error(
            "$.campaign.revision_id", f"must equal {expected_campaign_revision!r}"
        )

    _expect_id(checks, world["id"], "$.world.id", "urn:ordivon:security:world:")
    expected_world_revision = f"{world['id']}:revision-{world['revision']}"
    if world["revision_id"] != expected_world_revision:
        checks.error("$.world.revision_id", f"must equal {expected_world_revision!r}")
    for project in ("link", "edge", "game"):
        _typed_ref(checks, world[f"{project}_ref"], f"$.world.{project}_ref", project)

    provenance = manifest["provenance"]
    _typed_ref(checks, provenance["source_ref"], "$.provenance.source_ref", "source")
    policy_ids: set[str] = set()
    for index, policy in enumerate(provenance["policy_refs"]):
        path = f"$.provenance.policy_refs[{index}]"
        _typed_ref(checks, policy, path, "policy")
        if policy["id"] in policy_ids:
            checks.error(f"{path}.id", f"duplicates policy identity {policy['id']!r}")
        policy_ids.add(policy["id"])

    actor_map = _unique_ids(checks, actors, "$.actors")
    evaluated_actor_ids: set[str] = set()
    for index, actor in enumerate(actors):
        path = f"$.actors[{index}]"
        _expect_id(checks, actor["id"], f"{path}.id", "urn:ordivon:security:actor:")
        role = actor["role"]
        expected_plane = {
            "observer": "observation",
            "judge": "observation",
            "lifecycle_authority": "management",
        }.get(role, "experiment")
        if actor["control_plane"] != expected_plane:
            checks.error(
                f"{path}.control_plane",
                f"role {role!r} requires {expected_plane!r}",
            )
        if role in {"observer", "judge", "lifecycle_authority"} and actor["evaluated"]:
            checks.error(f"{path}.evaluated", f"role {role!r} must not be evaluated")
        if actor["evaluated"]:
            evaluated_actor_ids.add(actor["id"])
    if not evaluated_actor_ids:
        checks.error("$.actors", "must declare at least one evaluated experiment actor")

    _expect_id(
        checks,
        authority["authority_id"],
        "$.authority.authority_id",
        "urn:ordivon:security:authority:",
    )
    if authority["authority_id"] in actor_map:
        checks.error(
            "$.authority.authority_id",
            "authority identity must be distinct from every actor identity",
        )
    expected_record_id = f"{campaign['id']}:admission-{campaign['revision']}"
    if authority["record_id"] != expected_record_id:
        checks.error("$.authority.record_id", f"must equal {expected_record_id!r}")
    if authority["campaign_id"] != campaign["id"]:
        checks.error("$.authority.campaign_id", "must equal campaign.id")
    if authority["campaign_revision"] != campaign["revision"]:
        checks.error("$.authority.campaign_revision", "must equal campaign.revision")
    if authority["world_id"] != world["id"]:
        checks.error("$.authority.world_id", "must equal world.id")
    if authority["world_revision_id"] != world["revision_id"]:
        checks.error("$.authority.world_revision_id", "must equal world.revision_id")
    if not _valid_utc_timestamp(authority["admitted_at"]):
        checks.error(
            "$.authority.admitted_at",
            "must be a real UTC timestamp formatted YYYY-MM-DDTHH:MM:SSZ",
        )
    authority_roles = {
        "admitted_by_actor_id": "lifecycle_authority",
        "lifecycle_actor_id": "lifecycle_authority",
        "judge_actor_id": "judge",
    }
    for field, expected_role in authority_roles.items():
        actor = actor_map.get(authority[field])
        if actor is None:
            checks.error(f"$.authority.{field}", "must reference a declared actor")
        elif actor["role"] != expected_role:
            checks.error(
                f"$.authority.{field}", f"must reference role {expected_role!r}"
            )
    for index, actor_id in enumerate(authority["observer_actor_ids"]):
        actor = actor_map.get(actor_id)
        if actor is None or actor["role"] != "observer":
            checks.error(
                f"$.authority.observer_actor_ids[{index}]",
                "must reference an observer actor",
            )
    independent = {
        authority["lifecycle_actor_id"],
        authority["judge_actor_id"],
        *authority["observer_actor_ids"],
    }
    if len(independent) != 2 + len(authority["observer_actor_ids"]):
        checks.error(
            "$.authority",
            "lifecycle, judge, and observer actor identities must be independent",
        )

    _expect_id(
        checks,
        capability["id"],
        "$.capability_envelope.id",
        "urn:ordivon:security:capability-envelope:",
    )
    for project in ("host", "runtime"):
        _typed_ref(
            checks,
            capability[f"{project}_ref"],
            f"$.capability_envelope.{project}_ref",
            project,
        )
    _typed_ref(
        checks,
        capability["tool_catalog_ref"],
        "$.capability_envelope.tool_catalog_ref",
        "tool",
    )
    subject = actor_map.get(capability["subject_actor_id"])
    if (
        subject is None
        or not subject["evaluated"]
        or subject["control_plane"] != "experiment"
    ):
        checks.error(
            "$.capability_envelope.subject_actor_id",
            "must reference an evaluated experiment actor",
        )
    if capability["subject_actor_id"] in capability["collaborator_actor_ids"]:
        checks.error(
            "$.capability_envelope.collaborator_actor_ids",
            "must not repeat subject_actor_id",
        )
    for index, actor_id in enumerate(capability["collaborator_actor_ids"]):
        actor = actor_map.get(actor_id)
        if (
            actor is None
            or not actor["evaluated"]
            or actor["control_plane"] != "experiment"
        ):
            checks.error(
                f"$.capability_envelope.collaborator_actor_ids[{index}]",
                "must reference an evaluated experiment actor",
            )
    for key in capability["resources"]:
        if RESOURCE_KEY_RE.fullmatch(key) is None:
            checks.error(
                f"$.capability_envelope.resources[{key!r}]",
                "resource key must be lowercase ASCII identifier",
            )
    expected_capability_digest = envelope_digest(capability)
    if capability["digest"] != expected_capability_digest:
        checks.error(
            "$.capability_envelope.digest",
            f"digest mismatch; expected {expected_capability_digest}",
        )

    _expect_id(
        checks,
        consequence["id"],
        "$.consequence_envelope.id",
        "urn:ordivon:security:consequence-envelope:",
    )
    if consequence["world_revision_id"] != world["revision_id"]:
        checks.error(
            "$.consequence_envelope.world_revision_id",
            "must equal world.revision_id",
        )
    targets = _unique_ids(
        checks, consequence["targets"], "$.consequence_envelope.targets"
    )
    for index, target in enumerate(consequence["targets"]):
        path = f"$.consequence_envelope.targets[{index}]"
        _expect_id(checks, target["id"], f"{path}.id", "urn:ordivon:security:target:")
        if target["authority_id"] != authority["authority_id"]:
            checks.error(f"{path}.authority_id", "must equal authority.authority_id")
    del targets
    _unique_ids(checks, consequence["networks"], "$.consequence_envelope.networks")
    for index, network in enumerate(consequence["networks"]):
        path = f"$.consequence_envelope.networks[{index}]"
        _expect_id(checks, network["id"], f"{path}.id", "urn:ordivon:link:network:")
        if network["mode"] == "disconnected" and network["allowed_destinations"]:
            checks.error(
                f"{path}.allowed_destinations",
                "must be empty for disconnected networks",
            )
    boundaries = _unique_ids(
        checks,
        consequence["external_boundaries"],
        "$.consequence_envelope.external_boundaries",
    )
    for index, boundary in enumerate(consequence["external_boundaries"]):
        _expect_id(
            checks,
            boundary["id"],
            f"$.consequence_envelope.external_boundaries[{index}].id",
            "urn:ordivon:security:boundary:",
        )
    del boundaries
    expected_consequence_digest = envelope_digest(consequence)
    if consequence["digest"] != expected_consequence_digest:
        checks.error(
            "$.consequence_envelope.digest",
            f"digest mismatch; expected {expected_consequence_digest}",
        )

    _validate_envelope_ref(
        checks,
        authority["capability_envelope_ref"],
        capability,
        "$.authority.capability_envelope_ref",
    )
    _validate_envelope_ref(
        checks,
        authority["consequence_envelope_ref"],
        consequence,
        "$.authority.consequence_envelope_ref",
    )

    objective_map = _unique_ids(checks, manifest["objectives"], "$.objectives")
    for index, objective in enumerate(manifest["objectives"]):
        path = f"$.objectives[{index}]"
        _expect_id(
            checks, objective["id"], f"{path}.id", "urn:ordivon:security:objective:"
        )
        actor = actor_map.get(objective["actor_id"])
        if actor is None:
            checks.error(f"{path}.actor_id", "must reference a declared actor")
        elif actor["control_plane"] != "experiment":
            checks.error(
                f"{path}.actor_id",
                "objectives cannot be assigned to authority or observation actors",
            )

    _unique_ids(checks, manifest["stop_conditions"], "$.stop_conditions")
    for index, condition in enumerate(manifest["stop_conditions"]):
        path = f"$.stop_conditions[{index}]"
        _expect_id(checks, condition["id"], f"{path}.id", "urn:ordivon:security:stop:")
        kind = condition["kind"]
        has_limit = "limit" in condition
        has_resource = "resource" in condition
        if kind == "deadline" and (not has_limit or has_resource):
            checks.error(path, "deadline requires limit and forbids resource")
        elif (
            kind == "deadline"
            and condition["limit"] > capability["time"]["wall_seconds"]
        ):
            checks.error(path, "deadline limit cannot exceed capability wall_seconds")
        elif kind == "budget_exhausted" and (not has_limit or not has_resource):
            checks.error(path, "budget_exhausted requires limit and resource")
        elif kind == "budget_exhausted":
            resource = condition["resource"]
            if resource not in capability["resources"]:
                checks.error(path, "budget resource must exist in capability resources")
            elif condition["limit"] != capability["resources"][resource]:
                checks.error(
                    path, "budget limit must equal the admitted resource budget"
                )
        elif kind not in {"deadline", "budget_exhausted"} and (
            has_limit or has_resource
        ):
            checks.error(path, f"{kind} forbids limit and resource")
    authority_stops = [
        item
        for item in manifest["stop_conditions"]
        if item["kind"] == "authority_action"
    ]
    if not authority_stops:
        checks.error(
            "$.stop_conditions", "must include an out-of-band authority_action"
        )

    outcome = manifest["outcome"]
    if campaign["state"] == "admitted" and outcome is not None:
        checks.error("$.outcome", "must be null while campaign.state is 'admitted'")
    if campaign["state"] == "completed" and outcome is None:
        checks.error("$.outcome", "must be present while campaign.state is 'completed'")
    if outcome is not None:
        if outcome["recorded_by"] != authority["judge_actor_id"]:
            checks.error("$.outcome.recorded_by", "must equal authority.judge_actor_id")
        assessments: dict[str, dict[str, Any]] = {}
        for index, assessment in enumerate(outcome["objective_assessments"]):
            path = f"$.outcome.objective_assessments[{index}]"
            objective_id = assessment["objective_id"]
            if objective_id not in objective_map:
                checks.error(
                    f"{path}.objective_id", "must reference a declared objective"
                )
            if objective_id in assessments:
                checks.error(
                    f"{path}.objective_id", "duplicates an objective assessment"
                )
            assessments[objective_id] = assessment
            if assessment["status"] != "unknown" and not assessment["evidence_refs"]:
                checks.error(
                    f"{path}.evidence_refs",
                    "non-unknown assessments require evidence",
                )
        classification = outcome["classification"]
        statuses = [item["status"] for item in assessments.values()]
        if classification in {"success", "partial_progress", "defense"}:
            if set(assessments) != set(objective_map):
                checks.error(
                    "$.outcome.objective_assessments",
                    "must assess every objective for this classification",
                )
            if "unknown" in statuses:
                checks.error(
                    "$.outcome.objective_assessments",
                    "conclusive objective classifications cannot contain unknown status",
                )
        if classification == "success" and (
            not statuses or any(status != "achieved" for status in statuses)
        ):
            checks.error("$.outcome", "success requires every objective to be achieved")
        if classification == "partial_progress" and not any(
            status == "partially_achieved" for status in statuses
        ):
            checks.error(
                "$.outcome",
                "partial_progress requires a partially_achieved objective",
            )
        if classification == "defense":
            red_objective_ids = {
                objective_id
                for objective_id, objective in objective_map.items()
                if objective["actor_id"] in actor_map
                and actor_map[objective["actor_id"]]["role"] == "red"
            }
            red_statuses = [
                assessments[objective_id]["status"]
                for objective_id in red_objective_ids
                if objective_id in assessments
            ]
            if (
                not red_statuses
                or "prevented" not in red_statuses
                or any(
                    status not in {"prevented", "not_achieved"}
                    for status in red_statuses
                )
            ):
                checks.error(
                    "$.outcome",
                    "defense requires every Red objective to be prevented or not achieved",
                )
        if classification == "escape" and not outcome["containment_breach"]:
            checks.error("$.outcome.containment_breach", "must be true for escape")
        if classification != "escape" and outcome["containment_breach"]:
            checks.error(
                "$.outcome.containment_breach",
                "must be false unless classification is escape",
            )
        expected_quality = {
            "observer_loss": "inconclusive",
            "inconclusive_evidence": "inconclusive",
            "invalid_run": "invalid",
        }.get(classification, "conclusive")
        if outcome["evidence_quality"] != expected_quality:
            checks.error(
                "$.outcome.evidence_quality",
                f"must be {expected_quality!r} for {classification!r}",
            )
        if classification in {
            "escape",
            "observer_loss",
            "invalid_run",
            "inconclusive_evidence",
        } and not outcome.get("reason_codes"):
            checks.error("$.outcome.reason_codes", "must explain this classification")

    if manifest["identity"]["canonicalization"] != CANONICALIZATION:
        checks.error("$.identity.canonicalization", f"must equal {CANONICALIZATION!r}")
    expected_manifest_digest = manifest_digest(manifest)
    if manifest["identity"]["manifest_digest"] != expected_manifest_digest:
        checks.error(
            "$.identity.manifest_digest",
            f"digest mismatch; expected {expected_manifest_digest}",
        )
    if checks.errors:
        raise ContractError(checks.errors)


def _revisioned_substance(value: dict[str, Any], *extra: str) -> dict[str, Any]:
    omitted = {"digest", "revision", *extra}
    return {key: item for key, item in value.items() if key not in omitted}


def _validate_component_transition(
    errors: list[str],
    previous: dict[str, Any],
    current: dict[str, Any],
    path: str,
) -> bool:
    if current["id"] != previous["id"]:
        _append_error(errors, f"{path}.id: transition must preserve logical identity")
    changed = _revisioned_substance(previous) != _revisioned_substance(current)
    if changed:
        if current["revision"] != previous["revision"] + 1:
            _append_error(
                errors,
                f"{path}.revision: changed substance must advance exactly one revision",
            )
        if current["digest"] == previous["digest"]:
            _append_error(
                errors, f"{path}.digest: changed substance must change digest"
            )
    elif (
        current["revision"] != previous["revision"]
        or current["digest"] != previous["digest"]
    ):
        _append_error(
            errors, f"{path}: unchanged substance must retain revision and digest"
        )
    return changed


def validate_transition(previous: dict[str, Any], current: dict[str, Any]) -> None:
    """Validate ``current`` as the next immutable Campaign record revision."""

    validate_campaign(previous)
    validate_campaign(current)
    errors: list[str] = []
    old_campaign = previous["campaign"]
    new_campaign = current["campaign"]
    if new_campaign["id"] != old_campaign["id"]:
        _append_error(
            errors, "$.campaign.id: transition must preserve Campaign identity"
        )
    if new_campaign["revision"] != old_campaign["revision"] + 1:
        _append_error(
            errors,
            "$.campaign.revision: next Campaign record must advance exactly one revision",
        )
    if old_campaign["state"] == "completed" and new_campaign["state"] != "completed":
        _append_error(errors, "$.campaign.state: completed Campaign cannot be reopened")
    if current["authority"]["authority_id"] != previous["authority"]["authority_id"]:
        _append_error(
            errors,
            "$.authority.authority_id: transition must preserve admission authority",
        )
    old_admitted_at = datetime.strptime(
        previous["authority"]["admitted_at"], "%Y-%m-%dT%H:%M:%SZ"
    )
    new_admitted_at = datetime.strptime(
        current["authority"]["admitted_at"], "%Y-%m-%dT%H:%M:%SZ"
    )
    if new_admitted_at < old_admitted_at:
        _append_error(
            errors,
            "$.authority.admitted_at: next record cannot predate the previous admission",
        )

    old_world = previous["world"]
    new_world = current["world"]
    if new_world["id"] != old_world["id"]:
        _append_error(errors, "$.world.id: transition must preserve World identity")
    world_changed = _revisioned_substance(
        old_world, "revision_id"
    ) != _revisioned_substance(new_world, "revision_id")
    if world_changed:
        if new_world["revision"] != old_world["revision"] + 1:
            _append_error(
                errors,
                "$.world.revision: changed World must advance exactly one revision",
            )
    elif (
        new_world["revision"] != old_world["revision"]
        or new_world["revision_id"] != old_world["revision_id"]
    ):
        _append_error(
            errors,
            "$.world: unchanged World must retain revision and revision_id",
        )

    _validate_component_transition(
        errors,
        previous["capability_envelope"],
        current["capability_envelope"],
        "$.capability_envelope",
    )
    consequence_changed = _validate_component_transition(
        errors,
        previous["consequence_envelope"],
        current["consequence_envelope"],
        "$.consequence_envelope",
    )
    if world_changed and not consequence_changed:
        _append_error(
            errors,
            "$.consequence_envelope: changed World requires a newly scoped consequence revision",
        )
    if errors:
        raise ContractError(errors)
