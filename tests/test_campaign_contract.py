from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ordivon_security_contracts.campaign import (
    CANONICALIZATION,
    ContractError,
    MAX_ERRORS,
    MAX_MANIFEST_BYTES,
    canonical_bytes,
    digest,
    envelope_digest,
    load_json,
    manifest_digest,
    validate_campaign,
    validate_transition,
)

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "fixtures/campaigns/valid/minimal-owned-range.json"
INVALID = ROOT / "fixtures/campaigns/invalid"


def load_valid() -> dict[str, Any]:
    return json.loads(VALID.read_text(encoding="utf-8"))


def pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    parts = pointer.lstrip("/").split("/")
    current = document
    for part in parts[:-1]:
        token = part.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current, parts[-1].replace("~1", "/").replace("~0", "~")


def apply_case(case_path: Path) -> tuple[dict[str, Any], str]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    fixture_root = (ROOT / "fixtures/campaigns").resolve()
    base_path = (case_path.parent / case["base"]).resolve()
    if not base_path.is_relative_to(fixture_root):
        raise AssertionError(f"fixture base escapes fixture root: {base_path}")
    base = json.loads(base_path.read_text(encoding="utf-8"))
    for mutation in case["mutations"]:
        parent, token = pointer_parent(base, mutation["path"])
        if mutation["op"] == "remove":
            if isinstance(parent, list):
                del parent[int(token)]
            else:
                del parent[token]
        elif mutation["op"] == "replace":
            if isinstance(parent, list):
                parent[int(token)] = mutation["value"]
            else:
                parent[token] = mutation["value"]
        elif mutation["op"] == "append-copy":
            parent[token].append(copy.deepcopy(parent[token][mutation["index"]]))
        elif mutation["op"] == "append":
            parent[token].append(copy.deepcopy(mutation["value"]))
        else:
            raise AssertionError(f"unsupported fixture mutation {mutation['op']}")
    # Keep identity errors from obscuring the intentional invalid condition.
    base.setdefault("identity", {})["manifest_digest"] = manifest_digest(base)
    return base, case["expected_error"]


def admit_revision(
    previous: dict[str, Any],
    *,
    change_capability: bool = False,
    change_consequence: bool = False,
) -> dict[str, Any]:
    current = copy.deepcopy(previous)
    current["campaign"]["revision"] += 1
    current["campaign"]["revision_id"] = (
        f"{current['campaign']['id']}:revision-{current['campaign']['revision']}"
    )
    current["authority"]["campaign_revision"] = current["campaign"]["revision"]
    current["authority"]["record_id"] = (
        f"{current['campaign']['id']}:admission-{current['campaign']['revision']}"
    )
    if change_capability:
        current["capability_envelope"]["revision"] += 1
        current["capability_envelope"]["time"]["step_limit"] += 1
        current["capability_envelope"]["digest"] = envelope_digest(
            current["capability_envelope"]
        )
        current["authority"]["capability_envelope_ref"] = {
            field: current["capability_envelope"][field]
            for field in ("id", "revision", "digest")
        }
    if change_consequence:
        consequence = current["consequence_envelope"]
        consequence["revision"] += 1
        consequence["data"].append("synthetic-fixture-data-v2")
        consequence["digest"] = envelope_digest(consequence)
        current["authority"]["consequence_envelope_ref"] = {
            field: consequence[field] for field in ("id", "revision", "digest")
        }
    current["identity"]["manifest_digest"] = manifest_digest(current)
    return current


def completed_manifest(
    classification: str,
    *,
    quality: str,
    status: str,
    breached: bool = False,
    reasons: list[str] | None = None,
    assessment_evidence: list[str] | None = None,
) -> dict[str, Any]:
    manifest = load_valid()
    manifest["campaign"]["state"] = "completed"
    manifest["outcome"] = {
        "classification": classification,
        "recorded_by": "urn:ordivon:security:actor:judge",
        "evidence_quality": quality,
        "objective_assessments": [
            {
                "objective_id": "urn:ordivon:security:objective:observe-owned-fixture",
                "status": status,
                "evidence_refs": (
                    ["evidence://judge/receipt"]
                    if assessment_evidence is None
                    else assessment_evidence
                ),
            }
        ],
        "evidence_refs": ["evidence://judge/receipt"],
        "containment_breach": breached,
        "reason_codes": [] if reasons is None else reasons,
    }
    manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
    return manifest


class CampaignContractTests(unittest.TestCase):
    def test_schema_is_valid_json_and_names_every_required_contract(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/campaign-manifest.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
        )
        for name in (
            "campaign",
            "world",
            "authority",
            "actor",
            "objective",
            "stopCondition",
            "capabilityEnvelope",
            "consequenceEnvelope",
            "outcome",
            "typedRef",
            "provenance",
            "envelopeRef",
        ):
            self.assertIn(name, schema["$defs"])

    def test_valid_fixture(self) -> None:
        validate_campaign(load_valid())

    def test_all_invalid_fixture_cases_fail_for_declared_reason(self) -> None:
        cases = sorted(INVALID.glob("*.case.json"))
        self.assertGreaterEqual(len(cases), 8)
        for path in cases:
            with self.subTest(path=path.name):
                manifest, expected = apply_case(path)
                with self.assertRaises(ContractError) as raised:
                    validate_campaign(manifest)
                self.assertIn(expected, "\n".join(raised.exception.errors))

    def test_canonicalization_sorts_keys_but_preserves_unicode_scalars(self) -> None:
        decomposed = {"z": "e\u0301", "a": [2, 1]}
        composed = {"a": [2, 1], "z": "\u00e9"}
        self.assertNotEqual(canonical_bytes(decomposed), canonical_bytes(composed))
        self.assertEqual(b'{"a":[2,1],"z":"e\xcc\x81"}', canonical_bytes(decomposed))

    def test_canonicalization_known_vector(self) -> None:
        value = {"unicode": "\u00e9", "control": "\n", "integer": 42}
        expected = b'{"control":"\\n","integer":42,"unicode":"\xc3\xa9"}'
        self.assertEqual(expected, canonical_bytes(value))
        self.assertEqual(
            "sha256:ba0405e94b579bde8478a31fe85f77737b6a7e2ebd0d0c82cab53263ec08dabe",
            digest(value),
        )

    def test_float_is_rejected_from_canonical_contract(self) -> None:
        with self.assertRaises(ContractError):
            canonical_bytes({"budget": 0.5})

    def test_surrogates_cycles_depth_and_wide_integers_are_rejected(self) -> None:
        cyclic: list[Any] = []
        cyclic.append(cyclic)
        values = [
            {"text": "\ud800"},
            {"integer": 9_223_372_036_854_775_808},
            cyclic,
        ]
        for value in values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ContractError):
                    canonical_bytes(value)

    def test_loader_bounds_and_rejects_ambiguous_json(self) -> None:
        cases = {
            "duplicate.json": '{"x":1,"x":2}',
            "float.json": '{"x":1.0}',
            "constant.json": '{"x":NaN}',
            "wide-int.json": '{"x":9223372036854775808}',
            "surrogate.json": '{"x":"\\ud800"}',
            "deep.json": '{"x":' * 70 + "0" + "}" * 70,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in cases.items():
                with self.subTest(name=name):
                    path = root / name
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(ContractError):
                        load_json(path)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
            with self.assertRaisesRegex(ContractError, "input limit"):
                load_json(oversized)

    def test_invalid_fixture_base_cannot_traverse_outside_fixture_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / "escape.case.json"
            case.write_text(
                json.dumps(
                    {
                        "base": "../../outside.json",
                        "mutations": [],
                        "expected_error": "unused",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "escapes fixture root"):
                apply_case(case)

    def test_schema_rejects_oversized_collections_before_semantics(self) -> None:
        manifest = load_valid()
        manifest["actors"] = [copy.deepcopy(manifest["actors"][0]) for _ in range(65)]
        with self.assertRaisesRegex(ContractError, "at most 64"):
            validate_campaign(manifest)

    def test_error_reporting_is_bounded(self) -> None:
        error = ContractError([f"error-{index}" for index in range(MAX_ERRORS + 20)])
        self.assertEqual(MAX_ERRORS, len(error.errors))
        self.assertIn("validation stopped", error.errors[-1])

    def test_capability_only_revision_preserves_exact_consequence(self) -> None:
        previous = load_valid()
        current = admit_revision(previous, change_capability=True)
        validate_transition(previous, current)
        self.assertEqual(
            previous["consequence_envelope"], current["consequence_envelope"]
        )

    def test_consequence_change_requires_new_campaign_admission(self) -> None:
        previous = load_valid()
        current = admit_revision(previous, change_consequence=True)
        validate_transition(previous, current)
        stale = copy.deepcopy(current)
        stale["campaign"] = copy.deepcopy(previous["campaign"])
        stale["authority"]["campaign_revision"] = previous["campaign"]["revision"]
        stale["authority"]["record_id"] = previous["authority"]["record_id"]
        stale["identity"]["manifest_digest"] = manifest_digest(stale)
        with self.assertRaisesRegex(ContractError, "advance exactly one revision"):
            validate_transition(previous, stale)

    def test_revision_only_envelope_bumps_are_rejected(self) -> None:
        previous = load_valid()
        for envelope_name, authority_ref in (
            ("capability_envelope", "capability_envelope_ref"),
            ("consequence_envelope", "consequence_envelope_ref"),
        ):
            with self.subTest(envelope=envelope_name):
                current = admit_revision(previous)
                envelope = current[envelope_name]
                envelope["revision"] += 1
                envelope["digest"] = envelope_digest(envelope)
                current["authority"][authority_ref] = {
                    field: envelope[field] for field in ("id", "revision", "digest")
                }
                current["identity"]["manifest_digest"] = manifest_digest(current)
                with self.assertRaisesRegex(
                    ContractError, "unchanged substance must retain revision and digest"
                ):
                    validate_transition(previous, current)

    def test_changed_capability_cannot_reuse_revision(self) -> None:
        previous = load_valid()
        current = admit_revision(previous)
        capability = current["capability_envelope"]
        capability["time"]["step_limit"] += 1
        capability["digest"] = envelope_digest(capability)
        current["authority"]["capability_envelope_ref"] = {
            field: capability[field] for field in ("id", "revision", "digest")
        }
        current["identity"]["manifest_digest"] = manifest_digest(current)
        with self.assertRaisesRegex(
            ContractError, "changed substance must advance exactly one revision"
        ):
            validate_transition(previous, current)

    def test_world_change_requires_world_and_consequence_revisions(self) -> None:
        previous = load_valid()
        current = admit_revision(previous)
        world = current["world"]
        world["revision"] += 1
        world["revision_id"] = f"{world['id']}:revision-{world['revision']}"
        world["link_ref"]["revision"] = "fixture-2"
        current["authority"]["world_revision_id"] = world["revision_id"]
        consequence = current["consequence_envelope"]
        consequence["revision"] += 1
        consequence["world_revision_id"] = world["revision_id"]
        consequence["digest"] = envelope_digest(consequence)
        current["authority"]["consequence_envelope_ref"] = {
            field: consequence[field] for field in ("id", "revision", "digest")
        }
        current["identity"]["manifest_digest"] = manifest_digest(current)
        validate_transition(previous, current)

    def test_transition_cannot_backdate_or_change_authority(self) -> None:
        previous = load_valid()
        current = admit_revision(previous)
        current["authority"]["admitted_at"] = "2026-07-27T23:59:59Z"
        current["identity"]["manifest_digest"] = manifest_digest(current)
        with self.assertRaisesRegex(ContractError, "cannot predate"):
            validate_transition(previous, current)

        current = admit_revision(previous)
        current["authority"]["authority_id"] = (
            "urn:ordivon:security:authority:different-owner"
        )
        current["consequence_envelope"]["targets"][0]["authority_id"] = current[
            "authority"
        ]["authority_id"]
        current["consequence_envelope"]["revision"] += 1
        current["consequence_envelope"]["digest"] = envelope_digest(
            current["consequence_envelope"]
        )
        current["authority"]["consequence_envelope_ref"] = {
            field: current["consequence_envelope"][field]
            for field in ("id", "revision", "digest")
        }
        current["identity"]["manifest_digest"] = manifest_digest(current)
        with self.assertRaisesRegex(ContractError, "preserve admission authority"):
            validate_transition(previous, current)

    def test_capability_and_consequence_can_change_only_as_explicit_revisions(
        self,
    ) -> None:
        previous = load_valid()
        current = admit_revision(
            previous, change_capability=True, change_consequence=True
        )
        validate_transition(previous, current)

    def test_every_outcome_class_has_a_consistent_executable_shape(self) -> None:
        cases = {
            "success": ("conclusive", "achieved", False, []),
            "partial_progress": ("conclusive", "partially_achieved", False, []),
            "defense": ("conclusive", "prevented", False, []),
            "escape": ("conclusive", "unknown", True, ["boundary-crossing-receipt"]),
            "observer_loss": (
                "inconclusive",
                "unknown",
                False,
                ["observer-stream-ended"],
            ),
            "invalid_run": ("invalid", "unknown", False, ["baseline-mismatch"]),
            "inconclusive_evidence": (
                "inconclusive",
                "unknown",
                False,
                ["receipt-missing"],
            ),
        }
        for classification, (quality, status, breached, reasons) in cases.items():
            with self.subTest(classification=classification):
                validate_campaign(
                    completed_manifest(
                        classification,
                        quality=quality,
                        status=status,
                        breached=breached,
                        reasons=reasons,
                    )
                )

    def test_outcome_claims_require_matching_evidence_semantics(self) -> None:
        invalid = [
            (
                completed_manifest("defense", quality="conclusive", status="achieved"),
                "every Red objective",
            ),
            (
                completed_manifest(
                    "observer_loss",
                    quality="conclusive",
                    status="unknown",
                    reasons=["observer-stream-ended"],
                ),
                "must be 'inconclusive'",
            ),
            (
                completed_manifest(
                    "escape",
                    quality="conclusive",
                    status="unknown",
                    breached=True,
                ),
                "must explain this classification",
            ),
            (
                completed_manifest(
                    "success",
                    quality="conclusive",
                    status="achieved",
                    assessment_evidence=[],
                ),
                "non-unknown assessments require evidence",
            ),
        ]
        for manifest, expected in invalid:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ContractError, expected):
                    validate_campaign(manifest)

    def test_authority_objective_and_capability_subject_planes_are_enforced(
        self,
    ) -> None:
        mutations = [
            (
                "/authority/judge_actor_id",
                "urn:ordivon:security:actor:lifecycle",
                "must reference role 'judge'",
            ),
            (
                "/objectives/0/actor_id",
                "urn:ordivon:security:actor:judge",
                "cannot be assigned",
            ),
            (
                "/capability_envelope/subject_actor_id",
                "urn:ordivon:security:actor:observer",
                "evaluated experiment actor",
            ),
        ]
        for pointer, value, expected in mutations:
            with self.subTest(pointer=pointer):
                manifest = load_valid()
                parent, token = pointer_parent(manifest, pointer)
                parent[token] = value
                if pointer.startswith("/capability_envelope"):
                    manifest["capability_envelope"]["digest"] = envelope_digest(
                        manifest["capability_envelope"]
                    )
                    manifest["authority"]["capability_envelope_ref"]["digest"] = (
                        manifest["capability_envelope"]["digest"]
                    )
                manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
                with self.assertRaisesRegex(ContractError, expected):
                    validate_campaign(manifest)

    def test_stop_condition_parameters_bind_to_capability_budgets(self) -> None:
        manifest = load_valid()
        manifest["stop_conditions"].append(
            {
                "id": "urn:ordivon:security:stop:budget",
                "kind": "budget_exhausted",
                "action": "stop",
                "description": "Stop at the admitted range budget.",
                "resource": "range_credits",
                "limit": 1,
            }
        )
        manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
        validate_campaign(manifest)
        manifest["stop_conditions"][-1]["limit"] = 2
        manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
        with self.assertRaisesRegex(
            ContractError, "equal the admitted resource budget"
        ):
            validate_campaign(manifest)

    def test_invalid_calendar_timestamp_is_rejected(self) -> None:
        manifest = load_valid()
        manifest["authority"]["admitted_at"] = "2026-02-30T00:00:00Z"
        manifest["identity"]["manifest_digest"] = manifest_digest(manifest)
        with self.assertRaisesRegex(ContractError, "real UTC timestamp"):
            validate_campaign(manifest)

    def test_cli_is_ci_friendly(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/validate_campaign.py", str(VALID), "--digest"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            load_valid()["identity"]["manifest_digest"], result.stdout.strip()
        )
        conflict = subprocess.run(
            [
                sys.executable,
                "scripts/validate_campaign.py",
                str(VALID),
                "--digest",
                "--canonical",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, conflict.returncode)

    def test_canonicalization_label_is_stable(self) -> None:
        self.assertEqual("ordivon-canonical-json-v0", CANONICALIZATION)


if __name__ == "__main__":
    unittest.main()
