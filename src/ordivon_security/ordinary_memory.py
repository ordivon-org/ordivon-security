from __future__ import annotations

import hashlib
import json
import re
import tempfile
from pathlib import Path
from ordivon_security._canonical import JsonObject, validate_json
from ordivon_security.research_corpus import ResearchCorpus
from ordivon_security.research_corpus_sources import normalize_provider_record

ROOT = Path(__file__).resolve().parents[2]
_SEED_PATHS = (
    "research/corpus/seed-ca2-vulnerability.json",
    "research/corpus/seed-eicar-sample.json",
    "research/corpus/seed-caseb-sample-postedge.json",
)
_OSV_OLD = "research/corpus/k1/controlled-osv-old.json"
_OSV_CURRENT = "research/corpus/k1/controlled-osv-current.json"


def _load(root: Path, relative: str) -> JsonObject:
    value = json.loads((root / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"ordinary Security source must be an object: {relative}")
    return value


def _source_digest(root: Path, relative: str) -> str:
    return "sha256:" + hashlib.sha256((root / relative).read_bytes()).hexdigest()


def _populate(corpus: ResearchCorpus, root: Path) -> None:
    for relative in _SEED_PATHS:
        corpus.register(_load(root, relative))
    corpus.register(normalize_provider_record("osv", _load(root, _OSV_OLD)))


_QUERY_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{3,}|[\u3400-\u9fff]+")


def _query_terms(needle: str) -> list[str]:
    seen: set[str] = set()
    terms: list[str] = []
    for match in _QUERY_TOKEN.finditer(needle):
        term = match.group(0).casefold()
        if term not in seen:
            seen.add(term)
            terms.append(term)
    return terms


def _candidate_projection(
    record: JsonObject, *, matched_terms: list[str] | None = None
) -> JsonObject:
    claims = record.get("claims", [])
    role_counts: dict[str, int] = {}
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            role = claim.get("truthRole")
            if isinstance(role, str):
                role_counts[role] = role_counts.get(role, 0) + 1
    result: JsonObject = {
        "recordId": str(record["recordId"]),
        "recordKind": str(record["recordKind"]),
        "claimRoleCounts": role_counts,
        "sourceRefCount": (
            len(record.get("sourceRefs", []))
            if isinstance(record.get("sourceRefs"), list)
            else 0
        ),
    }
    if matched_terms is not None:
        result["matchedTerms"] = matched_terms
        result["score"] = len(matched_terms)
    if record.get("recordKind") == "sample" and isinstance(record.get("sample"), dict):
        sample = record["sample"]
        result["sampleStanding"] = {
            "artifactRole": sample.get("artifactRole"),
            "materialization": sample.get("materialization"),
            "executionAdmission": sample.get("executionAdmission"),
        }
    validate_json(result)
    return result


def security_ordinary_research_query(needle: str, *, root: Path = ROOT) -> JsonObject:
    if not isinstance(needle, str) or not needle.strip():
        raise ValueError("ordinary Security research query must be a non-empty string")
    with tempfile.TemporaryDirectory(prefix="ordivon-security-ordinary-corpus-") as raw:
        corpus = ResearchCorpus(Path(raw) / "corpus")
        _populate(corpus, root)
        terms = _query_terms(needle.strip())
        ranked: list[tuple[int, str, JsonObject, list[str]]] = []
        for head in corpus.list_heads():
            record = corpus.load(head.record_id, record_kind=head.record_kind)
            searchable = json.dumps(record, ensure_ascii=False, sort_keys=True).casefold()
            matched = [term for term in terms if term in searchable]
            if matched:
                ranked.append((len(matched), head.record_id, record, matched))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        candidates = [
            _candidate_projection(record, matched_terms=matched)
            for _, _, record, matched in ranked[:8]
        ]
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ordinary-research-query",
            "truthRole": "derived-read-only-owner-memory-projection",
            "query": needle.strip(),
            "queryTerms": terms,
            "candidateCount": len(candidates),
            "candidates": candidates,
            "sourceBindings": [
                {"path": relative, "digest": _source_digest(root, relative)}
                for relative in (*_SEED_PATHS, _OSV_OLD)
            ],
            "boundaries": [
                "query candidates are bounded lexical matches over exact retained owner-memory records, not semantic-equivalence judgments or live provider discovery",
                "absence of a candidate does not establish semantic non-equivalence or absence in the external world",
                "catalog possession does not grant Sample execution authority",
            ],
        }
        validate_json(value)
        return value


def security_ordinary_research_inspect(record_id: str, *, root: Path = ROOT) -> JsonObject:
    if not isinstance(record_id, str) or not record_id.strip():
        raise ValueError("ordinary Security recordId must be a non-empty string")
    with tempfile.TemporaryDirectory(prefix="ordivon-security-ordinary-corpus-") as raw:
        corpus = ResearchCorpus(Path(raw) / "corpus")
        _populate(corpus, root)
        inspection = corpus.inspect(record_id.strip())
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ordinary-research-inspection",
            "truthRole": "derived-read-only-owner-memory-projection",
            "inspection": inspection,
            "sourceBindings": [
                {"path": relative, "digest": _source_digest(root, relative)}
                for relative in (*_SEED_PATHS, _OSV_OLD)
            ],
            "claims": {
                "executionAuthorityGranted": False,
                "liveProviderCurrentnessEvaluated": False,
                "corpusStorageCoordinateExposed": False,
            },
        }
        validate_json(value)
        return value


def security_ordinary_provider_currentness(*, root: Path = ROOT) -> JsonObject:
    with tempfile.TemporaryDirectory(prefix="ordivon-security-ordinary-corpus-") as raw:
        corpus = ResearchCorpus(Path(raw) / "corpus")
        _populate(corpus, root)
        current = normalize_provider_record("osv", _load(root, _OSV_CURRENT))
        comparison = corpus.compare_candidate(current)
        value: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ordinary-provider-currentness",
            "truthRole": "derived-read-only-owner-memory-projection",
            "comparison": comparison,
            "claims": {
                "mutationPerformed": False,
                "targetApplicabilityInferred": False,
                "executionAuthorityGranted": False,
            },
        }
        validate_json(value)
        return value


__all__ = [
    "security_ordinary_provider_currentness",
    "security_ordinary_research_inspect",
    "security_ordinary_research_query",
]
