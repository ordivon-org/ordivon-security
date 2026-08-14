from __future__ import annotations

from typing import Any

from ordivon_security._canonical import JsonObject, canonical_digest, validate_json


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _sha256(value: object, label: str) -> str:
    text = _text(value, label).lower()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    if len(text) != 64:
        raise ValueError(f"{label} must contain 64 SHA-256 hex characters")
    try:
        int(text, 16)
    except ValueError as exc:
        raise ValueError(f"{label} contains invalid SHA-256 hex") from exc
    return "sha256:" + text


def _snapshot_ref(
    provider: str,
    record_id: str,
    raw: JsonObject,
    *,
    locator: str | None = None,
    modified: str | None = None,
) -> JsonObject:
    result: JsonObject = {
        "provider": provider,
        "recordId": record_id,
        "snapshotDigest": canonical_digest(raw),
    }
    if locator is not None:
        result["locator"] = locator
    if modified is not None:
        result["providerModified"] = modified
    return result



def _select_nvd_cve(raw: JsonObject, record_id: str | None) -> dict[str, Any]:
    vulnerabilities = raw.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        candidate = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
        return _object(candidate, "NVD CVE")
    candidates = [item for item in vulnerabilities if isinstance(item, dict)]
    if record_id is not None:
        matches = [
            item for item in candidates
            if isinstance(item.get("cve"), dict) and item["cve"].get("id") == record_id
        ]
        if len(matches) != 1:
            raise ValueError(
                f"NVD snapshot does not contain exactly one requested CVE: {record_id}"
            )
        return _object(matches[0].get("cve"), "NVD CVE")
    if len(candidates) != 1:
        raise ValueError("NVD provider snapshot must contain exactly one CVE or specify record_id")
    return _object(candidates[0].get("cve"), "NVD CVE")


def _select_cisa_kev(raw: JsonObject, record_id: str | None) -> dict[str, Any]:
    vulnerabilities = raw.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return raw
    candidates = [item for item in vulnerabilities if isinstance(item, dict)]
    if record_id is None:
        if len(candidates) != 1:
            raise ValueError(
                "CISA KEV catalog snapshot requires record_id to select one exact vulnerability"
            )
        return candidates[0]
    matches = [item for item in candidates if item.get("cveID") == record_id]
    if len(matches) != 1:
        raise ValueError(
            f"CISA KEV snapshot does not contain exactly one requested CVE: {record_id}"
        )
    return matches[0]


def normalize_osv_vulnerability(raw: JsonObject) -> JsonObject:
    validate_json(raw)
    osv_id = _text(raw.get("id"), "OSV id")
    modified = _text(raw.get("modified"), "OSV modified")
    aliases = [str(value) for value in raw.get("aliases", []) if isinstance(value, str)]
    affected_summary: list[JsonObject] = []
    for item in raw.get("affected", []):
        if not isinstance(item, dict):
            continue
        package = item.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        ecosystem = package.get("ecosystem")
        if isinstance(name, str) and isinstance(ecosystem, str):
            affected_summary.append({"name": name, "ecosystem": ecosystem})
    return {
        "schemaVersion": 1,
        "recordKind": "vulnerability",
        "recordId": f"vuln:osv:{osv_id}",
        "subject": {
            "targetScope": "external-advisory-only",
            "revisions": [],
            "affectedPackages": affected_summary,
        },
        "sourceRefs": [
            _snapshot_ref(
                "osv",
                osv_id,
                raw,
                locator=f"osv:{osv_id}",
                modified=modified,
            )
        ],
        "claims": [
            {
                "claimId": "osv-record-published",
                "predicate": "provider-vulnerability-record-published",
                "value": True,
                "truthRole": "provider-claim",
                "assertedBy": "osv",
                "evidenceRefs": [],
            }
        ],
        "evidenceRefs": [],
        "metadata": {"aliases": aliases, "affectedPackages": affected_summary},
    }


def normalize_nvd_vulnerability(
    raw: JsonObject, *, record_id: str | None = None
) -> JsonObject:
    validate_json(raw)
    cve = _select_nvd_cve(raw, record_id)
    cve_id = _text(cve.get("id"), "NVD CVE id")
    modified = cve.get("lastModified")
    modified_text = modified if isinstance(modified, str) else None
    weaknesses: list[str] = []
    for group in cve.get("weaknesses", []):
        if not isinstance(group, dict):
            continue
        for description in group.get("description", []):
            if isinstance(description, dict) and isinstance(description.get("value"), str):
                weaknesses.append(str(description["value"]))
    return {
        "schemaVersion": 1,
        "recordKind": "vulnerability",
        "recordId": f"vuln:nvd:{cve_id}",
        "subject": {"targetScope": "external-advisory-only", "revisions": []},
        "sourceRefs": [
            _snapshot_ref(
                "nvd",
                cve_id,
                raw,
                locator=f"nvd:{cve_id}",
                modified=modified_text,
            )
        ],
        "claims": [
            {
                "claimId": "nvd-record-published",
                "predicate": "provider-vulnerability-record-published",
                "value": True,
                "truthRole": "provider-claim",
                "assertedBy": "nvd",
                "evidenceRefs": [],
            }
        ],
        "evidenceRefs": [],
        "metadata": {"cveId": cve_id, "weaknesses": sorted(set(weaknesses))},
    }


def normalize_cisa_kev_vulnerability(
    raw: JsonObject, *, record_id: str | None = None
) -> JsonObject:
    validate_json(raw)
    entry = _select_cisa_kev(raw, record_id)
    cve_id = _text(entry.get("cveID"), "CISA KEV cveID")
    date_added = _text(entry.get("dateAdded"), "CISA KEV dateAdded")
    vendor = entry.get("vendorProject")
    product = entry.get("product")
    return {
        "schemaVersion": 1,
        "recordKind": "vulnerability",
        "recordId": f"vuln:cisa-kev:{cve_id}",
        "subject": {"targetScope": "external-advisory-only", "revisions": []},
        "sourceRefs": [
            _snapshot_ref(
                "cisa-kev",
                cve_id,
                raw,
                locator=f"cisa-kev:{cve_id}",
                modified=date_added,
            )
        ],
        "claims": [
            {
                "claimId": "cisa-known-exploited",
                "predicate": "known-exploited-in-the-wild",
                "value": True,
                "truthRole": "provider-claim",
                "assertedBy": "cisa-kev",
                "evidenceRefs": [],
            }
        ],
        "evidenceRefs": [],
        "metadata": {
            "cveId": cve_id,
            "dateAdded": date_added,
            "vendorProject": vendor if isinstance(vendor, str) else None,
            "product": product if isinstance(product, str) else None,
        },
    }


def normalize_malwarebazaar_sample(raw: JsonObject) -> JsonObject:
    validate_json(raw)
    info = raw
    if isinstance(raw.get("data"), list) and len(raw["data"]) == 1:
        candidate = raw["data"][0]
        info = _object(candidate, "MalwareBazaar data[0]")
    sha256 = _sha256(info.get("sha256_hash"), "MalwareBazaar sha256_hash")
    byte_length = _integer(info.get("file_size"), "MalwareBazaar file_size")
    file_name = info.get("file_name")
    mime = info.get("file_type_mime")
    signature = info.get("signature")
    tags = [str(value) for value in info.get("tags", []) if isinstance(value, str)]
    claims: list[JsonObject] = [
        {
            "claimId": "malwarebazaar-cataloged",
            "predicate": "provider-malware-corpus-member",
            "value": True,
            "truthRole": "provider-claim",
            "assertedBy": "malwarebazaar",
            "evidenceRefs": [],
        }
    ]
    if isinstance(signature, str) and signature:
        claims.append(
            {
                "claimId": "malwarebazaar-signature",
                "predicate": "provider-family-signature",
                "value": signature,
                "truthRole": "provider-claim",
                "assertedBy": "malwarebazaar",
                "evidenceRefs": [],
            }
        )
    return {
        "schemaVersion": 1,
        "recordKind": "sample",
        "recordId": "sample:" + sha256.removeprefix("sha256:"),
        "sample": {
            "sha256": sha256,
            "byteLength": byte_length,
            "mediaType": mime if isinstance(mime, str) and mime else "application/octet-stream",
            "originalName": file_name if isinstance(file_name, str) else None,
            "artifactRole": "third-party-artifact",
            "materialization": "metadata-only",
            "executionAdmission": "denied-by-default",
        },
        "sourceRefs": [
            _snapshot_ref(
                "malwarebazaar",
                sha256,
                raw,
                locator="malwarebazaar:hash:" + sha256.removeprefix("sha256:"),
            )
        ],
        "claims": claims,
        "evidenceRefs": [],
        "metadata": {"tags": tags},
    }


def normalize_virustotal_sample(raw: JsonObject) -> JsonObject:
    validate_json(raw)
    data = _object(raw.get("data"), "VirusTotal data") if "data" in raw else raw
    attributes = _object(data.get("attributes"), "VirusTotal attributes")
    sha256 = _sha256(data.get("id") or attributes.get("sha256"), "VirusTotal sha256")
    size = _integer(attributes.get("size"), "VirusTotal size")
    names = attributes.get("names")
    original_name = None
    if isinstance(names, list):
        original_name = next((str(value) for value in names if isinstance(value, str)), None)
    type_description = attributes.get("type_description")
    stats = attributes.get("last_analysis_stats")
    claims: list[JsonObject] = [
        {
            "claimId": "virustotal-file-record",
            "predicate": "provider-file-record-present",
            "value": True,
            "truthRole": "provider-claim",
            "assertedBy": "virustotal",
            "evidenceRefs": [],
        }
    ]
    if isinstance(stats, dict):
        claims.append(
            {
                "claimId": "virustotal-analysis-stats",
                "predicate": "provider-analysis-stats",
                "value": dict(stats),
                "truthRole": "provider-claim",
                "assertedBy": "virustotal",
                "evidenceRefs": [],
            }
        )
    return {
        "schemaVersion": 1,
        "recordKind": "sample",
        "recordId": "sample:" + sha256.removeprefix("sha256:"),
        "sample": {
            "sha256": sha256,
            "byteLength": size,
            "mediaType": "application/octet-stream",
            "originalName": original_name,
            "artifactRole": "third-party-artifact",
            "materialization": "metadata-only",
            "executionAdmission": "denied-by-default",
        },
        "sourceRefs": [
            _snapshot_ref(
                "virustotal",
                sha256,
                raw,
                locator="virustotal:sha256:" + sha256.removeprefix("sha256:"),
            )
        ],
        "claims": claims,
        "evidenceRefs": [],
        "metadata": {
            "typeDescription": type_description if isinstance(type_description, str) else None
        },
    }


def normalize_provider_record(
    provider: str, raw: JsonObject, *, record_id: str | None = None
) -> JsonObject:
    normalized = provider.strip().lower()
    if normalized == "osv":
        return normalize_osv_vulnerability(raw)
    if normalized == "nvd":
        return normalize_nvd_vulnerability(raw, record_id=record_id)
    if normalized in {"cisa-kev", "kev"}:
        return normalize_cisa_kev_vulnerability(raw, record_id=record_id)
    if normalized in {"malwarebazaar", "malware-bazaar"}:
        return normalize_malwarebazaar_sample(raw)
    if normalized in {"virustotal", "virus-total"}:
        return normalize_virustotal_sample(raw)
    raise ValueError(f"Unsupported research corpus provider normalizer: {provider}")


__all__ = [
    "normalize_cisa_kev_vulnerability",
    "normalize_malwarebazaar_sample",
    "normalize_nvd_vulnerability",
    "normalize_osv_vulnerability",
    "normalize_provider_record",
    "normalize_virustotal_sample",
]
