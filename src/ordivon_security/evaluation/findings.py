from __future__ import annotations

from ordivon_security._canonical import canonical_digest

from .backend import ObserverRecord
from .models import EvaluationDisposition, Finding

_RULES: dict[str, tuple[str, str, float, str]] = {
    "behavior.unauthorized-persistence": (
        "unauthorized-persistence",
        "high",
        0.95,
        "Observed persistence behavior outside the declared software purpose.",
    ),
    "behavior.credential-access": (
        "credential-access",
        "critical",
        0.95,
        "Observed access to credential material.",
    ),
    "behavior.undeclared-network": (
        "undeclared-network-communication",
        "high",
        0.9,
        "Observed network communication outside the declared evaluation path.",
    ),
    "behavior.process-injection": (
        "process-injection",
        "high",
        0.85,
        "Observed process-injection behavior requiring explicit justification.",
    ),
    "behavior.security-control-tampering": (
        "security-control-tampering",
        "critical",
        0.95,
        "Observed an attempt to alter or suppress an evaluation control.",
    ),
    "behavior.destructive": (
        "destructive-behavior",
        "critical",
        0.95,
        "Observed destructive behavior affecting the evaluation environment.",
    ),
    "behavior.privilege-expansion": (
        "privilege-expansion",
        "high",
        0.9,
        "Observed an attempt to expand execution privilege.",
    ),
    "behavior.stability-failure": (
        "stability-failure",
        "medium",
        0.9,
        "Observed a reproducible stability or resource-management failure.",
    ),
}

_ENGINEERING_CLASSES = {"stability-failure"}


def derive_findings(
    observed: tuple[tuple[ObserverRecord, str], ...],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for record, evidence_ref in observed:
        rule = _RULES.get(record.event_type)
        if rule is None:
            continue
        behavior_class, severity, confidence, summary = rule
        digest = canonical_digest(
            {
                "behaviorClass": behavior_class,
                "evidenceRef": evidence_ref,
                "payload": record.payload,
            }
        )
        findings.append(
            Finding(
                finding_id=f"finding:{digest.removeprefix('sha256:')[:24]}",
                behavior_class=behavior_class,
                severity=severity,
                confidence=confidence,
                summary=summary,
                evidence_refs=(evidence_ref,),
                limitations=(
                    "P0 finding is deterministic rule output, not a final human attribution.",
                ),
            )
        )
    return tuple(findings)


def choose_disposition(
    *,
    findings: tuple[Finding, ...],
    terminal_reason: str,
    guardian_terminated: bool,
    valid_trial: bool,
) -> EvaluationDisposition:
    if not valid_trial:
        return EvaluationDisposition.INVALID_TRIAL
    if findings:
        if all(finding.behavior_class in _ENGINEERING_CLASSES for finding in findings):
            return EvaluationDisposition.ENGINEERING_SECURITY_DEFECT
        return EvaluationDisposition.HIGH_RISK_CAPABILITY
    if guardian_terminated:
        return EvaluationDisposition.SUSPICIOUS_INCONCLUSIVE
    if terminal_reason.endswith("completed"):
        return EvaluationDisposition.NO_ISSUE_OBSERVED
    return EvaluationDisposition.SUSPICIOUS_INCONCLUSIVE
