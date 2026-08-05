"""Authorized software Evaluation Trial contracts and local analysis infrastructure."""

from .backend import (
    EvaluationArtifact,
    EvaluationExecution,
    EvaluationInstance,
    EvaluationRangeBackend,
    FixtureEvaluationBackend,
    GuardianRecord,
    ObserverRecord,
    ResidualClosureReceipt,
)
from .evidence import (
    EvaluationEvidenceBundle,
    EvaluationEvidenceChannel,
    EvaluationEvidenceRecorder,
    verify_evaluation_evidence,
    verify_evaluation_operational_evidence,
)
from .models import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationDisposition,
    EvaluationResult,
    EvaluationSpec,
    Finding,
    GuardianPolicy,
    ObservationPlan,
    SampleIdentity,
)
from .quarantine import harden_quarantine_tree
from .runner import EVALUATION_EVIDENCE_SCHEMA_REVISION, EvaluationRunner
from .static import (
    ArchiveInventoryAnalyzer,
    AuthenticodeReportAnalyzer,
    ClamAvAnalyzer,
    ClamAvReportAnalyzer,
    FileIdentityAnalyzer,
    ImportedReportAnalyzer,
    LocalStaticEvaluationBackend,
    StaticAnalyzer,
    StaticAnalyzerResult,
)
from .vault import SampleVault

__all__ = [
    "ArchiveInventoryAnalyzer",
    "AuthorityManifest",
    "AuthenticodeReportAnalyzer",
    "ClamAvAnalyzer",
    "ClamAvReportAnalyzer",
    "EVALUATION_EVIDENCE_SCHEMA_REVISION",
    "EnvironmentIdentity",
    "EvaluationArtifact",
    "EvaluationDisposition",
    "EvaluationEvidenceBundle",
    "EvaluationEvidenceChannel",
    "EvaluationEvidenceRecorder",
    "EvaluationExecution",
    "EvaluationInstance",
    "EvaluationRangeBackend",
    "EvaluationResult",
    "EvaluationRunner",
    "EvaluationSpec",
    "FileIdentityAnalyzer",
    "Finding",
    "FixtureEvaluationBackend",
    "GuardianPolicy",
    "GuardianRecord",
    "ImportedReportAnalyzer",
    "LocalStaticEvaluationBackend",
    "ObservationPlan",
    "ObserverRecord",
    "ResidualClosureReceipt",
    "SampleIdentity",
    "SampleVault",
    "StaticAnalyzer",
    "StaticAnalyzerResult",
    "harden_quarantine_tree",
    "verify_evaluation_evidence",
    "verify_evaluation_operational_evidence",
]
