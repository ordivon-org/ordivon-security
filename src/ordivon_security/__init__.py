"""Ordivon Security public package."""

from .contest import ContestResult, ScenarioManifest
from .contest.runner import ContestRunner
from .evaluation import EvaluationResult, EvaluationRunner, EvaluationSpec
from .ordinary_capability import security_ordinary_capability_preflight
from .providers import WindowsKvmMachineConfig, WindowsKvmMachineProvider
from .range import (
    AdversarialWindowsRange,
    RangeAuthority,
    RangeEvent,
    RangeSession,
    RangeSessionSpec,
    SacrificialWindowsRangeConfig,
)
from .research_corpus import ResearchCorpus
from .surface import security_ordinary_surface_manifest, security_surface_manifest

__all__ = [
    "AdversarialWindowsRange",
    "ContestResult",
    "ContestRunner",
    "EvaluationResult",
    "EvaluationRunner",
    "EvaluationSpec",
    "RangeAuthority",
    "RangeEvent",
    "RangeSession",
    "RangeSessionSpec",
    "ResearchCorpus",
    "security_ordinary_capability_preflight",
    "security_ordinary_surface_manifest",
    "SacrificialWindowsRangeConfig",
    "ScenarioManifest",
    "WindowsKvmMachineConfig",
    "WindowsKvmMachineProvider",
    "security_surface_manifest",
]
__version__ = "0.8.0"
