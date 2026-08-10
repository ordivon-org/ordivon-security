"""Ordivon Security public package."""

from .api import (
    AdversarialWindowsRange,
    ContestResult,
    ContestRunner,
    EvaluationResult,
    EvaluationRunner,
    EvaluationSpec,
    RangeAuthority,
    RangeEvent,
    RangeSession,
    RangeSessionSpec,
    SacrificialWindowsRangeConfig,
    ScenarioManifest,
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
)
from .surface import security_surface_manifest

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
    "SacrificialWindowsRangeConfig",
    "ScenarioManifest",
    "WindowsKvmMachineConfig",
    "WindowsKvmMachineProvider",
    "security_surface_manifest",
]
__version__ = "0.8.0"
