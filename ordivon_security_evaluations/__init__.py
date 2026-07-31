"""Executable adversarial evaluations, separate from frozen lifecycle contracts."""

from .control_boundary import (
    ATTACK_TEMPLATES,
    BASELINE_IDS,
    GAME_IMPLEMENTATION_REVISION,
    GAME_PAIR_IDS,
    GAME_REPORT_SHA256,
    AdversarialMatrixError,
    architecture_dispositions,
    build_scenarios,
    evaluate,
    load_game_report,
    report_markdown,
)

__all__ = [
    "ATTACK_TEMPLATES",
    "BASELINE_IDS",
    "GAME_IMPLEMENTATION_REVISION",
    "GAME_PAIR_IDS",
    "GAME_REPORT_SHA256",
    "AdversarialMatrixError",
    "architecture_dispositions",
    "build_scenarios",
    "evaluate",
    "load_game_report",
    "report_markdown",
]
