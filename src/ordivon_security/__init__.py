"""Ordivon Security package navigation surface.

Domain contracts live in their owner modules. The package root exposes only current
navigation/preflight projections so importing ``ordivon_security`` does not flatten
constitution, profiles, integrations, and research apparatus into one apparent API tier.
"""

from .ordinary_capability import security_ordinary_capability_preflight
from .surface import security_ordinary_surface_manifest, security_surface_manifest

__all__ = [
    "security_ordinary_capability_preflight",
    "security_ordinary_surface_manifest",
    "security_surface_manifest",
]
__version__ = "0.8.0"
