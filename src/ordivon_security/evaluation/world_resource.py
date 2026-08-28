"""Compatibility import path for historical World Resource consumers."""

from ordivon_security.world_boundary.resource import (
    WorldResourceIdentityConflict,
    WorldResourceInbox,
    WorldResourcePolicyRejected,
    WorldResourceRequestError,
    rejected_world_resource_response,
)

__all__ = [
    "WorldResourceIdentityConflict",
    "WorldResourceInbox",
    "WorldResourcePolicyRejected",
    "WorldResourceRequestError",
    "rejected_world_resource_response",
]
