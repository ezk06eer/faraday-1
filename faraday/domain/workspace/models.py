"""YAGNI shim - re-export desde faraday.server.models (futura extraccion)"""
from faraday.server.models import (  # noqa: F401
    DatabaseMetadata,
    Scope,
    SeveritiesHistogram,
    VulnerabilityHitCount,
    Workspace,
    WorkspacePermission,
)

__all__ = [
    "DatabaseMetadata",
    "Scope",
    "SeveritiesHistogram",
    "VulnerabilityHitCount",
    "Workspace",
    "WorkspacePermission",
]
