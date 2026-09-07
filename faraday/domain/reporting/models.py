"""YAGNI shim — re-export reporting from faraday.server.models."""
from faraday.server.models import (  # noqa: F401
    ExecutiveReport, Analytics, WorkspaceSummaryReport, WorkspaceSummaryReportRun,
)
__all__ = ["ExecutiveReport", "Analytics", "WorkspaceSummaryReport", "WorkspaceSummaryReportRun"]
