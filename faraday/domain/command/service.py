"""Command domain service — YAGNI extraction from Command/CommandObject.

Extrae helpers puros: is_report_source, tool normalization.
No rompe contracts.md POST ?command_id audit.
"""
def is_report_source(import_source: str) -> bool:
    return import_source == "report"

def normalize_tool(tool: str) -> str:
    return (tool or "").strip()[:250]
