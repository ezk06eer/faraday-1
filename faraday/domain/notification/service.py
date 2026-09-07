"""Notification domain service — YAGNI pure helpers."""
def should_notify(event_type: str, enabled: bool) -> bool:
    return bool(enabled and event_type)
