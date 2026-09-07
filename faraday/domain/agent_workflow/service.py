"""Agent workflow domain service — YAGNI pure helpers."""
def is_agent_active(last_run, threshold_days: int = 7) -> bool:
    if not last_run:
        return False
    from datetime import datetime, timedelta
    return datetime.utcnow() - last_run < timedelta(days=threshold_days)

def normalize_agent_name(name: str) -> str:
    return (name or "").strip()[:250]
