"""Redis infra — YAGNI extraction from faraday/server/debouncer.py:21

Deterministic, no global state beyond singleton _redis_client.
Mantiene contrato: _redis_url_from_config lee faraday_server.celery_backend_url.
"""
import redis
from faraday.server.config import faraday_server

def _redis_url_from_config() -> str:
    raw = (getattr(faraday_server, "celery_backend_url", None) or "").strip()
    if not raw:
        return "redis://127.0.0.1:6379/0"
    if raw.startswith("redis://") or raw.startswith("rediss://"):
        return raw
    return f"redis://{raw}"

_redis_client = None

def get_redis_client() -> redis.Redis:
    global _redis_client  # pylint: disable=W0603
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(_redis_url_from_config(), decode_responses=True)
    return _redis_client
