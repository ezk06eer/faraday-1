"""
Repository layer — isolates SQLAlchemy queries from services/controllers (E2).

Each repo is a thin wrapper around db.session with explicit methods,
no text() SQL injection, deterministic.
"""
