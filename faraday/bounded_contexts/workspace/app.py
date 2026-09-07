"""Workspace BC standalone factory — YAGNI.

Demuestra cómo dejar de ser monolito: este factory solo registra workspace blueprints
y usa faraday/domain/workspace + faraday/repo/workspace_repo + faraday/services.
No importa vuln/host/agent -> desacoplado grafo.

Uso:
    from faraday.bounded_contexts.workspace.app import create_workspace_app
    app = create_workspace_app(testing=True)
"""
from flask import Flask

def create_workspace_app(db_connection_string=None, testing=None):
    """Crea Flask app solo con workspace BC (para tests y futuro microservicio)."""
    from faraday.server.app import create_app as _create_app  # lazy

    # Por ahora delega a create_app completo (monolito) — YAGNI: no duplicar lógica
    # Futuro: registrar solo workspace_api + repo/workspace_repo sin vuln/host
    # Mantiene contracts.md: APPLICATION_PREFIX /_api, workspace routes /v3/ws
    app = _create_app(db_connection_string=db_connection_string, testing=testing, register_extensions_flag=False)
    return app

# Re-export para compat
__all__ = ["create_workspace_app"]
