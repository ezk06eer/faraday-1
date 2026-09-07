"""Workspace BC standalone factory — YAGNI.

Demuestra cómo dejar de ser monolito: este factory solo registra workspace blueprints
y usa faraday/domain/workspace + faraday/repo/workspace_repo + faraday/services.
No importa vuln/host/agent -> desacoplado grafo.

Uso:
    from faraday.bounded_contexts.workspace.app import create_workspace_app
    app = create_workspace_app(testing=True)
"""
def create_workspace_app(db_connection_string=None, testing=None):
    """Crea Flask app solo con workspace BC (para tests y futuro microservicio)."""
    from flask import Flask

    app = Flask(__name__, static_folder=None)
    app.config['APPLICATION_PREFIX'] = '/_api' if not testing else ''
    app.config['SQLALCHEMY_DATABASE_URI'] = db_connection_string or "sqlite:///:memory:"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    if testing:
        app.config['TESTING'] = True

    from faraday.server.models import db
    db.init_app(app)

    from faraday.server.api.modules.workspaces import workspace_api
    app.register_blueprint(workspace_api, url_prefix=app.config['APPLICATION_PREFIX'])

    return app


# Re-export para compat
__all__ = ["create_workspace_app"]
