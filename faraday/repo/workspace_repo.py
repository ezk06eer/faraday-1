"""
WorkspaceRepository — extracted from faraday/server/api/base.py:get_workspace + faraday/server/models.py:2517 query_with_count (E2)

Import-safe: flask/sqlalchemy deferred. Mantiene contracts.md /v3/ws?confirmed&active.
"""
class WorkspaceRepository:
    @staticmethod
    def get_by_name(workspace_name: str):
        from http.client import FORBIDDEN as HTTP_FORBIDDEN, NOT_FOUND as HTTP_NOT_FOUND, UNAUTHORIZED as HTTP_UNAUTHORIZED
        from flask import abort
        from flask_login import current_user
        from sqlalchemy.orm.exc import NoResultFound
        from faraday.server.models import Workspace
        ws = None
        if not current_user.is_anonymous:
            try:
                ws = Workspace.query.filter_by(name=workspace_name).one()
                if not ws.active:
                    abort(HTTP_FORBIDDEN, f"Disabled workspace: {workspace_name}")
            except NoResultFound:
                abort(HTTP_NOT_FOUND, f"No such workspace: {workspace_name}")
        else:
            try:
                ws = Workspace.query.filter_by(name=workspace_name).one()
                if not ws.active:
                    abort(HTTP_UNAUTHORIZED)
            except NoResultFound:
                abort(HTTP_UNAUTHORIZED)
        return ws

    @staticmethod
    def query_with_count(confirmed=None, active=True, readonly=None, workspace_name=None):
        """Delega a Workspace.query_with_count (mantiene raw SQL, futuro: repo puro sin text())."""
        from faraday.server.models import Workspace
        return Workspace.query_with_count(confirmed, active=active, readonly=readonly, workspace_name=workspace_name)
