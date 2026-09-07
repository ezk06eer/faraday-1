"""
WorkspaceRepository — repo/workspace count + get_by_name (E2/E3)

Import-safe, YAGNI sin text() aún (delegación por ahora, SQL moverá en próximo corte sin cortes).
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
        """Night: delegación directa, próximo corte moverá raw SQL de models.py:2517 aquí sin text()."""
        from faraday.server.models import Workspace
        return Workspace.query_with_count(confirmed, active=active, readonly=readonly, workspace_name=workspace_name)
