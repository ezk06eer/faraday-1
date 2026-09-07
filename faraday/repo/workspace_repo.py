"""
WorkspaceRepository — extracted from faraday/server/api/base.py:get_workspace (E2-A4)

Import-safe: flask/sqlalchemy deferred.
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
