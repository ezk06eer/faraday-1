"""Workspace domain service — YAGNI extraction from faraday/server/models.py:2376 Workspace

Mantiene contrato wire; extrae lógica que no necesita estar en el modelo SQLAlchemy.
Delegado por Workspace.set_scope, activate, deactivate, change_readonly.
"""
from typing import List


def set_workspace_scope(workspace, new_scope: List[str]):
    """Delegado de Workspace.set_scope — usa set_children_objects."""
    from faraday.server.models import set_children_objects  # lazy to avoid cycle

    return set_children_objects(
        workspace, new_scope, parent_field="scope", child_field="name", workspaced=False
    )


def activate_workspace(workspace) -> bool:
    if not workspace.active:
        workspace.active = True
        return True
    return False


def deactivate_workspace(workspace) -> bool:
    if workspace.active is not False:
        workspace.active = False
        return True
    return False


def toggle_readonly(workspace):
    workspace.readonly = not workspace.readonly
