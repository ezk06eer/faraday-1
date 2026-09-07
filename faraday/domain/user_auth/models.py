"""YAGNI import-safe shim around the load-bearing ``faraday.server.models.User``.

A16 (Oleada2): NO mueve ni modifica ``User``/``UserToken`` en server; solo
reexporta de forma defensiva (reshard from other permisos incluidos) y añade
helpers puros.
"""

DOMAIN_USER_AVAILABLE = False

try:  # pragma: no cover - defensivo ante imports circulares
    from faraday.server.models import (  # noqa: F401
        Role, UserToken, User, UserAvatar, MethodologyTemplate, Methodology,
        PlannerProject, ProjectTask, License,
        PermissionsGroup, PermissionsUnit, PermissionsUnitAction, RolePermission,
    )
    DOMAIN_USER_AVAILABLE = True
except Exception:  # noqa: BLE001
    Role = UserToken = User = UserAvatar = MethodologyTemplate = Methodology = None
    PlannerProject = ProjectTask = License = None
    PermissionsGroup = PermissionsUnit = PermissionsUnitAction = RolePermission = None

__all__ = [
    "Role", "UserToken", "User", "UserAvatar", "MethodologyTemplate",
    "Methodology", "PlannerProject", "ProjectTask", "License",
    "PermissionsGroup", "PermissionsUnit", "PermissionsUnitAction", "RolePermission",
    "DOMAIN_USER_AVAILABLE", "roles_for", "token_type_is",
]


def roles_for(user):
    """Devuelve la lista de nombres de rol de un usuario (helper puro)."""
    if user is None:
        return []
    return [getattr(r, "name", str(r)) for r in getattr(user, "roles", []) or []]


def token_type_is(authg, expected):
    """True si el ``type`` del token (dict claims o UserToken) == ``expected``."""
    if authg is None:
        return False
    if isinstance(authg, dict):
        return authg.get("type") == expected
    return getattr(authg, "type", None) == expected
