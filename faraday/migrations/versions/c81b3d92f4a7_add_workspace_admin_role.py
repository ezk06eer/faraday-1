"""add workspace_admin default role

Revision ID: c81b3d92f4a7
Revises: 5f70ccd6cfb9
Create Date: 2026-07-02 00:00:00.000000+00:00

"""
from alembic import op

from faraday.server.models import PermissionsUnitAction, User
from faraday.server.utils.permissions import (
    GROUP_ADMIN,
    GROUP_ALL,
    UNIT_ADMIN,
    UNIT_BASE,
    UNIT_USERS,
    UNIT_WORKSPACES,
)

# revision identifiers, used by Alembic.
revision = 'c81b3d92f4a7'
down_revision = '5f70ccd6cfb9'
branch_labels = None
depends_on = None

WORKSPACE_ADMIN_ROLE = User.WORKSPACE_ADMIN_ROLE
DESCRIPTION = (
    'Full control over assigned workspaces, including their creation and deletion; '
    'cannot manage users or instance settings.'
)

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION


def upgrade():
    op.execute(
        f"INSERT INTO faraday_role (name, weight, custom, description) "
        f"VALUES ('{WORKSPACE_ADMIN_ROLE}', 15, false, '{DESCRIPTION}')"
    )
    # Same default profile as the other roles plus CREATE/DELETE on workspaces.
    # Units and actions are resolved by name since their ids vary between environments.
    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) "
        f"SELECT pua.id, "
        f"(SELECT id FROM faraday_role WHERE name = '{WORKSPACE_ADMIN_ROLE}'), "
        f"CASE "
        f"WHEN pg.name = '{GROUP_ALL}' THEN true "
        f"WHEN pu.name = '{UNIT_WORKSPACES}' AND pua.action_type IN ('{CREATE}', '{READ}', '{UPDATE}', '{DELETE}') THEN true "
        f"WHEN pu.name IN ('{UNIT_ADMIN}', '{UNIT_USERS}') AND pua.action_type IN ('{READ}', '{UPDATE}') THEN true "
        f"WHEN pu.name = '{UNIT_BASE}' AND pua.action_type = '{READ}' THEN true "
        f"ELSE false "
        f"END "
        f"FROM permissions_unit_action pua "
        f"JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "
        f"JOIN permissions_group pg ON pu.permissions_group_id = pg.id "
        f"WHERE pg.name IN ('{GROUP_ADMIN}', '{GROUP_ALL}')"
    )


def downgrade():
    for table, column in (
        ('role_permission', 'role_id'),
        ('roles_users', 'role_id'),
        ('notification_allowed_roles', 'allowed_role_id'),
    ):
        op.execute(
            f"DELETE FROM {table} WHERE {column} = "  # nosec B608
            f"(SELECT id FROM faraday_role WHERE name = '{WORKSPACE_ADMIN_ROLE}')"
        )
    op.execute(f"DELETE FROM faraday_role WHERE name = '{WORKSPACE_ADMIN_ROLE}'")
