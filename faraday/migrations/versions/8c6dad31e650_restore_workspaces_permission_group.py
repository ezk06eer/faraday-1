"""restore workspaces permission group

Re-creates a dedicated 'workspaces' permissions_group (dropped by
45a831782601_delete_bulk_create_permission_unit) and moves UNIT_WORKSPACES
back into it, out of GROUP_ADMIN. This doesn't change any role_permission
value: admin and workspace_admin keep full CRUD, every role keeps its
current allowed/denied actions. What changes is visibility — since
GROUP_ADMIN is one of roles.EXCLUDED_GROUPS, workspaces permissions were
silently dropped from the role_permissions JSON used to view/clone/create
custom roles. Moving the unit to its own group (not excluded) makes them
show up there. READ already comes out allowed=true/can_edit=false for every
role (including newly created custom roles) because the CLIENT role's own
READ permission on this unit is already true, and
_get_basic_permissions()'s can_edit is derived as `not allowed` from it —
no code change needed for that to hold once the unit is un-excluded.

Revision ID: 8c6dad31e650
Revises: 2b45cf202f3f
Create Date: 2026-08-07 00:00:00.000000+00:00

"""
from alembic import op

from faraday.server.utils.permissions import GROUP_ADMIN, GROUP_WORKSPACES, UNIT_WORKSPACES

# revision identifiers, used by Alembic.
revision = '8c6dad31e650'
down_revision = '2b45cf202f3f'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        f"INSERT INTO permissions_group (name) VALUES ('{GROUP_WORKSPACES}')"  # nosec B608
    )
    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = "  # nosec B608
        f"(SELECT id FROM permissions_group WHERE name = '{GROUP_WORKSPACES}') "
        f"WHERE name = '{UNIT_WORKSPACES}'"
    )


def downgrade():
    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = "  # nosec B608
        f"(SELECT id FROM permissions_group WHERE name = '{GROUP_ADMIN}') "
        f"WHERE name = '{UNIT_WORKSPACES}'"
    )
    op.execute(
        f"DELETE FROM permissions_group WHERE name = '{GROUP_WORKSPACES}'"  # nosec B608
    )
