"""add workspace_admin default role

Revision ID: c81b3d92f4a7
Revises: 5f70ccd6cfb9
Create Date: 2026-07-02 00:00:00.000000+00:00

"""
from alembic import op

from faraday.server.models import User
from faraday.server.utils.permissions import UNIT_WORKSPACES

# revision identifiers, used by Alembic.
revision = 'c81b3d92f4a7'
down_revision = '5f70ccd6cfb9'
branch_labels = None
depends_on = None

WORKSPACE_ADMIN_ROLE = User.WORKSPACE_ADMIN_ROLE
PENTESTER_ROLE = User.PENTESTER_ROLE
DESCRIPTION = (
    'Full control over assigned workspaces, including their creation and deletion; '
    'cannot manage users or instance settings.'
)


def upgrade():
    op.execute(
        f"INSERT INTO faraday_role (name, weight, custom, description) "
        f"VALUES ('{WORKSPACE_ADMIN_ROLE}', 15, false, '{DESCRIPTION}')"
    )
    # workspace_admin mirrors the pentester role over every permission unit (so it has
    # full access to workspace contents: vulnerabilities, hosts, services, comments,
    # credentials, agents, reports, ...), and additionally gets full CRUD on
    # UNIT_WORKSPACES so it can create/delete/edit/activate/lock/group workspaces.
    # The generic per-assignee check (enforce_workspace_permission_check) keeps all of
    # this scoped to the workspaces where the user is an allowed_user. pentester already
    # withholds user management and instance settings, so those stay denied.
    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) "  # nosec B608
        f"SELECT pua.id, "  # nosec B608
        f"(SELECT id FROM faraday_role WHERE name = '{WORKSPACE_ADMIN_ROLE}'), "  # nosec B608
        f"CASE "  # nosec B608
        f"WHEN pu.name = '{UNIT_WORKSPACES}' THEN true "  # nosec B608
        f"ELSE COALESCE(pentester_rp.allowed, false) "  # nosec B608
        f"END "  # nosec B608
        f"FROM permissions_unit_action pua "  # nosec B608
        f"JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "  # nosec B608
        f"LEFT JOIN role_permission pentester_rp "  # nosec B608
        f"ON pentester_rp.unit_action_id = pua.id "  # nosec B608
        f"AND pentester_rp.role_id = (SELECT id FROM faraday_role WHERE name = '{PENTESTER_ROLE}')"  # nosec B608
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
