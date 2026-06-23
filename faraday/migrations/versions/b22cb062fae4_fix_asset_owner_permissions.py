"""fix asset owner permissions

Revision ID: b22cb062fae4
Revises: b3e7f1a2c904
Create Date: 2026-06-23 19:44:41.732691+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b22cb062fae4'
down_revision = 'b3e7f1a2c904'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE name = 'asset_owner';"
    )
    role_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'web_help_desk';"
    )
    whd_unit_id = result.scalar()

    if whd_unit_id:
        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'update' AND permissions_unit_id = {whd_unit_id};"  # nosec B608
        )
        unit_action_id = result.scalar()

        op.execute(
            f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {unit_action_id} AND role_id = {role_id};"  # nosec B608
        )


def downgrade():
    pass
