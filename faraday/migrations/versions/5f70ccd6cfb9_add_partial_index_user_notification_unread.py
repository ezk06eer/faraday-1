"""add partial index on user_notification for unread count

Revision ID: 5f70ccd6cfb9
Revises: a9b75b0ddc01
Create Date: 2026-04-15 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '5f70ccd6cfb9'
down_revision = 'a9b75b0ddc01'
branch_labels = None
depends_on = None


def upgrade():
    op.get_bind().execution_options(isolation_level="AUTOCOMMIT")
    op.execute(
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_notification_user_id_unread "
        "ON user_notification (user_id) WHERE read = false"
    )


def downgrade():
    op.get_bind().execution_options(isolation_level="AUTOCOMMIT")
    op.execute(
        "DROP INDEX CONCURRENTLY IF EXISTS ix_user_notification_user_id_unread"
    )
