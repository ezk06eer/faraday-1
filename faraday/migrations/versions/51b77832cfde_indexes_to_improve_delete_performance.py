"""Indexes to improve delete performance

Revision ID: 51b77832cfde
Revises: 8201db92d9e7
Create Date: 2026-01-09 10:20:37.443548+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '51b77832cfde'
down_revision = '8201db92d9e7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_cve_association_vulnerability_id', 'cve_association', ['vulnerability_id'], unique=False)
    op.create_index('ix_cwe_vulnerability_association_vulnerability_id', 'cwe_vulnerability_association', ['vulnerability_id'], unique=False)
    op.create_index('ix_owasp_vulnerability_association_vulnerability_id', 'owasp_vulnerability_association', ['vulnerability_id'], unique=False)
    op.create_index('ix_reference_vulnerability_association_vulnerability_id', 'reference_vulnerability_association', ['vulnerability_id'], unique=False)
    op.create_index('ix_vulnerabilities_related_association_vulnerability_id', 'vulnerabilities_related_association', ['vulnerability_id'], unique=False)
    op.create_index('ix_vulnerability_reference_vulnerability_id', 'vulnerability_reference', ['vulnerability_id'], unique=False)


def downgrade():
    op.drop_index('ix_vulnerability_reference_vulnerability_id', table_name='vulnerability_reference')
    op.drop_index('ix_vulnerabilities_related_association_vulnerability_id', table_name='vulnerabilities_related_association')
    op.drop_index('ix_reference_vulnerability_association_vulnerability_id', table_name='reference_vulnerability_association')
    op.drop_index('ix_owasp_vulnerability_association_vulnerability_id', table_name='owasp_vulnerability_association')
    op.drop_index('ix_cwe_vulnerability_association_vulnerability_id', table_name='cwe_vulnerability_association')
    op.drop_index('ix_cve_association_vulnerability_id', table_name='cve_association')
