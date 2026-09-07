"""Domain workspace — Workspace, Scope y WorkspacePermission reales (shard desde faraday/server/models.py).

Workspace es el hub del grafo (in-degree 71) y load-bearing. Copia exacta de
faraday/server/models.py:2446-2713. Todas las relaciones usan string references
('Host', 'Service', 'VulnerabilityGeneric', 'Command', 'User', 'Agent',
'Pipeline', 'WorkspacePermission', 'Scope', 'ExecutiveReport') — nunca
referencias directas a clases.

Sigue el patrón de faraday/domain/notification/models.py para el ciclo
domain<->server: si este módulo se importa ANTES que faraday.server.models, la
importación de `db` dispara la carga completa de server.models, cuyo shim cae en
el fallback ImportError y define las clases localmente; al retomar este módulo
las tablas ya existen en el MetaData, así que se detecta y se re-exportan esas
clases (identidad preservada en ambos órdenes, sin doble definición).

DatabaseMetadata, SeveritiesHistogram y VulnerabilityHitCount siguen en
faraday/server/models.py y se re-exportan aquí para mantener contracts.md.
"""
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import backref, query_expression, relationship

from faraday.domain.base import Metadata
from faraday.server.fields import JSONType

try:
    from faraday.server.models import (  # type: ignore
        BlankColumn,
        DatabaseMetadata,
        NonBlankColumn,
        SeveritiesHistogram,
        VulnerabilityHitCount,
        _make_generic_count_property,
        _return_last_30_days,
        association_workspace_and_users_table,
        db,
        executive_report_workspace_table,
        set_children_objects,
    )
except ImportError:  # fallback para py_compile / uso aislado sin app
    from datetime import date as _date, timedelta as _timedelta
    from functools import partial as _partial

    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import Table as _Table, func as _func, select as _select, text as _text
    from sqlalchemy.orm import column_property as _column_property

    db = SQLAlchemy()  # type: ignore
    BlankColumn = _partial(Column, nullable=False, info={'allow_blank': True}, default='')
    NonBlankColumn = _partial(Column, nullable=False, info={'allow_blank': False})
    DatabaseMetadata = None  # type: ignore
    SeveritiesHistogram = None  # type: ignore
    VulnerabilityHitCount = None  # type: ignore

    def _make_generic_count_property(parent_table, children_table, where=None, use_column_property=True):
        children_id_field = f'{children_table}.id'
        parent_id_field = f'{parent_table}.id'
        children_rel_field = f'{children_table}.{parent_table}_id'
        query = (
            _select(_func.count(_text(children_id_field)))
            .select_from(_text(children_table))
            .where(_text(f'{children_rel_field} = {parent_id_field}'))
        )
        if where is not None:
            query = query.where(where)
        query = query.scalar_subquery()
        if use_column_property:
            return _column_property(query, deferred=True)
        return query

    def _return_last_30_days() -> list:
        today = _date.today()
        last_30_days = [today - _timedelta(days=i) for i in range(30)]
        return [day.isoformat() for day in last_30_days]

    association_workspace_and_users_table = _Table(
        'workspace_permission_association',
        db.Model.metadata,
        Column('workspace_id', Integer, ForeignKey('workspace.id', ondelete='CASCADE')),
        Column('user_id', Integer, ForeignKey('faraday_user.id')),
    )

    executive_report_workspace_table = _Table(
        'executive_report_workspace_table',
        db.Model.metadata,
        Column('workspace_id', Integer, ForeignKey('workspace.id', ondelete='CASCADE')),
        Column('executive_report_id', Integer, ForeignKey('executive_report.id', ondelete='CASCADE')),
    )

    set_children_objects = None  # type: ignore


if 'workspace' in db.metadata.tables:
    # Ciclo domain-first: server.models ya definió las clases via fallback.
    from faraday.server.models import (  # type: ignore  # noqa: F401
        Scope,
        Workspace,
        WorkspacePermission,
    )
else:
    class Workspace(Metadata):
        __tablename__ = 'workspace'

        NAME = "name"
        CVE = "cve"
        GROUP_BY = [NAME, CVE]

        LEVENSHTEIN = "levenshtein"
        SENTENCE_TRANSFORMER = "sentence_transformer"
        GROUP_ALGORITHM = [LEVENSHTEIN, SENTENCE_TRANSFORMER]

        id = Column(Integer, primary_key=True)
        customer = BlankColumn(String(250))  # TBI
        description = BlankColumn(Text)
        active = Column(Boolean(), nullable=False, default=True)  # TBI
        readonly = Column(Boolean(), nullable=False, default=False)  # TBI
        end_date = Column(DateTime(), nullable=True)
        name = NonBlankColumn(String(250), unique=True, nullable=False)
        public = Column(Boolean(), nullable=False, default=False)  # TBI
        start_date = Column(DateTime(), nullable=True)
        risk_history_total = Column(JSONType(), nullable=False, default=[{"date": day, "risk": 0} for day in _return_last_30_days()])
        risk_history_avg = Column(JSONType(), nullable=False, default=[{"date": day, "risk": 0} for day in _return_last_30_days()])

        credential_count = _make_generic_count_property('workspace', 'credential')
        last_run_agent_date = query_expression()

        force_lowercase_assets = Column(Boolean, nullable=False, default=False)

        group_by = Column(Enum(*GROUP_BY, name='group_by'), nullable=True)
        group_algorithm = Column(Enum(*GROUP_ALGORITHM, name='group_algorithm'), nullable=True)
        group_threshold = Column(Integer, nullable=True)

        # Stats

        host_count = Column(Integer, nullable=False, default=0)
        host_confirmed_count = Column(Integer, nullable=False, default=0)
        host_notclosed_count = Column(Integer, nullable=False, default=0)
        host_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        open_service_count = Column(Integer, nullable=False, default=0)
        total_service_count = Column(Integer, nullable=False, default=0)
        service_confirmed_count = Column(Integer, nullable=False, default=0)
        service_notclosed_count = Column(Integer, nullable=False, default=0)
        service_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)

        # Total by vuln type

        vulnerability_web_count = Column(Integer, nullable=False, default=0)
        vulnerability_code_count = Column(Integer, nullable=False, default=0)
        vulnerability_standard_count = Column(Integer, nullable=False, default=0)

        # Total by vuln status

        vulnerability_open_count = Column(Integer, nullable=False, default=0)
        vulnerability_re_opened_count = Column(Integer, nullable=False, default=0)
        vulnerability_risk_accepted_count = Column(Integer, nullable=False, default=0)
        vulnerability_closed_count = Column(Integer, nullable=False, default=0)

        # Total by dashboard filters

        vulnerability_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_total_count = Column(Integer, nullable=False, default=0)

        # Total by severity

        vulnerability_high_count = Column(Integer, nullable=False, default=0)
        vulnerability_critical_count = Column(Integer, nullable=False, default=0)
        vulnerability_medium_count = Column(Integer, nullable=False, default=0)
        vulnerability_low_count = Column(Integer, nullable=False, default=0)
        vulnerability_informational_count = Column(Integer, nullable=False, default=0)
        vulnerability_unclassified_count = Column(Integer, nullable=False, default=0)

        # Confirmed by vuln type

        vulnerability_web_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_code_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_standard_confirmed_count = Column(Integer, nullable=False, default=0)

        # Confirmed by status

        vulnerability_open_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_re_opened_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_risk_accepted_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_closed_confirmed_count = Column(Integer, nullable=False, default=0)

        # Confirmed by severity

        vulnerability_high_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_critical_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_medium_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_low_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_informational_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_unclassified_confirmed_count = Column(Integer, nullable=False, default=0)

        # Not closed by vuln type

        vulnerability_web_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_code_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_standard_notclosed_count = Column(Integer, nullable=False, default=0)

        # Not closed by severity

        vulnerability_high_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_critical_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_medium_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_low_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_informational_notclosed_count = Column(Integer, nullable=False, default=0)
        vulnerability_unclassified_notclosed_count = Column(Integer, nullable=False, default=0)

        # Confirmed and not closed by vuln type:

        vulnerability_web_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_code_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_standard_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)

        # Confirmed and not closed by severity:

        vulnerability_high_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_critical_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_medium_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_low_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_informational_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)
        vulnerability_unclassified_notclosed_confirmed_count = Column(Integer, nullable=False, default=0)

        importance = Column(Integer, default=0)

        reports = relationship(
            'ExecutiveReport',
            secondary=executive_report_workspace_table,
            back_populates='workspaces',
            cascade='delete'
        )

        allowed_users = relationship(
            'User',
            secondary=association_workspace_and_users_table,
            back_populates="workspaces"
        )

        @classmethod
        def query_with_count(cls, confirmed, active=True, readonly=None, workspace_name=None):
            """Delegates to WorkspaceRepository (repo real, YAGNI import-safe)."""
            try:
                from faraday.repo.workspace_repo import WorkspaceRepository  # pylint: disable=import-outside-toplevel
                return WorkspaceRepository.query_with_count(
                    confirmed, active=active, readonly=readonly, workspace_name=workspace_name
                )
            except ImportError:
                # import-safe fallback: minimal db.session query without text()
                q = db.session.query(cls)
                if active is not None:
                    q = q.filter(cls.active == active)
                if readonly is not None:
                    q = q.filter(cls.readonly == readonly)
                if workspace_name:
                    q = q.filter(cls.name == workspace_name)
                q = q.order_by(cls.name.asc())
                rows = []
                for ws in q.all():
                    rows.append({
                        'workspace_id': ws.id,
                        'workspace_name': ws.name,
                        'workspace_active': ws.active,
                        'workspace_readonly': ws.readonly,
                    })

                class _FallbackResult:
                    def __init__(self, _rows):
                        self._rows = _rows
                    def fetchone(self):
                        return self._rows[0] if self._rows else None
                    def fetchall(self):
                        return self._rows
                    def __iter__(self):
                        return iter(self._rows)
                    def mappings(self):
                        return self
                return _FallbackResult(rows)

        def set_scope(self, new_scope):
            # Delegates to domain service (ponytail YAGNI, keeps contract)
            try:
                from faraday.domain.workspace.service import set_workspace_scope  # pylint: disable=import-outside-toplevel

                return set_workspace_scope(self, new_scope)
            except ImportError:
                return set_children_objects(self, new_scope,
                                            parent_field='scope',
                                            child_field='name',
                                            workspaced=False)

        def activate(self):
            try:
                from faraday.domain.workspace.service import activate_workspace  # pylint: disable=import-outside-toplevel

                return activate_workspace(self)
            except ImportError:
                if not self.active:
                    self.active = True
                    return True
                return False

        def deactivate(self):
            try:
                from faraday.domain.workspace.service import deactivate_workspace  # pylint: disable=import-outside-toplevel

                return deactivate_workspace(self)
            except ImportError:
                if self.active is not False:
                    self.active = False
                    return True
                return False

        def change_readonly(self):
            try:
                from faraday.domain.workspace.service import toggle_readonly  # pylint: disable=import-outside-toplevel

                return toggle_readonly(self)
            except ImportError:
                self.readonly = not self.readonly

    class Scope(Metadata):
        __tablename__ = 'scope'
        id = Column(Integer, primary_key=True)
        name = NonBlankColumn(Text)

        workspace_id = Column(
            Integer,
            ForeignKey('workspace.id', ondelete='CASCADE'),
            index=True,
            nullable=False
        )

        workspace = relationship(
            'Workspace',
            backref=backref('scope', cascade="all, delete-orphan"),
            foreign_keys=[workspace_id],
        )

        __table_args__ = (
            UniqueConstraint('name', 'workspace_id', name='uix_scope_name_workspace'),
        )

        @property
        def parent(self):
            return

    class WorkspacePermission(db.Model):
        __tablename__ = "workspace_permission_association"
        __table_args__ = {'extend_existing': True}
        id = Column(Integer, primary_key=True)
        workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), nullable=False)
        workspace = relationship('Workspace')

        user_id = Column(Integer, ForeignKey('faraday_user.id'), nullable=False)
        user = relationship('User', foreign_keys=[user_id])

        @property
        def parent(self):
            return


__all__ = [
    "DatabaseMetadata",
    "Scope",
    "SeveritiesHistogram",
    "VulnerabilityHitCount",
    "Workspace",
    "WorkspacePermission",
]
