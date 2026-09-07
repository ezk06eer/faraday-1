"""Domain reporting — shard real (X1): ExecutiveReport, WorkspaceSummaryReport,
WorkspaceSummaryReportRun, MethodologyTemplate, Methodology, PlannerProject,
ProjectTask y License extraídas verbatim desde faraday/server/models.py.

Patrón: lazy `db` import como faraday/domain/base.py para evitar ciclo duro;
Metadata viene de faraday/domain/base.py (ya real).
Relaciones cross-shard usan string references ('Workspace', 'User', 'Tag',
'File', 'VulnerabilityGeneric') — la resolución es lazy por registry SQLAlchemy.
Las tablas de asociación del planner (project_task_user_association,
task_dependencies_association, vulnerabilities_related_association) se definen
aquí con guarda `db.metadata.tables.get(...)` para no duplicarlas si el ciclo
domain-first ya las registró vía fallback de server.models.

Ciclo domain<->server: si este módulo se importa ANTES que
faraday.server.models, la importación de `db` dispara la carga completa de
server.models, cuyo shim cae en el fallback ImportError y define las clases
localmente; al retomar este módulo las tablas ya existen en el MetaData, así
que se detecta y se re-exportan esas clases (identidad preservada en ambos
órdenes, sin doble definición).
"""
from functools import partial

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    and_,  # noqa: F401  (usado en primaryjoin string de ExecutiveReport.tags)
)
from sqlalchemy.orm import backref, relationship

try:
    from faraday.server.models import db  # type: ignore
except ImportError:  # fallback para py_compile / uso aislado sin app
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # type: ignore

try:
    from faraday.server.fields import JSONType
except ImportError:
    from sqlalchemy import JSON as JSONType  # type: ignore

from faraday.domain.base import Metadata

NonBlankColumn = partial(Column, nullable=False, info={'allow_blank': False})
BlankColumn = partial(Column, nullable=False, info={'allow_blank': True}, default='')


project_task_user_association = db.metadata.tables.get('project_task_user_association')
if project_task_user_association is None:
    project_task_user_association = db.Table(
        'project_task_user_association',
        db.Column('task_id', db.Integer(), db.ForeignKey('project_task.id')),
        db.Column('user_id', db.Integer(),
                  db.ForeignKey('faraday_user.id', ondelete='CASCADE')),
    )

task_dependencies_association = db.metadata.tables.get('task_dependencies_association')
if task_dependencies_association is None:
    task_dependencies_association = db.Table(
        'task_dependencies_association',
        db.Column('task_id', db.Integer(), db.ForeignKey('project_task.id')),
        db.Column('task_dependency_id', db.Integer(),
                  db.ForeignKey('project_task.id', ondelete='CASCADE')),
    )

vulnerabilities_related_association = db.metadata.tables.get('vulnerabilities_related_association')
if vulnerabilities_related_association is None:
    vulnerabilities_related_association = db.Table(
        'vulnerabilities_related_association',
        db.Column('task_id', db.Integer(),
                  db.ForeignKey('project_task.id'),
                  primary_key=True),
        db.Column('vulnerability_id', db.Integer(),
                  db.ForeignKey('vulnerability.id', ondelete='CASCADE'),
                  primary_key=True),
        Index('ix_vulnerabilities_related_association_vulnerability_id', 'vulnerability_id'),
    )


if 'executive_report' in db.metadata.tables:
    # Ciclo domain-first: server.models ya definió las clases via fallback.
    from faraday.server.models import (  # type: ignore  # noqa: F401
        ExecutiveReport, MethodologyTemplate, Methodology, PlannerProject,
        ProjectTask, License, WorkspaceSummaryReport, WorkspaceSummaryReportRun,
    )
else:
    class MethodologyTemplate(Metadata):
        # TODO: reset template_id in methodologies when deleting meth template
        __tablename__ = 'methodology_template'
        id = Column(Integer, primary_key=True)
        name = NonBlankColumn(Text)


    class Methodology(Metadata):
        # TODO: add unique constraint -> name, workspace
        __tablename__ = 'methodology'
        id = Column(Integer, primary_key=True)
        name = NonBlankColumn(Text)

        template = relationship(
            'MethodologyTemplate',
            backref=backref('methodologies')
        )
        template_id = Column(
            Integer,
            ForeignKey('methodology_template.id', ondelete="SET NULL"),
            index=True,
            nullable=True,
        )

        workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
        workspace = relationship(
            'Workspace',
            backref=backref('methodologies', cascade="all, delete-orphan"),
        )

        @property
        def parent(self):
            return


    class PlannerProject(Metadata):
        __tablename__ = 'planner_project'
        id = Column(Integer, primary_key=True)
        name = NonBlankColumn(Text)

        @property
        def parent(self):
            return

        @property
        def start_date(self):
            if self.tasks:
                if all(x.type == 'milestone' for x in self.tasks):
                    return None
                return min(x.start_date for x in self.tasks if x.start_date is not None)

        @property
        def end_date(self):
            if self.tasks:
                return max(x.end_date for x in self.tasks if x.end_date is not None)


    class ProjectTask(Metadata):

        TASK_STATUS_NEW = 'new'
        TASK_STATUS_REVIEW = 'review'
        TASK_STATUS_COMPLETED = 'completed'
        TASK_STATUS_IN_PROGRESS = 'in progress'

        STATUSES = [
            TASK_STATUS_NEW,
            TASK_STATUS_REVIEW,
            TASK_STATUS_COMPLETED,
            TASK_STATUS_IN_PROGRESS,
        ]

        NORMAL_TASK = 'task'
        MILESTONE = 'milestone'

        TASK_TYPES = [
            NORMAL_TASK,
            MILESTONE
        ]

        __tablename__ = 'project_task'
        id = Column(Integer, primary_key=True)

        name = Column(String, nullable=False, default='')
        description = Column(String, nullable=True)
        start_date = Column(DateTime, nullable=True)
        end_date = Column(DateTime, nullable=True)
        status = Column(Enum(*STATUSES, name='project_task_statuses'), nullable=True)
        type = Column(Enum(*TASK_TYPES, name='project_task_types'), nullable=False)

        users_assigned = relationship(
            "User",
            secondary="project_task_user_association")

        task_dependencies = relationship(
            "ProjectTask",
            secondary="task_dependencies_association",
            primaryjoin=id == task_dependencies_association.c.task_id,
            secondaryjoin=id == task_dependencies_association.c.task_dependency_id
        )

        vulnerabilities_related = relationship(
            "VulnerabilityGeneric",
            secondary="vulnerabilities_related_association",
        )

        project_id = Column(
            Integer,
            ForeignKey('planner_project.id'),
            index=True,
            nullable=False,
        )
        project = relationship(
            'PlannerProject',
            backref=backref('tasks', cascade="all, delete-orphan")
        )

        @property
        def parent(self):
            return None


    class License(Metadata):
        __tablename__ = 'license'
        id = Column(Integer, primary_key=True)
        product = NonBlankColumn(Text)
        start_date = Column(DateTime, nullable=False)
        end_date = Column(DateTime, nullable=False)

        type = BlankColumn(Text)
        notes = BlankColumn(Text)

        __table_args__ = (
            UniqueConstraint('product', 'start_date', 'end_date', name='uix_license_product_start_end_dates'),
        )


    class ExecutiveReport(Metadata):
        STATUSES = [
            'created',
            'error',
            'processing',
        ]
        __tablename__ = 'executive_report'
        id = Column(Integer, primary_key=True)

        grouped = Column(Boolean, nullable=False, default=False)
        name = NonBlankColumn(Text, index=True)
        status = Column(Enum(*STATUSES, name='executive_report_statuses'), nullable=False, default='processing')
        template_name = NonBlankColumn(Text)

        conclusions = BlankColumn(Text)
        enterprise = BlankColumn(Text)
        objectives = BlankColumn(Text)
        recommendations = BlankColumn(Text)
        scope = BlankColumn(Text)
        summary = BlankColumn(Text)
        title = BlankColumn(Text)
        confirmed = Column(Boolean, nullable=False, default=False)
        vuln_count = Column(Integer, default=0)  # saves the amount of vulns when the report was generated.
        markdown = Column(Boolean, default=False, nullable=False)
        duplicate_detection = Column(Boolean, default=False, nullable=False)
        border_size = Column(Integer, default=3, nullable=True)
        advanced_filter = Column(Boolean, default=False, nullable=False)
        advanced_filter_parsed = Column(Text, nullable=False, default="")
        sections_metadata = Column(JSONType, nullable=False, default=dict)

        workspaces = relationship(
            'Workspace',
            secondary='executive_report_workspace_table',
            back_populates='reports'
        )
        tags = relationship(
            "Tag",
            secondary="tag_object",
            primaryjoin="and_(TagObject.object_id==ExecutiveReport.id, TagObject.object_type=='executive_report')",
            collection_class=set,
        )
        filter = Column(JSONType, nullable=True, default=[])

        @property
        def parent(self):
            return

        @property
        def attachments(self):
            try:
                from faraday.domain.vulnerability.models import File
            except ImportError:
                from faraday.server.models import File  # noqa: F401
            return db.session.query(File).filter_by(
                object_id=self.id,
                object_type='executive_report'
            )


    class WorkspaceSummaryReport(Metadata):
        DAILY_TYPE = 'daily'
        WEEKLY_TYPE = 'weekly'
        MONTHLY_TYPE = 'monthly'
        YEARLY_TYPE = 'yearly'

        SUMMARY_PERIOD_TYPES = [
            DAILY_TYPE,
            WEEKLY_TYPE,
            MONTHLY_TYPE,
            YEARLY_TYPE,
        ]

        __tablename__ = 'workspace_summary_report'
        id = Column(Integer, primary_key=True)

        user_id = Column(Integer, ForeignKey('faraday_user.id', ondelete='CASCADE'), index=True, nullable=False)
        user = relationship(
            'User',
            backref=backref('workspace_summary_reports', cascade="all, delete-orphan", passive_deletes=True),
            foreign_keys=[user_id],
        )

        workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
        workspace = relationship(
            'Workspace',
            foreign_keys=[workspace_id],
            backref=backref('workspace_summary_reports', cascade="all, delete-orphan", passive_deletes=True),
        )

        recipients = Column(JSONType, nullable=False, default={})
        summary_period_type = Column(
            Enum(*SUMMARY_PERIOD_TYPES, name='summary_period_types'),
            nullable=False,
            default='weekly',
        )
        active = Column(Boolean, nullable=False, default=True)

        __table_args__ = (
            UniqueConstraint('creator_id', 'workspace_id', name='uix_workspace_summary_report_creator_workspace'),
        )


    class WorkspaceSummaryReportRun(Metadata):
        __tablename__ = 'workspace_summary_report_run'
        id = Column(Integer, primary_key=True)

        workspace_summary_report_id = Column(
            Integer,
            ForeignKey('workspace_summary_report.id', ondelete='CASCADE'),
            index=True,
            nullable=False,
        )
        workspace_summary_report = relationship(
            'WorkspaceSummaryReport',
            foreign_keys=[workspace_summary_report_id],
            backref=backref('runs', cascade="all, delete-orphan", passive_deletes=True),
        )

        # Denormalized copy of the generated File's filename: set once at
        # creation and never updated afterwards, so listing runs doesn't need to
        # join the polymorphic File table.
        filename = NonBlankColumn(Text)

        @property
        def attachments(self):
            try:
                from faraday.domain.vulnerability.models import File
            except ImportError:
                from faraday.server.models import File  # noqa: F401
            return db.session.query(File).filter_by(
                object_id=self.id,
                object_type='ws_sum_report',
            )


__all__ = [
    'ExecutiveReport',
    'WorkspaceSummaryReport',
    'WorkspaceSummaryReportRun',
    'MethodologyTemplate',
    'Methodology',
    'PlannerProject',
    'ProjectTask',
    'License',
]
