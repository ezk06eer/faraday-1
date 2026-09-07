"""Domain command — definiciones reales de Command y CommandObject (shard desde faraday/server/models.py).

Mantiene las relaciones con Workspace/User via string references de SQLAlchemy.
Sigue el patrón lazy-import de faraday/domain/host_service/models.py para evitar
ciclos: cuando es importado desde faraday.server.models (import parcial), todos
los nombres necesarios ya están definidos en ese módulo.
"""
from datetime import datetime

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
    func,
    literal,
)
from sqlalchemy.orm import backref, column_property, query_expression, relationship, with_expression
from sqlalchemy.sql import select, table, text

from faraday.server.fields import JSONType
from faraday.server.utils.database import get_object_type_for
from faraday.server.models import (  # noqa: F401  (import parcial: nombres ya definidos antes del shim)
    BlankColumn,
    Metadata,
    NonBlankColumn,
    OBJECT_TYPES,
    _make_command_created_related_object,
    db,
)


class CommandObject(db.Model):
    __tablename__ = 'command_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

    command = relationship('Command', backref='command_objects')
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('command_objects', cascade="all, delete-orphan")
    )

    create_date = Column(DateTime, default=datetime.utcnow)

    # the following properties are used to know if the command created the specified objects_type
    # remember that this table has a row instances per relationship.
    # this created integer can be used to obtain the total object_type objects created.
    created = _make_command_created_related_object()

    # We are currently using the column property created. However, to avoid losing information
    # we also store a boolean to know if at the moment of created the object related to the
    # Command was created.
    created_persistent = Column(Boolean, nullable=False)

    __table_args__ = (
        Index('ix_command_object_command_id_type', 'command_id', 'object_type'),
        UniqueConstraint('object_id', 'object_type', 'command_id', 'workspace_id',
                         name='uix_command_object_objid_objtype_command_id_ws'),
    )

    @property
    def parent(self):
        return self.command

    @classmethod
    def create(cls, obj, command, add_to_session=True, **kwargs):
        co = cls(obj, workspace=command.workspace, command=command, created_persistent=True, **kwargs)
        if add_to_session:
            db.session.add(co)
        return co

    def __init__(self, object_=None, **kwargs):

        if object_ is not None:
            assert 'object_type' not in kwargs
            assert 'object_id' not in kwargs
            object_type = get_object_type_for(object_)

            # db.session.flush()
            assert object_.id is not None, "object must have an ID. Try flushing the session"
            kwargs['object_id'] = object_.id
            kwargs['object_type'] = object_type
        super().__init__(**kwargs)


def _make_created_objects_sum(object_type_filter):
    where_conditions = [f"command_object.object_type= '{object_type_filter}'",
                        "command_object.command_id = command.id",
                        "command_object.workspace_id = command.workspace_id"]
    return column_property(
        select(func.sum(CommandObject.created)).
        select_from(table('command_object')).
        where(text(' and '.join(where_conditions))).
        scalar_subquery()
    )


def _make_created_objects_sum_joined(object_type_filter, join_filters):
    """
    :param object_type_filter: can be any host, service, vulnerability, credential or any object created from commands.
    :param join_filters: Filter for vulnerability fields.
    :return: column property with sum of created objects.
    """
    where_conditions = [f"command_object.object_type= '{object_type_filter}'",
                        "command_object.command_id = command.id",
                        "vulnerability.id = command_object.object_id ",
                        "command_object.workspace_id = vulnerability.workspace_id"]
    for attr, filter_value in join_filters.items():
        where_conditions.append(f"vulnerability.{attr} = {filter_value}")
    return column_property(
        select(func.sum(CommandObject.created)).
        select_from(table('command_object')).
        select_from(table('vulnerability')).
        where(text(' and '.join(where_conditions))).
        scalar_subquery()
    )


class Command(Metadata):
    IMPORT_SOURCE = [
        'report',
        # all the files the tools export and faraday imports it from the reports directory,
        # gtk manual import or web import.
        'shell',  # command executed on the shell or webshell with hooks connected to faraday.
        'agent',
        'cloud_agent'
    ]

    __tablename__ = 'command'
    id = Column(Integer, primary_key=True)
    command = NonBlankColumn(Text)
    tool = NonBlankColumn(Text)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)
    ip = BlankColumn(String(250))  # where the command was executed
    hostname = BlankColumn(String(250))  # where the command was executed
    params = BlankColumn(Text)
    user = BlankColumn(String(250))  # os username where the command was executed
    import_source = Column(Enum(*IMPORT_SOURCE, name='import_source_enum'))

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('commands', cascade="all, delete-orphan")
    )
    warnings = Column(String(250), nullable=True)

    sum_created_vulnerabilities = _make_created_objects_sum('vulnerability')
    sum_created_vulnerabilities_web = _make_created_objects_sum_joined('vulnerability',
                                                                       {'type': '\'vulnerability_web\''})
    sum_created_hosts = _make_created_objects_sum('host')
    sum_created_services = _make_created_objects_sum('service')
    sum_created_vulnerability_critical = query_expression(literal(0))
    sum_created_vulnerability_high = query_expression(literal(0))
    sum_created_vulnerability_medium = query_expression(literal(0))
    sum_created_vulnerability_low = query_expression(literal(0))
    sum_created_vulnerability_info = query_expression(literal(0))
    sum_created_vulnerability_unclassified = query_expression(literal(0))

    @classmethod
    def with_severity_counts(cls, query):
        """Augment a Command ORM query with per-severity vulnerability creation counts.

        Uses correlated scalar subqueries so the main query structure (joins, eager
        loads, GROUP BY) is not altered. The attributes default to 0 when this method
        is not called, avoiding overhead on Command queries that don't need counts.
        """
        def _sev_expr(severity):
            where_conditions = [
                "command_object.object_type = 'vulnerability'",
                "command_object.command_id = command.id",
                "vulnerability.id = command_object.object_id",
                "command_object.workspace_id = vulnerability.workspace_id",
                f"vulnerability.severity = '{severity}'",
            ]
            return (
                select(func.sum(CommandObject.created))
                .select_from(table('command_object'))
                .select_from(table('vulnerability'))
                .where(text(' and '.join(where_conditions)))
                .scalar_subquery()
            )

        # populate_existing: SA 2.0 needs this for with_expression to override identity-map instances.
        return query.options(
            with_expression(cls.sum_created_vulnerability_critical, _sev_expr('critical')),
            with_expression(cls.sum_created_vulnerability_high, _sev_expr('high')),
            with_expression(cls.sum_created_vulnerability_medium, _sev_expr('medium')),
            with_expression(cls.sum_created_vulnerability_low, _sev_expr('low')),
            with_expression(cls.sum_created_vulnerability_info, _sev_expr('informational')),
            with_expression(cls.sum_created_vulnerability_unclassified, _sev_expr('unclassified')),
        ).execution_options(populate_existing=True)

    agent_execution = relationship(
        'AgentExecution',
        uselist=False,
        back_populates="command"
    )

    tasks = Column(JSONType, nullable=True, default=[])

    @property
    def parent(self):
        return


__all__ = ["Command", "CommandObject"]
