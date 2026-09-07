"""Domain host_service — YAGNI parcial: Hostname + Service reales migrados (1 arista).

TODO YAGNI: mover Host (100+ líneas), Credential y SourceCode desde
faraday/server/models.py:400,1237,2334 a definiciones reales aquí.
Mantiene re-export para contracts.md (__all__ con 5 clases) sin romper wire.

Usa lazy db import como en faraday/domain/base.py para evitar ciclo.
"""
from datetime import datetime
from functools import partial

try:
    from faraday.server.models import db  # type: ignore
except ImportError:  # fallback para py_compile sin app context
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # type: ignore

try:
    from faraday.domain.base import Metadata  # type: ignore
except ImportError:
    try:
        from faraday.server.models import Metadata  # type: ignore
    except ImportError:
        from sqlalchemy import Column, DateTime, ForeignKey, Integer  # noqa: F401
        from sqlalchemy.ext.declarative import declared_attr  # noqa: F401
        from sqlalchemy.orm import relationship  # noqa: F401

        class Metadata(db.Model):  # type: ignore
            __abstract__ = True

            @declared_attr
            def creator_id(cls):
                return Column(Integer, ForeignKey('faraday_user.id', ondelete="SET NULL"), nullable=True)

            @declared_attr
            def creator(cls):
                return relationship('User', foreign_keys=[cls.creator_id])

            @declared_attr
            def update_user_id(cls):
                return Column(Integer, ForeignKey('faraday_user.id', ondelete="SET NULL"), nullable=True)

            @declared_attr
            def update_user(cls):
                return relationship('User', foreign_keys=[cls.update_user_id])

            create_date = Column(DateTime, default=datetime.utcnow)
            update_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

from sqlalchemy import Boolean, Column, Enum, ForeignKey, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.orm import backref, column_property, joinedload, relationship, undefer
from sqlalchemy.sql import select, table

NonBlankColumn = partial(Column, nullable=False, info={'allow_blank': False})
BlankColumn = partial(Column, nullable=False, info={'allow_blank': True}, default='')


def _make_generic_count_property(parent_table, children_table, where=None, use_column_property=True):
    """Copia local de faraday/server/models.py:_make_generic_count_property para desacoplar dominio."""
    children_id_field = f'{children_table}.id'
    parent_id_field = f'{parent_table}.id'
    children_rel_field = f'{children_table}.{parent_table}_id'
    query = (
        select(func.count(text(children_id_field)))
        .select_from(table(children_table))
        .where(text(f'{children_rel_field} = {parent_id_field}'))
    )
    if where is not None:
        query = query.where(where)
    query = query.scalar_subquery()
    if use_column_property:
        return column_property(query, deferred=True)
    return query


class Hostname(Metadata):
    __tablename__ = 'hostname'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text)

    host_id = Column(Integer, ForeignKey('host.id', ondelete='CASCADE'), index=True, nullable=False)
    host = relationship('Host', backref=backref("hostnames", cascade="all, delete-orphan"))

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('hostnames', cascade="all, delete-orphan", passive_deletes=True),
    )

    __table_args__ = (
        UniqueConstraint(name, host_id, workspace_id, name='uix_hostname_host_workspace'),
    )

    def __str__(self):
        return self.name

    @property
    def parent(self):
        return self.host


class Service(Metadata):
    STATUSES = [
        'open',
        'closed',
        'filtered'
    ]
    __tablename__ = 'service'
    id = Column(Integer, primary_key=True)
    name = BlankColumn(Text)
    description = BlankColumn(Text)
    port = Column(Integer, nullable=False)
    owned = Column(Boolean, nullable=False, default=False)

    protocol = NonBlankColumn(Text)
    status = Column(Enum(*STATUSES, name='service_statuses'), nullable=False)
    version = BlankColumn(Text)

    banner = BlankColumn(Text)

    host_id = Column(Integer, ForeignKey('host.id', ondelete='CASCADE'), index=True, nullable=False)

    commands = relationship(
        'Command',
        secondary='command_object',
        primaryjoin='and_(Service.id == CommandObject.object_id, CommandObject.object_type == "service")',
        collection_class=set,
        passive_deletes=True
    )

    host = relationship(
        'Host',
        foreign_keys=[host_id],
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref('services', cascade="all, delete-orphan", passive_deletes=True),
    )

    vulnerability_count = _make_generic_count_property('service', 'vulnerability')

    __table_args__ = (
        UniqueConstraint(port, protocol, host_id, workspace_id, name='uix_service_port_protocol_host_workspace'),
    )

    @property
    def parent(self):
        return self.host

    @property
    def summary(self):
        if self.version and self.version.lower() != "unknown":
            version = " (" + self.version + ")"
        else:
            version = ""
        return f"({self.port}/{self.protocol}) {self.name}{version or ''}"


class SourceCode(Metadata):
    __tablename__ = 'source_code'
    id = Column(Integer, primary_key=True)
    filename = NonBlankColumn(Text)
    function = BlankColumn(Text)
    module = BlankColumn(Text)

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship('Workspace', backref='source_codes')

    __table_args__ = (
        UniqueConstraint(filename, workspace_id, name='uix_source_code_filename_workspace'),
    )

    @property
    def parent(self):
        return


class Credential(Metadata):
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    password = NonBlankColumn(Text, nullable=False)
    username = NonBlankColumn(Text, nullable=False)
    endpoint = Column(Text, default='')
    leak_date = Column(DateTime)
    owned = Column(Boolean, default=False)

    vulnerabilities = relationship("VulnerabilityGeneric",
                                   secondary='association_table_vulnerabilities_credentials',
                                   back_populates='credentials',
                                   lazy='selectin')

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship('Workspace', backref=backref('credentials', passive_deletes=True),
                            foreign_keys=[workspace_id], )

    __table_args__ = (
        UniqueConstraint('username', 'password', 'endpoint', 'workspace_id',
                         name='uix_credential_username_password_endpoint_workspace'),
        # Index handled via __table_args__ in original; keep minimal for YAGNI
    )

    @property
    def parent(self):
        return


class Host(Metadata):
    __tablename__ = 'host'
    id = Column(Integer, primary_key=True)
    ip = NonBlankColumn(Text)  # IP v4 or v6
    description = BlankColumn(Text)
    os = BlankColumn(Text)

    owned = Column(Boolean, nullable=False, default=False)

    default_gateway_ip = BlankColumn(Text)
    default_gateway_mac = BlankColumn(Text)

    mac = BlankColumn(Text)
    net_segment = BlankColumn(Text)

    commands = relationship(
        'Command',
        secondary='command_object',
        primaryjoin='and_(Host.id == CommandObject.object_id, CommandObject.object_type == "host")',
        collection_class=set,
        passive_deletes=True
    )

    services = relationship(
        'Service',
        order_by='Service.protocol,Service.port',
        cascade="all, delete-orphan"
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete='CASCADE'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        foreign_keys=[workspace_id],
        backref=backref("hosts", cascade="all, delete-orphan", passive_deletes=True)
    )

    open_service_count = _make_generic_count_property('host', 'service', where=text("service.status = 'open'"))
    total_service_count = _make_generic_count_property('host', 'service')

    vulnerability_count = column_property(
        (
            select(func.count(text('vulnerability.id')))
            .select_from(text('vulnerability'))
            .where(text('vulnerability.host_id = host.id'))
            .scalar_subquery()
        ) + (
            select(func.count(text('vulnerability.id')))
            .select_from(text('vulnerability, service'))
            .where(text('vulnerability.service_id = service.id and service.host_id = host.id'))
            .scalar_subquery()
        ),
        deferred=True,
    )

    # anti-ciclo: usa text() y lazy import para evitar dependencia dura a Command/CommandObject en import time
    # definiciones equivalentes a server/models.py pero con text() para desacoplar
    creator_command_id = column_property(
        select(text('command_object.command_id'))
        .select_from(text('command_object'))
        .where(text("command_object.object_type = 'host'"))
        .where(text('command_object.object_id = host.id'))
        .where(text('command_object.workspace_id = host.workspace_id'))
        .order_by(text('command_object.create_date asc'))
        .limit(1)
        .scalar_subquery(),
        deferred=True,
    )

    creator_command_tool = column_property(
        select(text('command.tool'))
        .select_from(text('command join command_object on command.id = command_object.command_id'))
        .where(text("command_object.object_type = 'host'"))
        .where(text('command_object.object_id = host.id'))
        .where(text('command_object.workspace_id = host.workspace_id'))
        .order_by(text('command_object.create_date asc'))
        .limit(1)
        .scalar_subquery(),
        deferred=True,
    )

    creator_command_params = column_property(
        select(text('command.params'))
        .select_from(text('command join command_object on command.id = command_object.command_id'))
        .where(text("command_object.object_type = 'host'"))
        .where(text('command_object.object_id = host.id'))
        .where(text('command_object.workspace_id = host.workspace_id'))
        .order_by(text('command_object.create_date asc'))
        .limit(1)
        .scalar_subquery(),
        deferred=True,
    )

    __table_args__ = (
        UniqueConstraint(ip, workspace_id, name='uix_host_ip_workspace'),
    )

    vulnerability_critical_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_high_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_medium_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_low_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_info_generic_count = Column(Integer, server_default=text("0"))
    vulnerability_unclassified_generic_count = Column(Integer, server_default=text("0"))

    importance = Column(Integer, default=0)

    risk = Column(Integer, default=0)

    @classmethod
    def query_with_count(cls, host_ids, workspace):
        # lazy imports para evitar ciclo con Workspace/User
        try:
            from faraday.server.models import Workspace as _Workspace, User as _User  # type: ignore
            Workspace = _Workspace  # noqa: F811
            User = _User  # noqa: F811
        except Exception:
            from sqlalchemy.orm import aliased  # noqa: F401
            Workspace = None  # type: ignore
            User = None  # type: ignore
        query = cls.query.join(Workspace).filter(Workspace.id == workspace.id)
        if host_ids:
            query = query.filter(cls.id.in_(host_ids))
        # undefer/joinedload ya importados arriba; si Workspace/User son None fallback simple
        if Workspace is not None:
            return query.options(
                undefer(cls.open_service_count),
                joinedload(cls.hostnames),
                joinedload(cls.services),
                joinedload(cls.update_user),
                joinedload(getattr(cls, 'creator')).load_only(User.username),
            ).limit(None).offset(0)
        return query

    @property
    def parent(self):
        return

    def set_hostnames(self, new_hostnames):
        """Override the host's hostnames. Take care of deleting old not
        used hostnames and to leave the sames the ones that weren't
        modified

        This function was thought to update existing objects, it shouldn't
        be used when creating!
        """
        try:
            from faraday.domain.host_service.service import set_host_hostnames  # pylint: disable=import-outside-toplevel

            return set_host_hostnames(self, new_hostnames)
        except ImportError:
            # fallback local sin depender de faraday.server.models.set_children_objects (evita ciclo)
            try:
                from faraday.server.models import set_children_objects as _set_children  # type: ignore
                return _set_children(self, new_hostnames,
                                     parent_field='hostnames',
                                     child_field='name')
            except Exception:
                # último fallback inline
                import operator
                children_model = getattr(type(self), 'hostnames').property.mapper.class_
                value = set(new_hostnames)
                from faraday.server.models import db as _db  # type: ignore
                with _db.session.no_autoflush:
                    current_value = getattr(self, 'hostnames')
                    current_value_fields = set(map(operator.attrgetter('name'), current_value))
                    for existing_child in current_value_fields:
                        if existing_child not in value:
                            removed_instance = next(
                                inst for inst in current_value
                                if getattr(inst, 'name') == existing_child)
                            _db.session.delete(removed_instance)
                    for new_child in value:
                        if new_child in current_value_fields:
                            continue
                        kwargs = {'name': new_child, 'workspace': self.workspace}
                        current_value.append(children_model(**kwargs))
                return None


__all__ = ["SourceCode", "Hostname", "Host", "Service", "Credential"]
