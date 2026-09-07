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
from sqlalchemy.orm import backref, column_property, relationship
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


# TODO YAGNI parcial: Host, Credential, SourceCode aún viven en faraday/server/models.py
# Re-export para contracts.md y para que faraday.domain.host_service sea fachada completa (5 nodos).
# Eager try para caso sin ciclo; si falla (carga parcial circular), se resuelve vía __getattr__ lazy.
try:
    from faraday.server.models import SourceCode as _SourceCode, Host as _Host, Credential as _Credential  # type: ignore  # noqa: F401
    SourceCode = _SourceCode  # noqa: F401
    Host = _Host  # noqa: F401
    Credential = _Credential  # noqa: F401
    _has_reexports = True
except Exception:  # noqa: BLE001 - ciclo de importación parcial durante carga de server/models
    _has_reexports = False

__all__ = ["SourceCode", "Hostname", "Host", "Service", "Credential"]


def __getattr__(name):
    if name in ("SourceCode", "Host", "Credential"):
        try:
            import importlib
            srv = importlib.import_module("faraday.server.models")
            return getattr(srv, name)
        except Exception as e:
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from e
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
