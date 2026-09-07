"""Domain tagging — YAGNI: Tag + TagObject reales migrados desde faraday/server/models.py.

TagObject hace las veces de association table genérica ('tag_object') entre tags y
cualquier objeto (vulnerability, executive_report, credential, ...). Los consumidores
la referencian por string (secondary="tag_object"), por lo que basta con que la clase
esté registrada en el metadata global.

Usa lazy db import como en faraday/domain/base.py para evitar ciclo.
"""
from functools import partial

try:
    from faraday.server.models import db  # type: ignore
except ImportError:  # fallback para py_compile sin app context
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # type: ignore

try:
    from faraday.domain.base import Metadata  # type: ignore
except ImportError:
    from faraday.server.models import Metadata  # type: ignore

from sqlalchemy import Column, Enum, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import relationship

NonBlankColumn = partial(Column, nullable=False, info={'allow_blank': False})

OBJECT_TYPES = [
    'vulnerability',
    'host',
    'credential',
    'service',
    'source_code',
    'comment',
    'executive_report',
    'workspace',
    'task',
    'report_logo',
    'report_template',
    'template_logo',
    'ws_sum_report',
]


class Tag(Metadata):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True)
    name = NonBlankColumn(Text, unique=True)
    slug = NonBlankColumn(Text, unique=True)


class TagObject(db.Model):
    __tablename__ = 'tag_object'
    id = Column(Integer, primary_key=True)

    object_id = Column(Integer, nullable=False)
    object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

    tag = relationship('Tag', backref='tagged_objects')
    tag_id = Column(Integer, ForeignKey('tag.id'), index=True)

    __table_args__ = (
        # Enables fast lookup: "all tags for objects of type X with id IN (...)"
        Index('ix_tag_object_type_object_id', 'object_type', 'object_id'),
    )


__all__ = ['Tag', 'TagObject']
