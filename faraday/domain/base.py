"""Domain base — YAGNI extraction of Metadata + CustomAssociationSet from faraday/server/models.py

Mantiene contrato: Metadata abstract + CustomAssociationSet helper.
"""
from datetime import datetime

try:
    from faraday.server.models import db  # type: ignore
except ImportError:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()

from sqlalchemy import Column, DateTime, ForeignKey, Integer
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship
from sqlalchemy.ext.associationproxy import _AssociationSet
from sqlalchemy.exc import IntegrityError

try:
    from faraday.server.utils.database import is_unique_constraint_violation
except ImportError:
    def is_unique_constraint_violation(ex): return False

class Metadata(db.Model):
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

class CustomAssociationSet(_AssociationSet):
    """Custom association set that passes creator method both value and parent instance."""
    def __init__(self, lazy_collection, creator, value_attr, parent):
        if getattr(parent, 'getset_factory', False):
            getter, setter = parent.getset_factory(parent.collection_class, parent)
        else:
            getter, setter = parent._default_getset(parent.collection_class)
        super().__init__(lazy_collection, creator, getter, setter, parent)

    def _create(self, value):
        if getattr(self.lazy_collection, 'ref', False):
            parent_instance = self.lazy_collection.ref()
        else:
            parent_instance = self.lazy_collection.parent
        session = db.session
        conflict_objs = session.new
        try:
            yield self.creator(value, parent_instance)
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            session.rollback()
            for conflict_obj in conflict_objs:
                if not hasattr(conflict_obj, 'name'):
                    continue
                if conflict_obj.name == value:
                    continue
                persisted_conflict_obj = session.query(conflict_obj.__class__).filter_by(name=conflict_obj.name).first()
                if persisted_conflict_obj:
                    self.col.add(persisted_conflict_obj)
            yield self.creator(value, parent_instance)

    def add(self, value):
        if value not in self:
            for new_value in self._create(value):
                self.col.add(new_value)
