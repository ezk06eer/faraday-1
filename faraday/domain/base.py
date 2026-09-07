"""Domain base — YAGNI extraction of Metadata abstract base from faraday/server/models.py:368

Mantiene contrato: creator/update_user/create_date/update_date.
Import-safe: lazy db import to avoid cycle, fallback to faraday.server.models.db.
"""
from datetime import datetime

try:
    from faraday.server.models import db  # type: ignore
except ImportError:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # fallback for isolated tests

from sqlalchemy import Column, DateTime, ForeignKey, Integer
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship


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
