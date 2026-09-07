"""Domain user_auth — shard real (X4): Role, UserToken, User, UserAvatar,
PermissionsGroup, PermissionsUnit, PermissionsUnitAction, RolePermission.

Extraídas verbatim desde faraday/server/models.py. MethodologyTemplate,
Methodology, PlannerProject, ProjectTask y License permanecen en
faraday/server/models.py y se re-exportan aquí de forma lazy (PEP 562) para
mantener el contrato del shard (faraday/domain/README.md, user_auth: 9 clases).

CRÍTICO AUTH: User/Role son load-bearing (flask-login + jwt HS512 en
faraday/server/app.py:257). Patrón lazy `db` import como faraday/domain/base.py;
Metadata viene de faraday/domain/base.py. Relaciones cross-shard usan string
references ('Workspace', 'Role') — resolución lazy por registry SQLAlchemy.

Ciclo domain<->server: si este módulo se importa ANTES que
faraday.server.models, la importación de `db` dispara la carga completa de
server.models, cuyo shim cae en el fallback ImportError y define las clases
localmente; al retomar este módulo las tablas ya existen en el MetaData, así
que se detecta y se re-exportan esas clases (identidad preservada en ambos
órdenes, sin doble definición).
"""
import time
from datetime import datetime

import jwt
from flask import current_app as app
from flask_security import RoleMixin, UserMixin
from flask_security.utils import hash_data
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
    case,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import backref, relationship

from faraday.domain.base import Metadata

try:
    from faraday.server.models import (  # type: ignore
        BlankColumn,
        LDAP_TYPE,
        LOCAL_TYPE,
        NonBlankColumn,
        SAML_TYPE,
        association_workspace_and_users_table,
        db,
    )
except ImportError:  # fallback para py_compile / uso aislado sin app
    from functools import partial
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # type: ignore
    NonBlankColumn = partial(Column, nullable=False, info={'allow_blank': False})
    BlankColumn = partial(Column, nullable=False, info={'allow_blank': True}, default='')
    LDAP_TYPE = 'ldap'
    LOCAL_TYPE = 'local'
    SAML_TYPE = 'saml'
    association_workspace_and_users_table = None  # type: ignore

try:
    from faraday.server.fields import FaradayUploadedFile, JSONType
except ImportError:
    from sqlalchemy import JSON as JSONType  # type: ignore
    FaradayUploadedFile = None  # type: ignore

from depot.fields.sqlalchemy import UploadedFileField

try:
    from faraday.server.config import faraday_server
except ImportError:
    faraday_server = None  # type: ignore


if 'faraday_user' in db.metadata.tables:
    # Ciclo domain-first: server.models ya definió las clases via fallback.
    from faraday.server.models import (  # type: ignore  # noqa: F401
        PermissionsGroup,
        PermissionsUnit,
        PermissionsUnitAction,
        Role,
        RolePermission,
        User,
        UserAvatar,
        UserToken,
    )
    roles_users = db.metadata.tables.get('roles_users')
    DOMAIN_USER_AVAILABLE = True
else:
    roles_users = db.Table('roles_users',
                           db.Column('user_id', db.Integer(), db.ForeignKey('faraday_user.id')),
                           db.Column('role_id', db.Integer(), db.ForeignKey('faraday_role.id')))


    class Role(Metadata, RoleMixin):
        __tablename__ = 'faraday_role'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        weight = db.Column(db.Integer(), nullable=False, default=100)
        custom = db.Column(db.Boolean(), nullable=False, default=True)
        description = db.Column(db.String(280))


    class UserToken(Metadata):
        __tablename__ = 'user_token'
        GITLAB_SCOPE = 'gitlab'
        SCHEDULER_SCOPE = 'scheduler'
        SERVICE_DESK_SCOPE = 'service_desk'
        JIRA_SCOPE = 'jira'
        GLOBAL_SCOPE = 'global'
        SCOPES = [GITLAB_SCOPE, SERVICE_DESK_SCOPE, SCHEDULER_SCOPE, JIRA_SCOPE, GLOBAL_SCOPE]

        id = Column(Integer(), primary_key=True)

        user_id = Column(Integer, ForeignKey('faraday_user.id', ondelete='CASCADE'), index=True, nullable=False)
        user = relationship('User',
                            backref=backref('user_tokens', cascade="all, delete-orphan", passive_deletes=True),
                            foreign_keys=[user_id])

        token = Column(String(), nullable=False, unique=True)
        alias = Column(String(), nullable=False)
        expires_at = Column(DateTime(), nullable=True)
        scope = Column(Enum(*SCOPES, name='token_scopes'), nullable=False, default="gitlab")
        revoked = Column(Boolean(), default=False, nullable=False)
        hide = Column(Boolean(), default=False, nullable=False)

        @hybrid_property
        def expired(self):
            return self.expires_at is not None and self.expires_at < datetime.utcnow()

        @expired.expression
        def expired(cls):
            return case(
                (cls.expires_at != None, cls.expires_at < datetime.utcnow()),  # noqa E711
                else_=False
            )


    DOMAIN_USER_AVAILABLE = True


    class User(db.Model, UserMixin):
        __tablename__ = 'faraday_user'
        ADMIN_ROLE = 'admin'
        PENTESTER_ROLE = 'pentester'
        ASSET_OWNER_ROLE = 'asset_owner'
        CLIENT_ROLE = 'client'
        WORKSPACE_ADMIN_ROLE = 'workspace_admin'
        ROLES = [ADMIN_ROLE, PENTESTER_ROLE, ASSET_OWNER_ROLE, CLIENT_ROLE, WORKSPACE_ADMIN_ROLE]
        OTP_STATES = ["disabled", "requested", "confirmed"]
        USER_TYPES = [LDAP_TYPE, LOCAL_TYPE, SAML_TYPE]

        id = Column(Integer, primary_key=True)
        username = NonBlankColumn(String(255), unique=True)
        password = Column(String(255), nullable=True)
        email = Column(String(255), unique=True, nullable=True)  # TBI
        name = BlankColumn(String(255))  # TBI
        last_login_at = Column(DateTime())  # flask-security
        current_login_at = Column(DateTime())  # flask-security
        last_login_ip = BlankColumn(String(100))  # flask-security
        current_login_ip = BlankColumn(String(100))  # flask-security
        login_count = Column(Integer)  # flask-security
        active = Column(Boolean(), default=True, nullable=False)  # TBI flask-security
        confirmed_at = Column(DateTime())
        _otp_secret = Column(
            String(32),
            name="otp_secret", nullable=True
        )
        state_otp = Column(Enum(*OTP_STATES, name='user_otp_states'), nullable=False, default="disabled")
        preferences = Column(JSONType, nullable=True, default={})
        fs_uniquifier = Column(String(64), unique=True, nullable=False)  # flask-security

        roles = db.relationship('Role', secondary=roles_users, backref='users')
        user_type = Column(Enum(*USER_TYPES, name='user_types'), nullable=False, default=LOCAL_TYPE)

        @property
        def roles_list(self):
            return [role.name for role in self.roles]

        workspaces = relationship(
            'Workspace',
            secondary=association_workspace_and_users_table,
            back_populates="allowed_users",
        )

        session_id = Column(String(64), unique=True)

        def __repr__(self):
            return f"<{'LDAP ' if self.user_type == LDAP_TYPE else ''}User: {self.username}>"

        def get_security_payload(self):
            return {
                "username": self.username,
                "name": self.username,
                "email": self.email,
                "roles": self.roles_list,
            }

        def get_token(self):
            user_id = self.fs_uniquifier
            hashed_data = hash_data(self.password) if self.password else None
            iat = int(time.time())
            exp = iat + int(faraday_server.api_token_expiration)
            jwt_data = {'user_id': user_id, "validation_check": hashed_data, 'iat': iat, 'exp': exp}

            return jwt.encode(jwt_data, app.config['SECRET_KEY'], algorithm="HS512")


    class UserAvatar(Metadata):
        __tablename__ = 'user_avatar'

        id = Column(Integer, autoincrement=True, primary_key=True)
        name = BlankColumn(Text, unique=True)
        # photo field will automatically generate thumbnail
        # if the file is a valid image
        photo = Column(UploadedFileField(upload_type=FaradayUploadedFile))
        user_id = Column('user_id', Integer(), ForeignKey('faraday_user.id'))
        user = relationship('User', foreign_keys=[user_id])


    class PermissionsGroup(db.Model):
        __tablename__ = 'permissions_group'

        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False, unique=True)


    class PermissionsUnit(db.Model):
        __tablename__ = 'permissions_unit'

        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False, unique=True)
        permissions_group_id = Column(Integer, ForeignKey('permissions_group.id'), index=True, nullable=False)
        permissions_group = relationship(
            'PermissionsGroup',
            backref=backref('permissions_units', cascade="all, delete-orphan"),
            foreign_keys=[permissions_group_id],
        )


    class PermissionsUnitAction(db.Model):
        __tablename__ = 'permissions_unit_action'
        CREATE_ACTION = 'create'
        READ_ACTION = 'read'
        UPDATE_ACTION = 'update'
        DELETE_ACTION = 'delete'
        RUN_ACTION = 'run'
        TAG_ACTION = 'tag'
        ACTIONS = [CREATE_ACTION, READ_ACTION, UPDATE_ACTION, DELETE_ACTION, RUN_ACTION, TAG_ACTION]

        id = Column(Integer, primary_key=True)

        permissions_unit_id = Column(Integer, ForeignKey('permissions_unit.id'), index=True, nullable=False)
        permissions_unit = relationship(
            'PermissionsUnit',
            backref=backref('permissions_actions', cascade="all, delete-orphan"),
            foreign_keys=[permissions_unit_id],
        )
        action_type = Column(Enum(*ACTIONS, name='action_types'), nullable=False, default=READ_ACTION)

        __table_args__ = (UniqueConstraint(permissions_unit_id, action_type, name='uix_permissions_unit_action'),)


    class RolePermission(db.Model):
        __tablename__ = 'role_permission'

        id = Column(Integer, primary_key=True)

        unit_action_id = Column(Integer, ForeignKey('permissions_unit_action.id'), index=True, nullable=False)
        unit_action = relationship(
            'PermissionsUnitAction',
            backref=backref('role_permissions', cascade="all, delete-orphan"),
            foreign_keys=[unit_action_id],
        )
        role_id = Column(Integer, ForeignKey('faraday_role.id'), index=True, nullable=False)
        role = relationship(
            'Role',
            backref=backref('unit_action_permissions', cascade="all, delete-orphan"),
            foreign_keys=[role_id],
        )

        allowed = Column(Boolean, default=False, nullable=False)

        __table_args__ = (UniqueConstraint(unit_action_id, role_id, name='uix_unit_action_role'),)


_LAZY_SERVER_EXPORTS = {
    'MethodologyTemplate', 'Methodology', 'PlannerProject', 'ProjectTask', 'License',
}


def __getattr__(name):
    if name in _LAZY_SERVER_EXPORTS:
        from faraday.server import models as _server_models
        return getattr(_server_models, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Role", "UserToken", "User", "UserAvatar",
    # Lazy re-exports via __getattr__ (permanecen en faraday.server.models):
    "MethodologyTemplate",  # noqa: F822
    "Methodology",  # noqa: F822
    "PlannerProject",  # noqa: F822
    "ProjectTask",  # noqa: F822
    "License",  # noqa: F822
    "PermissionsGroup", "PermissionsUnit", "PermissionsUnitAction", "RolePermission",
    "DOMAIN_USER_AVAILABLE", "roles_for", "token_type_is",
]


def roles_for(user):
    """Devuelve la lista de nombres de rol de un usuario (helper puro)."""
    if user is None:
        return []
    return [getattr(r, "name", str(r)) for r in getattr(user, "roles", []) or []]


def token_type_is(authg, expected):
    """True si el ``type`` del token (dict claims o UserToken) == ``expected``."""
    if authg is None:
        return False
    if isinstance(authg, dict):
        return authg.get("type") == expected
    return getattr(authg, "type", None) == expected
