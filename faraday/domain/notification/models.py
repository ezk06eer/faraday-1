"""Domain notification — shard real (W4 Comment + W7 notification).

Comment (W4) y 16 clases de notificación (W7) extraídas verbatim desde
faraday/server/models.py: NotificationSubscription*, NotificationEvent,
NotificationBase (+3 subtipos), Notification, BaseNotification,
UserNotification, UserNotificationSettings, EmailNotification, SlackNotification.

ExecutiveReport y EventType permanecen en faraday/server/models.py y se
re-exportan aquí para mantener el contrato del shard
(faraday/domain/README.md, notification: 12 clases).

Patrón: lazy `db` import como faraday/domain/base.py para evitar ciclo
duro; Metadata viene de faraday/domain/base.py (ya real).
Relaciones cross-shard usan string references ('User', 'Role', 'Workspace',
'EventType', 'ObjectType') — la resolución es lazy por registry SQLAlchemy.

Ciclo domain<->server: si este módulo se importa ANTES que
faraday.server.models, la importación de `db` dispara la carga completa de
server.models, cuyo shim cae en el fallback ImportError y define las clases
localmente; al retomar este módulo las tablas ya existen en el MetaData, así
que se detecta y se re-exportan esas clases (identidad preservada en ambos
órdenes, sin doble definición).
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
)
from sqlalchemy.orm import backref, relationship
from sqlalchemy.sql import text

from faraday.domain.base import Metadata

try:
    from faraday.server.models import (
        db,  # type: ignore
        NOTIFICATION_METHODS,
        OBJECT_TYPES,
        ExecutiveReport,
        EventType,
        BlankColumn,
        COMMENT_TYPES,
    )
except ImportError:  # fallback para py_compile / uso aislado sin app
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()  # type: ignore
    NOTIFICATION_METHODS = ['mail', 'webhook', 'websocket']
    OBJECT_TYPES = [
        'vulnerability', 'host', 'credential', 'service', 'source_code',
        'comment', 'executive_report', 'workspace', 'task', 'report_logo',
        'report_template', 'template_logo', 'ws_sum_report',
    ]
    ExecutiveReport = None  # type: ignore
    EventType = None  # type: ignore
    BlankColumn = Text
    COMMENT_TYPES = ['user']

try:
    from faraday.server.fields import JSONType
except ImportError:
    from sqlalchemy import JSON as JSONType  # type: ignore


if 'notification_subscription' in db.metadata.tables:
    # Ciclo domain-first: server.models ya definió las clases via fallback.
    from faraday.server.models import (  # type: ignore  # noqa: F401
        NotificationSubscription, NotificationSubscriptionConfigBase,
        NotificationSubscriptionMailConfig, NotificationSubscriptionWebHookConfig,
        NotificationSubscriptionWebSocketConfig, NotificationEvent, NotificationBase,
        MailNotification, WebHookNotification, WebsocketNotification, Notification,
        BaseNotification, UserNotification, UserNotificationSettings,
        EmailNotification, SlackNotification,
    )
else:
    allowed_roles_association = db.metadata.tables.get('notification_allowed_roles')
    if allowed_roles_association is None:
        allowed_roles_association = db.Table('notification_allowed_roles',
                                             Column('notification_subscription_id', Integer,
                                                    db.ForeignKey('notification_subscription.id'), nullable=False),
                                             Column('allowed_role_id', Integer, db.ForeignKey('faraday_role.id'),
                                                    nullable=False)
                                             )


    class NotificationSubscription(Metadata):
        __tablename__ = 'notification_subscription'
        id = Column(Integer, primary_key=True)
        event_type_id = Column(Integer, ForeignKey('event_type.id'), index=True, nullable=False)
        event_type = relationship(
            'EventType',
            backref=backref('event_type', cascade="all, delete-orphan")
        )
        allowed_roles = relationship("Role", secondary=allowed_roles_association)


    class NotificationSubscriptionConfigBase(db.Model):
        __tablename__ = 'notification_subscription_config_base'
        id = Column(Integer, primary_key=True)
        subscription_id = Column(Integer, ForeignKey('notification_subscription.id'), index=True, nullable=False)
        subscription = relationship(
            'NotificationSubscription',
            backref=backref('notification_subscription_config', cascade="all, delete-orphan")
        )

        role_level = Column(Boolean, default=False)
        workspace_level = Column(Boolean, default=False)

        active = Column(Boolean, default=True)
        type = Column(String(24))

        __mapper_args__ = {
            'polymorphic_on': type,
            'polymorphic_identity': 'base'
        }

        __table_args__ = (
            UniqueConstraint('subscription_id', 'type', name='uix_subscriptionid_type'),
        )

        @property
        def dst(self):
            raise NotImplementedError('Notification subscription base dst called. Must Be implemented.')


    class NotificationSubscriptionMailConfig(NotificationSubscriptionConfigBase):
        __tablename__ = 'notification_subscription_mail_config'
        id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
        email = Column(String(50), nullable=True)
        user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=True)
        user_notified = relationship(
            'User',
            backref=backref('notification_subscription_mail_config', cascade="all, delete-orphan")
        )

        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[0]
        }


    class NotificationSubscriptionWebHookConfig(NotificationSubscriptionConfigBase):
        __tablename__ = 'notification_subscription_webhook_config'
        id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
        url = Column(String(50), nullable=False)
        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[1]
        }


    class NotificationSubscriptionWebSocketConfig(NotificationSubscriptionConfigBase):
        __tablename__ = 'notification_subscription_websocket_config'
        id = Column(Integer, ForeignKey('notification_subscription_config_base.id'), primary_key=True)
        user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=True)
        user_notified = relationship(
            'User',
            backref=backref('notification_subscription_websocket_config', cascade="all, delete-orphan")
        )
        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[2]
        }


    class NotificationEvent(db.Model):
        __tablename__ = 'notification_event'
        id = Column(Integer, primary_key=True)
        event_type_id = Column(Integer, ForeignKey('event_type.id'), index=True, nullable=False)
        event_type = relationship(
            'EventType',
            backref=backref('notification_event_type', cascade="all, delete-orphan")
        )
        object_id = Column(Integer, nullable=False)
        object_type_id = Column(Integer, ForeignKey('object_type.id'), index=True, nullable=False)
        object_type = relationship(
            'ObjectType',
            backref=backref('notification_event_object_type', cascade="all, delete-orphan")
        )

        notification_data = Column(JSONType, nullable=False)
        create_date = Column(DateTime, default=datetime.utcnow)

        workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=True)
        workspace = relationship(
            'Workspace',
            backref=backref('notification_event_workspace', cascade="all, delete-orphan"),
        )

        @property
        def parent(self):
            return


    class NotificationBase(db.Model):
        __tablename__ = 'notification_base'
        id = Column(Integer, primary_key=True)
        notification_event_id = Column(Integer, ForeignKey('notification_event.id', ondelete="CASCADE"), index=True, nullable=False)
        notification_event = relationship(
            'NotificationEvent',
            backref=backref('notifications', cascade="all, delete-orphan"),
        )
        notification_subscription_config_id = Column(Integer, ForeignKey('notification_subscription_config_base.id'),
                                                     index=True, nullable=False)
        notification_subscription_config = relationship(
            'NotificationSubscriptionConfigBase',
            backref=backref('notifications', cascade="all, delete-orphan"),
        )

        type = Column(String(24))

        __mapper_args__ = {
            'polymorphic_on': type,
            'polymorphic_identity': 'base'
        }


    # TBI
    class MailNotification(NotificationBase):
        __tablename__ = 'mail_notification'

        id = Column(Integer, ForeignKey('notification_base.id'), primary_key=True)

        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[0]
        }


    # TBI
    class WebHookNotification(NotificationBase):
        __tablename__ = 'webhook_notification'

        id = Column(Integer, ForeignKey('notification_base.id'), primary_key=True)

        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[1]
        }


    class WebsocketNotification(NotificationBase):
        __tablename__ = 'websocket_notification'

        id = Column(Integer, ForeignKey('notification_base.id', ondelete='CASCADE'), primary_key=True)
        user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True)
        user_notified = relationship(
            'User',
            backref=backref('notifications', cascade="all, delete-orphan")
        )

        mark_read = Column(Boolean, default=False, index=True)

        __mapper_args__ = {
            'polymorphic_identity': NOTIFICATION_METHODS[2]
        }


    class Notification(db.Model):
        __tablename__ = 'notification'
        id = Column(Integer, primary_key=True)
        user_notified_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=False)
        user_notified = relationship(
            'User',
            backref=backref('notification', cascade="all, delete-orphan"),
            # primaryjoin="User.id == Notification.user_notified_id"
        )

        object_id = Column(Integer, nullable=False)
        object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)
        notification_text = Column(Text, nullable=False)

        workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
        workspace = relationship(
            'Workspace',
            backref=backref('notification', cascade="all, delete-orphan"),
            # primaryjoin="Notification.id == Notification.workspace_id"
        )

        mark_read = Column(Boolean, default=False, index=True)
        create_date = Column(DateTime, default=datetime.utcnow)

        @property
        def parent(self):
            return

    class BaseNotification(Metadata):
        __tablename__ = "base_notification"

        id = Column(Integer, primary_key=True)
        data = Column(JSONType, nullable=False)
        processed = Column(Boolean, default=False)
        verbose = Column(Boolean, default=False)

        def __repr__(self):
            return f"Notification ID:{self.id}, type:{self.data.get('type')}, subtype:{self.data.get('subtype')}"


    class UserNotification(Metadata):
        __tablename__ = "user_notification"

        id = Column(Integer, primary_key=True)
        message = Column(Text, nullable=False)
        extra_data = Column(JSONType, nullable=True)
        type = Column(String, nullable=False)
        subtype = Column(String, nullable=False)
        read = Column(Boolean, default=False)
        triggered_by = Column(JSONType)
        user_id = Column(Integer, ForeignKey('faraday_user.id'), index=True, nullable=False)
        user = relationship('User',
                            backref=backref('user_notifications', cascade="all, delete-orphan"),
                            foreign_keys=[user_id])
        links_to = Column(JSONType, nullable=True)
        event_date = Column(DateTime, default=datetime.utcnow(), nullable=False)

        __table_args__ = (
            Index(
                'ix_user_notification_user_id_unread',
                'user_id',
                postgresql_where=text('read = false'),
            ),
        )

        def mark_as_read(self):
            self.read = True

        def __repr__(self):
            return f"{self.message}"


    class UserNotificationSettings(Metadata):
        __tablename__ = 'user_notification_settings'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('faraday_user.id'))
        user = relationship('User',
                            backref=backref('notification_settings', uselist=False, cascade="all, delete-orphan"),
                            foreign_keys=[user_id])

        paused = Column(Boolean, default=False)
        slack_id = Column(String, nullable=True, default=None)
        no_self_notify = Column(Boolean, default=False)

        agents_enabled = Column(Boolean, default=True)
        agents_app = Column(Boolean, default=True)
        agents_email = Column(Boolean, default=False)
        agents_slack = Column(Boolean, default=False)

        analytics_enabled = Column(Boolean, default=True)
        analytics_app = Column(Boolean, default=True)
        analytics_email = Column(Boolean, default=False)
        analytics_slack = Column(Boolean, default=False)

        cli_enabled = Column(Boolean, default=True)
        cli_app = Column(Boolean, default=True)
        cli_email = Column(Boolean, default=False)
        cli_slack = Column(Boolean, default=False)

        comments_enabled = Column(Boolean, default=True)
        comments_app = Column(Boolean, default=True)
        comments_email = Column(Boolean, default=False)
        comments_slack = Column(Boolean, default=False)

        hosts_enabled = Column(Boolean, default=True)
        hosts_app = Column(Boolean, default=True)
        hosts_email = Column(Boolean, default=False)
        hosts_slack = Column(Boolean, default=False)

        users_enabled = Column(Boolean, default=True)
        users_app = Column(Boolean, default=True)
        users_email = Column(Boolean, default=False)
        users_slack = Column(Boolean, default=False)

        reports_enabled = Column(Boolean, default=True)
        reports_app = Column(Boolean, default=True)
        reports_email = Column(Boolean, default=False)
        reports_slack = Column(Boolean, default=False)

        ws_sum_reports_enabled = Column(Boolean, default=True)
        ws_sum_reports_app = Column(Boolean, default=True)
        ws_sum_reports_email = Column(Boolean, default=False)
        ws_sum_reports_slack = Column(Boolean, default=False)

        vulnerabilities_enabled = Column(Boolean, default=True)
        vulnerabilities_app = Column(Boolean, default=True)
        vulnerabilities_email = Column(Boolean, default=False)
        vulnerabilities_slack = Column(Boolean, default=False)

        workspaces_enabled = Column(Boolean, default=True)
        workspaces_app = Column(Boolean, default=True)
        workspaces_email = Column(Boolean, default=False)
        workspaces_slack = Column(Boolean, default=False)

        pipelines_enabled = Column(Boolean, default=True)
        pipelines_app = Column(Boolean, default=True)
        pipelines_email = Column(Boolean, default=False)
        pipelines_slack = Column(Boolean, default=False)

        executive_reports_enabled = Column(Boolean, default=True)
        executive_reports_app = Column(Boolean, default=True)
        executive_reports_email = Column(Boolean, default=False)
        executive_reports_slack = Column(Boolean, default=False)

        planner_enabled = Column(Boolean, default=True)
        planner_app = Column(Boolean, default=True)
        planner_email = Column(Boolean, default=False)
        planner_slack = Column(Boolean, default=False)

        integrations_enabled = Column(Boolean, default=True)
        integrations_app = Column(Boolean, default=True)
        integrations_email = Column(Boolean, default=False)
        integrations_slack = Column(Boolean, default=False)

        other_enabled = Column(Boolean, default=True)
        other_app = Column(Boolean, default=True)
        other_email = Column(Boolean, default=False)
        other_slack = Column(Boolean, default=False)

        adv_high_crit_vuln_enabled = Column(Boolean, default=False)
        adv_high_crit_vuln_app = Column(Boolean, default=False)
        adv_high_crit_vuln_email = Column(Boolean, default=False)
        adv_high_crit_vuln_slack = Column(Boolean, default=False)
        adv_high_crit_vuln = Column(Boolean, default=False)

        adv_risk_score_threshold_enabled = Column(Boolean, default=False)
        adv_risk_score_threshold_app = Column(Boolean, default=False)
        adv_risk_score_threshold_email = Column(Boolean, default=False)
        adv_risk_score_threshold_slack = Column(Boolean, default=False)
        adv_risk_score_threshold = Column(Integer, default=0)

        adv_vuln_open_days_critical_enabled = Column(Boolean, default=False)
        adv_vuln_open_days_critical_app = Column(Boolean, default=False)
        adv_vuln_open_days_critical_email = Column(Boolean, default=False)
        adv_vuln_open_days_critical_slack = Column(Boolean, default=False)
        adv_vuln_open_days_critical = Column(Integer, default=0)

        adv_vuln_open_days_high_enabled = Column(Boolean, default=False)
        adv_vuln_open_days_high_app = Column(Boolean, default=False)
        adv_vuln_open_days_high_email = Column(Boolean, default=False)
        adv_vuln_open_days_high_slack = Column(Boolean, default=False)
        adv_vuln_open_days_high = Column(Integer, default=0)

        adv_vuln_open_days_medium_enabled = Column(Boolean, default=False)
        adv_vuln_open_days_medium_app = Column(Boolean, default=False)
        adv_vuln_open_days_medium_email = Column(Boolean, default=False)
        adv_vuln_open_days_medium_slack = Column(Boolean, default=False)
        adv_vuln_open_days_medium = Column(Integer, default=0)

        adv_vuln_open_days_low_enabled = Column(Boolean, default=False)
        adv_vuln_open_days_low_app = Column(Boolean, default=False)
        adv_vuln_open_days_low_email = Column(Boolean, default=False)
        adv_vuln_open_days_low_slack = Column(Boolean, default=False)
        adv_vuln_open_days_low = Column(Integer, default=0)


    class EmailNotification(db.Model):
        id = Column(Integer, primary_key=True)
        user_email = Column(String, nullable=False)
        message = Column(String, nullable=False)
        processed = Column(Boolean, default=False)


    class SlackNotification(db.Model):
        id = Column(Integer, primary_key=True)
        slack_id = Column(String, nullable=False)
        message = Column(String, nullable=False)
        processed = Column(Boolean, default=False)


if 'comment' in db.metadata.tables:
    # Ciclo domain-first: server.models ya definió Comment via fallback.
    from faraday.server.models import Comment  # noqa: F401
else:
    class Comment(Metadata):
        __tablename__ = 'comment'
        id = Column(Integer, primary_key=True)
        comment_type = Column(Enum(*COMMENT_TYPES, name='comment_types'), nullable=False, default='user')

        text = BlankColumn(Text)

        reply_to_id = Column(Integer, ForeignKey('comment.id', ondelete='SET NULL'))
        reply_to = relationship(
            'Comment',
            remote_side=[id],
            foreign_keys=[reply_to_id]
        )

        workspace_id = Column(Integer, ForeignKey('workspace.id', ondelete="CASCADE"), index=True, nullable=True)
        workspace = relationship(
            'Workspace',
            foreign_keys=[workspace_id],
            backref=backref('comments', cascade="all, delete-orphan"),
        )

        object_id = Column(Integer, nullable=False)
        object_type = Column(Enum(*OBJECT_TYPES, name='object_types'), nullable=False)

        @property
        def parent(self):
            return


__all__ = ['Comment', 'ExecutiveReport', 'EventType', 'NotificationSubscription', 'NotificationSubscriptionConfigBase', 'NotificationSubscriptionMailConfig', 'NotificationSubscriptionWebHookConfig', 'NotificationSubscriptionWebSocketConfig', 'NotificationEvent', 'NotificationBase', 'MailNotification', 'WebHookNotification', 'WebsocketNotification', 'Notification', 'BaseNotification', 'UserNotification', 'UserNotificationSettings', 'EmailNotification', 'SlackNotification']
