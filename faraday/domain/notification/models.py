"""Domain notification — Comment real (shard desde faraday/server/models.py).

Comment vive aquí como definición real; faraday/server/models.py mantiene
shim try/except (DOMAIN_COMMENT_AVAILABLE) con fallback, siguiendo el patrón
de DOMAIN_HOST_AVAILABLE / DOMAIN_COMMAND_AVAILABLE.

Las relaciones a Workspace y al self-reference usan string references de
SQLAlchemy ('Workspace', 'Comment') para evitar ciclos. Los nombres de
faraday.server.models (BlankColumn/Metadata/COMMENT_TYPES/OBJECT_TYPES) se
importan con el patrón de import parcial igual que faraday/domain/command:
cuando este módulo es cargado desde el shim de server.models, esos nombres ya
están definidos en ese módulo.

El resto de clases de notification sigue siendo shim YAGNI re-export.
"""
import sys

from sqlalchemy import Column, Enum, ForeignKey, Integer, Text
from sqlalchemy.orm import backref, relationship

from faraday.server.models import (  # import parcial: nombres ya definidos antes del shim
    BlankColumn,
    COMMENT_TYPES,
    OBJECT_TYPES,
    Metadata,
)


_sm = sys.modules.get('faraday.server.models')
_existing_comment = getattr(_sm, 'Comment', None) if _sm is not None else None

if _existing_comment is not None:
    # Orden domain-first: server.models ya cargó completo con el fallback del
    # shim; reutilizar esa clase para mantener identidad (dn.Comment is s.Comment)
    # y no redefinir la tabla 'comment'.
    Comment = _existing_comment
    _sm.DOMAIN_COMMENT_AVAILABLE = True
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

# Shim YAGNI (resto de notification todavía vive en faraday/server/models.py).
try:
    from faraday.server.models import (  # noqa: F401
        ExecutiveReport, EventType, NotificationSubscription, NotificationSubscriptionConfigBase,
        NotificationSubscriptionMailConfig, NotificationSubscriptionWebHookConfig,
        NotificationSubscriptionWebSocketConfig, NotificationEvent, NotificationBase,
        MailNotification, WebHookNotification, Notification, BaseNotification, UserNotification,
        UserNotificationSettings, EmailNotification, SlackNotification,
    )
except ImportError:
    pass

__all__ = ["Comment", "ExecutiveReport", "EventType", "NotificationSubscription", "NotificationSubscriptionConfigBase", "NotificationSubscriptionMailConfig", "NotificationSubscriptionWebHookConfig", "NotificationSubscriptionWebSocketConfig", "NotificationEvent", "NotificationBase", "MailNotification", "WebHookNotification", "Notification", "BaseNotification", "UserNotification", "UserNotificationSettings", "EmailNotification", "SlackNotification"]
