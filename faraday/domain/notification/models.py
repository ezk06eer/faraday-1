"""YAGNI shim — re-export notification."""
from faraday.server.models import (  # noqa: F401
    ExecutiveReport, EventType, NotificationSubscription, NotificationSubscriptionConfigBase,
    NotificationSubscriptionMailConfig, NotificationSubscriptionWebHookConfig, NotificationSubscriptionWebSocketConfig,
    NotificationEvent, NotificationBase, MailNotification, WebHookNotification, Notification,
)
__all__ = ["ExecutiveReport", "EventType", "NotificationSubscription", "NotificationSubscriptionConfigBase", "NotificationSubscriptionMailConfig", "NotificationSubscriptionWebHookConfig", "NotificationSubscriptionWebSocketConfig", "NotificationEvent", "NotificationBase", "MailNotification", "WebHookNotification", "Notification"]
