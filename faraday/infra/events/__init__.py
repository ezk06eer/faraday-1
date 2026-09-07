"""
Event bus abstraction — replaces Queue() global in faraday/server/events.py (E2-A8)

Deterministic port: EventPublisher interface.
Current impl wraps the existing Queue for backwards compat.
Future: Redis pub/sub or in-memory.
"""

from abc import ABC, abstractmethod
from queue import Queue
from typing import Any


class EventPublisher(ABC):
    @abstractmethod
    def publish(self, event: Any) -> None: ...

    @abstractmethod
    def subscribe(self): ...


class QueueEventPublisher(EventPublisher):
    def __init__(self, queue: Queue | None = None):
        self.queue = queue or Queue()

    def publish(self, event: Any) -> None:
        self.queue.put(event)

    def subscribe(self):
        return self.queue
