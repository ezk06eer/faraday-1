"""
Broker abstraction — TaskQueue port (E2-A8 / E3).

Deterministic interface for Celery. Allows in-memory impl for tests
without Redis, and future Kafka/RabbitMQ swap.

Implementations:
- CeleryTaskQueue: wraps faraday.server.extensions.celery
- InMemoryTaskQueue: synchronous, for unit tests
"""

from abc import ABC, abstractmethod
from typing import Any


class TaskQueue(ABC):
    @abstractmethod
    def delay(self, task_name: str, *args: Any, **kwargs: Any) -> Any: ...

    @abstractmethod
    def chord(self, tasks, callback) -> Any: ...


class CeleryTaskQueue(TaskQueue):
    def __init__(self, celery_app=None):
        if celery_app is None:
            from faraday.server.extensions import celery as _celery

            celery_app = _celery
        self.celery = celery_app

    def delay(self, task_name: str, *args: Any, **kwargs: Any) -> Any:
        task = self.celery.tasks.get(task_name)
        if task is None:
            raise ValueError(f"Task not found: {task_name}")
        return task.delay(*args, **kwargs)

    def chord(self, tasks, callback) -> Any:
        return self.celery.chord(tasks)(callback)


class InMemoryTaskQueue(TaskQueue):
    """Synchronous in-memory queue for deterministic tests."""

    def delay(self, task_name: str, *args: Any, **kwargs: Any) -> Any:
        from faraday.server.extensions import celery as _celery

        task = _celery.tasks.get(task_name)
        if task is None:
            raise ValueError(f"Task not found: {task_name}")
        return task.apply(args=args, kwargs=kwargs)

    def chord(self, tasks, callback) -> Any:
        # Execute synchronously
        results = [t.apply().get() for t in tasks]
        return callback(results)
