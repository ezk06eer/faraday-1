"""Event bus — YAGNI extraction from faraday/server/events.py:1

Mantiene contrato: changes_queue = Queue() para websockets + SQLAlchemy listeners.
"""
from queue import Queue

# Singleton determinístico (mantiene contrato)
changes_queue = Queue()

def publish_change(event):
    changes_queue.put(event)

def get_queue() -> Queue:
    return changes_queue
