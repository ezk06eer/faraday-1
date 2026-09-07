"""
WebSocket abstraction — wraps flask_socketio SocketIO (E2-A8)

Deterministic port for DispatcherNamespace.
"""

from abc import ABC, abstractmethod
from typing import Any


class WebSocketGateway(ABC):
    @abstractmethod
    def emit(self, event: str, data: Any, room: str | None = None) -> None: ...

    @abstractmethod
    def join_room(self, room: str, sid: str) -> None: ...


class SocketIOGateway(WebSocketGateway):
    def __init__(self, socketio=None):
        if socketio is None:
            from faraday.server.extensions import socketio as _socketio

            socketio = _socketio
        self.socketio = socketio

    def emit(self, event: str, data: Any, room: str | None = None) -> None:
        self.socketio.emit(event, data, room=room)

    def join_room(self, room: str, sid: str) -> None:
        from flask_socketio import join_room as _join

        _join(room, sid=sid)
