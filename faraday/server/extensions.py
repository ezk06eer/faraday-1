"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

Infra extensions — Dependency Injection migration
-------------------------------------------------
Este módulo expone la infraestructura compartida SocketIO / Celery.

Migración a DI determinístico (E1-A2):
* Legacy (deprecated): los singletons de módulo ``socketio`` y ``celery``
  se mantienen para compatibilidad backwards. Todo código existente que hace
  ``from faraday.server.extensions import socketio, celery`` sigue funcionando.
  Están marcados como *deprecated* y serán removidos en una versión futura;
  nuevo código debe preferir las factories.
* Preferred (DI): usar las factories ``create_socketio(app=None)``,
  ``create_celery(app=None)`` e ``init_extensions(app)``. Cada factory
  crea/retorna una instancia configurada de forma determinística sin efectos
  globales extra, salvo ``init_extensions`` que inicializa los singletons
  legacy contra la app Flask dada (útil para el app factory). Todas son
  import-safe: importar este módulo no lee config ni hace I/O.
* Determinismo: mismo input → mismo output; no random, no side effects en
  import; ``create_*`` siempre retorna instancias nuevas e independientes.
"""
# Related third party imports
from flask_socketio import SocketIO

from flask_celery import Celery

# ---------------------------------------------------------------------------
# Legacy singletons — DEPRECATED
# Mantener exactamente la misma inicialización para no romper imports
# existentes (faraday.server.tasks:19, app:63/76, agent:32, etc.).
# Nuevo código: preferir create_socketio() / create_celery() / init_extensions().
# ---------------------------------------------------------------------------
socketio = SocketIO(cors_allowed_origins='*', engineio_logger=True)  # deprecated: usar create_socketio()
celery = Celery()  # deprecated: usar create_celery()


def create_socketio(app=None):
    """Factory determinística para SocketIO.

    Crea una instancia nueva de :class:`flask_socketio.SocketIO` con la
    misma configuración legacy (``cors_allowed_origins='*'``,
    ``engineio_logger=True``).

    Si ``app`` es provista, hace ``init_app`` de forma determinística
    usando ``faraday_server.socketio_*`` cuando está disponible, sin
    registrar namespaces ni iniciar background tasks (eso queda en
    ``faraday.server.app.register_extensions``).

    :param app: instancia Flask opcional.
    :returns: instancia configurada de SocketIO.
    """
    instance = SocketIO(cors_allowed_origins='*', engineio_logger=True)
    if app is not None:
        try:
            from faraday.server.config import faraday_server

            instance.init_app(
                app,
                ping_interval=faraday_server.socketio_ping_interval,
                ping_timeout=faraday_server.socketio_ping_timeout,
                logger=faraday_server.socketio_logger,
            )
        except Exception:
            # Fallback determinístico si config no está disponible (e.g. tests)
            instance.init_app(app)
    return instance


def create_celery(app=None):
    """Factory determinística para Celery.

    Crea una instancia nueva de :class:`flask_celery.Celery` sin argumentos,
    idéntico al singleton legacy. Si ``app`` es provista **y** celery está
    habilitado en config (``faraday_server.celery_enabled``), hace
    ``init_app(app)`` de forma determinística. No hace ``sys.exit`` ni
    valida broker/backend — esa validación queda en el app factory.

    :param app: instancia Flask opcional.
    :returns: instancia configurada de Celery.
    """
    instance = Celery()
    if app is not None:
        try:
            from faraday.server.config import faraday_server

            if getattr(faraday_server, 'celery_enabled', False):
                instance.init_app(app)
        except Exception:
            # Si config no cargable, no inicializar — caller decide
            pass
    return instance


def init_extensions(app):
    """Inicializa los singletons legacy contra la app dada (DI compat).

    Es el helper determinístico para el app factory. Hace
    ``socketio.init_app`` siempre y ``celery.init_app`` solo si
    ``faraday_server.celery_enabled`` es True. No registra namespaces
    ni inicia background tasks — eso lo hace ``register_extensions`` en
    ``faraday.server.app``.

    Import-safe y determinístico: solo lee config dentro de la función,
    sin side effects globales extra más allá de inicializar los singletons.

    :param app: instancia Flask.
    :returns: dict con ``{"socketio": socketio, "celery": celery}``.
    """
    from faraday.server.config import faraday_server

    try:
        socketio.init_app(
            app,
            ping_interval=faraday_server.socketio_ping_interval,
            ping_timeout=faraday_server.socketio_ping_timeout,
            logger=faraday_server.socketio_logger,
        )
    except Exception:
        # Fallback determinístico si config incompleta (e.g. tests con mock)
        try:
            socketio.init_app(app)
        except Exception:
            pass
    if getattr(faraday_server, 'celery_enabled', False):
        try:
            celery.init_app(app)
        except Exception:
            pass
    return {"socketio": socketio, "celery": celery}
