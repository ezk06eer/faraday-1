"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import sys

from faraday.server.config import faraday_server


def require_celery_enabled(process_name: str) -> None:
    """Abort when celery is disabled.

    Without it the celery object never gets the app config, so the process
    would start against celery's default broker with an empty schedule and
    no registered tasks, without logging any error.
    """
    if not faraday_server.celery_enabled:
        print(f"In order to run faraday {process_name} you must set "
              f"`celery_enabled=True` in your server.ini")
        sys.exit(1)
