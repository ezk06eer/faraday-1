"""
HostCreationService — anti-corruption layer for faraday/server/tasks.py:209 E2-A8

Breaks cycle: tasks.py -> api.modules.bulk_create -> tasks

Deterministic: lazy import only when needed, explicit workspace/host/command args.
"""
from typing import Any, Dict


def create_host_via_service(workspace, host: Dict[str, Any], command: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic wrapper around _create_host. Defer import to avoid cycle."""
    from faraday.server.api.modules.bulk_create import _create_host  # pylint: disable=import-outside-toplevel

    return _create_host(workspace, host, command)
