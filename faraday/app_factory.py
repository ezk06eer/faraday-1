"""
App Factory — Modulith entry point (E3)

Deterministic factory that composes bounded contexts without monolith coupling.
Import-safe: defers faraday.server.app imports.
"""
def create_app(*args, **kwargs):
    from faraday.server.app import create_app as _create_app
    return _create_app(*args, **kwargs)

def get_app(*args, **kwargs):
    from faraday.server.app import get_app as _get_app
    return _get_app(*args, **kwargs)

def get_debouncer(*args, **kwargs):
    from faraday.server.app import get_debouncer as _get_debouncer
    return _get_debouncer(*args, **kwargs)

__all__ = ["create_app", "get_app", "get_debouncer"]
