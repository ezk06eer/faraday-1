"""YAGNI shim — re-export desde faraday.server.models (futura extracción). No romper contracts.md"""
from faraday.server.models import SourceCode, Hostname, Host, Service, Credential  # noqa: F401

__all__ = ["SourceCode", "Hostname", "Host", "Service", "Credential"]
