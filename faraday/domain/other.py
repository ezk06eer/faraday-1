"""Domain other — 17 clases cajón deuda (reshard Permissions->user_auth).

YAGNI: reshard progresivo. Ver /tmp/domain_shards.json other.
"""
# TODO ponytail: mover Analytics->reporting, SearchFilter->reporting, etc. (17 restantes)
from faraday.server.models import Metadata  # noqa: F401

__all__ = ["Metadata"]
