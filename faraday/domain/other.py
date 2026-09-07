"""Domain other — 13 clases cajón deuda (reshard Permissions->user_auth, Analytics->reporting).

YAGNI: reshard progresivo. Ver /tmp/domain_shards.json other.
"""
# TODO ponytail: mover SearchFilter, Configuration, etc. (13 restantes)
from faraday.server.models import Metadata  # noqa: F401

__all__ = ["Metadata"]
