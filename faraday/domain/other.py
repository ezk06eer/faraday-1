"""Domain other — 11 clases cajón deuda (reshard SearchFilter+Configuration->reporting).

YAGNI: reshard progresivo. Ver /tmp/domain_shards.json other.
"""
# TODO ponytail: mover BaseNotification, UserNotification, etc. (11 restantes)
from faraday.server.models import Metadata  # noqa: F401

__all__ = ["Metadata"]
