"""Domain other — 6 clases cajón deuda (reshard BaseNotification*->notification).

YAGNI: reshard progresivo.
"""
# TODO ponytail: mover VulnerabilityStatusHistory, CustomAssociationSet, etc. (6 restantes)
from faraday.server.models import Metadata  # noqa: F401

__all__ = ["Metadata"]
