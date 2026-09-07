"""Domain other — 21 clases cajón deuda (Metadata, CustomAssociationSet, etc.)

YAGNI: reshard progresivo. Ver /tmp/domain_shards.json other.
No romper contracts.md; estas clases no son contrato wire directo.
"""
# TODO ponytail: mover PermissionsGroup->user_auth, Analytics->reporting, etc.
from faraday.server.models import Metadata  # noqa: F401  # base

__all__ = ["Metadata"]
