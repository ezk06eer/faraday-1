"""Domain other — 2 clases restantes (CustomAssociationSet helper + Metadata base).

YAGNI: other vaciado 21->2, listo para eliminar cuando Metadata se extraiga a faraday/domain/base.py
"""
from faraday.server.models import Metadata  # noqa: F401
# CustomAssociationSet es helper, no modelo — se queda aquí hasta extraer a base
from faraday.server.models import CustomAssociationSet  # noqa: F401

__all__ = ["Metadata", "CustomAssociationSet"]
