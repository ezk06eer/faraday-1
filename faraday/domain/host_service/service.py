"""Host domain service — YAGNI extraction from faraday/server/models.py:1352 Host.set_hostnames"""
from typing import List

def set_host_hostnames(host, new_hostnames: List[str]):
    from faraday.server.models import set_children_objects  # lazy
    return set_children_objects(host, new_hostnames, parent_field="hostnames", child_field="name")
