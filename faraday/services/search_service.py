"""
SearchService — extracted from faraday/server/utils/search.py:1 (1042L) E2-A9

Deterministic wrapper, import-safe: sqlalchemy deferred.
Shim delegates to utils/search for now, future: pure repo query builder.
"""
from typing import Any

class SearchService:
    @staticmethod
    def search(session, model_class, filters: dict) -> Any:
        from faraday.server.utils.search import search
        return search(session, model_class, filters)

    @staticmethod
    def search_retrieve_only_ids(session, model_class, filters: dict) -> Any:
        from faraday.server.utils.search import search_retrieve_only_ids
        return search_retrieve_only_ids(session, model_class, filters)

    @staticmethod
    def delete_returning_only_ids(session, model_class, filters: dict) -> Any:
        from faraday.server.utils.search import delete_returning_only_ids
        return delete_returning_only_ids(session, model_class, filters)
