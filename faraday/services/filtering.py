"""
FilteringService — extracted from faraday/server/api/base.py:FilterAlchemyMixin / FilterMixin (E2-A4)

Deterministic wrapper, import-safe: webargs deferred.
Pure helpers for pagination without DB.
"""
class FilteringService:
    @staticmethod
    def filter_query_alchemy(view, query):
        assert view.filterset_class is not None, "You must define a filterset"
        return view.filterset_class(query).filter()

    @staticmethod
    def translate_filters(view, filters):
        if hasattr(view, "_translate_filters"):
            return view._translate_filters(filters)
        return filters, None

    @staticmethod
    def extract_pagination(filters: dict):
        """Pure: extract offset/limit from parsed filters dict without DB.

        Mutates filters (pops offset/limit) and returns (filters, offset, limit).
        """
        offset = 0
        limit = None
        if "offset" in filters:
            offset = filters.pop("offset")
        if "limit" in filters:
            limit = filters.pop("limit")
        return filters, offset, limit

    @staticmethod
    def parse_filter_pagination(filters: dict):
        """Pure alias for extract_pagination (test-friendly name)."""
        return FilteringService.extract_pagination(filters)
