"""
FilteringService — extracted from faraday/server/api/base.py:FilterAlchemyMixin / FilterMixin (E2-A4)

Deterministic wrapper, import-safe: webargs deferred.
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
