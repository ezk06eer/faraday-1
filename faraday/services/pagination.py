"""
PaginationService — extracted from faraday/server/api/base.py:PaginatedMixin (E2-A4)

Deterministic, no global state. Wraps query.paginate.
"""
from flask import abort, request
from http.client import NOT_FOUND as HTTP_NOT_FOUND


class PaginationService:
    per_page_parameter_name = "page_size"
    page_number_parameter_name = "page"

    @staticmethod
    def paginate(query, hard_limit=0):
        page, per_page = None, None
        if PaginationService.per_page_parameter_name in request.args:
            try:
                page = int(request.args.get(PaginationService.page_number_parameter_name, 1))
            except (TypeError, ValueError):
                abort(HTTP_NOT_FOUND, "Invalid page number")
            try:
                per_page = int(request.args[PaginationService.per_page_parameter_name])
            except (TypeError, ValueError):
                abort(HTTP_NOT_FOUND, "Invalid per_page value")
            pagination_metadata = query.paginate(page=page, per_page=per_page, error_out=False)
            return pagination_metadata.items, pagination_metadata
        elif hard_limit != 0:
            pagination_metadata = query.paginate(page=1, per_page=hard_limit, error_out=False)
            return pagination_metadata.items, pagination_metadata
        return query, None
