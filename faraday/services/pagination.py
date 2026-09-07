"""
PaginationService — extracted from faraday/server/api/base.py:PaginatedMixin (E2-A4)

Deterministic, no global state. Wraps query.paginate.
Pure helpers (no DB) for unit tests: parse_params.
"""
from flask import abort, request
from http.client import NOT_FOUND as HTTP_NOT_FOUND


class PaginationService:
    per_page_parameter_name = "page_size"
    page_number_parameter_name = "page"

    @staticmethod
    def parse_params(args: dict, hard_limit: int = 0):
        """Pure: parse pagination from args dict without DB/request.

        Returns (page, per_page) or (None, None) or (1, hard_limit).
        Raises ValueError on invalid ints (caller maps to 404).
        """
        if PaginationService.per_page_parameter_name in args:
            try:
                page = int(args.get(PaginationService.page_number_parameter_name, 1))
            except (TypeError, ValueError) as e:
                raise ValueError("Invalid page number") from e
            try:
                per_page = int(args[PaginationService.per_page_parameter_name])
            except (TypeError, ValueError) as e:
                raise ValueError("Invalid per_page value") from e
            return page, per_page
        if hard_limit != 0:
            return 1, hard_limit
        return None, None

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
