"""
SortingService — extracted from faraday/server/api/base.py:SortableMixin (E2-A4)

Pure function, deterministic: same request.args -> same order field.
Validates against schema fields and model attrs (whitelist).
Import-safe: sqlalchemy import deferred inside function to avoid import cycles in tests without deps.
"""
import logging
from flask import request

from faraday.server.api.base import InvalidUsage

logger = logging.getLogger(__name__)


class SortingService:
    sort_field_parameter_name = "sort"
    sort_direction_parameter_name = "sort_dir"
    sort_pass_silently = False
    default_sort_direction = "asc"

    @staticmethod
    def get_order_field(view, **kwargs):
        from sqlalchemy.inspection import inspect
        try:
            order_field = request.args[SortingService.sort_field_parameter_name]
        except KeyError:
            return view.order_field
        schema = view._get_schema_instance(kwargs)
        try:
            metadata_field = schema.fields.pop("metadata")
        except KeyError:
            pass
        else:
            for key, value in metadata_field.target_schema.fields.items():
                schema.fields["metadata." + key] = value
                schema.fields[key] = value
        try:
            field_instance = schema.fields[order_field]
        except KeyError as e:
            if view.sort_pass_silently:
                logger.warning(f"Unknown field: {order_field}")
                return view.order_field
            raise InvalidUsage(f"Unknown field: {order_field}") from e
        order_field = field_instance.attribute or order_field
        model_class = getattr(view, "sort_model_class", None) or view.model_class
        if order_field not in inspect(model_class).attrs:
            if view.sort_pass_silently:
                logger.warning(f"Field not in the DB: {order_field}")
                return view.order_field
            raise InvalidUsage(f"Field not in the DB: {order_field}")
        if hasattr(model_class, order_field + "_id"):
            field = getattr(model_class, order_field + "_id")
        else:
            field = getattr(model_class, order_field)
        sort_dir = request.args.get(
            SortingService.sort_direction_parameter_name, SortingService.default_sort_direction
        )
        if sort_dir not in ("asc", "desc"):
            if view.sort_pass_silently:
                logger.warning(f"Invalid value for sorting direction: {sort_dir}")
                return view.order_field
            raise InvalidUsage(f"Invalid value for sorting direction: {sort_dir}")
        try:
            if view.order_field is not None:
                if not isinstance(view.order_field, tuple):
                    view.order_field = (view.order_field,)
                return (getattr(field, sort_dir)(),) + view.order_field
            return getattr(field, sort_dir)()
        except NotImplementedError as e:
            if view.sort_pass_silently:
                logger.warning(f"field {order_field} doesn't support sorting")
                return view.order_field
            raise InvalidUsage(f"field {order_field} doesn't support sorting") from e
