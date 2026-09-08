"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""Filtros webargs/filteralchemy de vulnerabilidades (P4b, extraído de vulns_base)."""
from filteralchemy import Filter, FilterSet, operators
from flask import request
from marshmallow import fields
from marshmallow.validate import OneOf
from sqlalchemy.orm import (
    aliased,
)
from werkzeug.datastructures import ImmutableMultiDict
from faraday.server.api.base import (
    FilterSetMeta,
)
try:
    from faraday.domain.vulnerability.models import VulnerabilityGeneric
except ImportError:
    from faraday.server.models import VulnerabilityGeneric
from faraday.server.models import (
    Host,
    Hostname,
    Service,
    Vulnerability,
    VulnerabilityWeb,
)
from faraday.server.schemas import (
    SeverityField,
)
from faraday.server.utils.vulns import (
    FILTER_SET_FIELDS,
    FILTER_SET_STRICT_FIELDS,
)

_strict_filtering = {'default_operator': operators.Equal}

class IDFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.id == value)

class StatusCodeFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.status_code == value)

class TargetFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.target_host_ip == value)

class TypeFilter(Filter):
    def filter(self, query, model, attr, value):
        type_map = {
            'Vulnerability': 'vulnerability',
            'VulnerabilityWeb': 'vulnerability_web',
        }
        assert value in type_map
        return query.filter(model.__table__.c.type == type_map[value])

class CreatorFilter(Filter):
    def filter(self, query, model, attr, value):
        return query.filter(model.creator_command_tool.ilike(
            '%' + value + '%'))

class ServiceFilter(Filter):
    def filter(self, query, model, attr, value):
        alias = aliased(Service, name='service_filter')
        return query.join(
            alias,
            alias.id == model.__table__.c.service_id).filter(
            alias.name == value
        )

class HostnamesFilter(Filter):
    def filter(self, query, model, attr, value):
        alias = aliased(Hostname, name='hostname_filter')

        value_list = value.split(",")

        service_hostnames_query = query.join(Service, Service.id == Vulnerability.service_id). \
            join(Host). \
            join(alias). \
            filter(alias.name.in_(value_list))

        host_hostnames_query = query.join(Host, Host.id == Vulnerability.host_id). \
            join(alias). \
            filter(alias.name.in_(value_list))

        query = service_hostnames_query.union(host_hostnames_query)
        return query

class CustomILike(operators.Operator):
    """A filter operator that puts a % in the beginning and in the
    end of the search string to force a partial search"""

    def __call__(self, query, model, attr, value):
        column = getattr(model, attr)
        condition = column.ilike('%' + value + '%')
        return query.filter(condition)

class VulnerabilityFilterSet(FilterSet):
    class Meta(FilterSetMeta):
        model = VulnerabilityWeb  # It has all the fields
        fields = FILTER_SET_FIELDS
        strict_fields = FILTER_SET_STRICT_FIELDS
        default_operator = CustomILike
        column_overrides = {field: _strict_filtering for field in strict_fields}
        operators = (CustomILike, operators.Equal)

    id = IDFilter(fields.Int())
    target = TargetFilter(fields.Str())
    type = TypeFilter(fields.Str(validate=[OneOf(['Vulnerability', 'VulnerabilityWeb'])]))
    creator = CreatorFilter(fields.Str())
    service = ServiceFilter(fields.Str())
    severity = Filter(SeverityField())
    ease_of_resolution = Filter(fields.String(
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True))
    status_code = StatusCodeFilter(fields.Int())
    status = Filter(fields.Function(
        deserialize=lambda val: 'open' if val == 'opened' else val,
        validate=OneOf(Vulnerability.STATUSES + ['opened'])
    ))
    hostnames = HostnamesFilter(fields.Str())
    confirmed = Filter(fields.Boolean())

    def filter(self):
        """Generate a filtered query from request parameters.

        :returns: Filtered SQLAlchemy query
        """
        # TODO migration: this can became a normal filter instead of a custom
        # one, since now we can use creator_command_id
        command_id = request.args.get('command_id')

        # The web UI uses old field names. Translate them into the new field
        # names to maintain backwards compatibility
        param_mapping = {
            'query': 'query_string',
            'pname': 'parameter_name',
            'params': 'parameters',
            'easeofresolution': 'ease_of_resolution',
        }
        new_args = request.args.copy()
        for (old_param, real_param) in param_mapping.items():
            try:
                new_args[real_param] = request.args[old_param]
            except KeyError:
                pass
        request.args = ImmutableMultiDict(new_args)

        query = super().filter()

        if command_id:
            # query = query.filter(CommandObject.command_id == int(command_id))
            query = query.filter(VulnerabilityGeneric.creator_command_id
                                 == int(command_id))  # TODO migration: handle invalid int()
        return query
