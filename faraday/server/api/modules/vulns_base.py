"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""VulnerabilityView + blueprint (P4b: schemas y filtros viven en sus módulos)."""
from base64 import b64decode
from datetime import datetime
from http.client import (
    BAD_REQUEST as HTTP_BAD_REQUEST,
    FORBIDDEN as HTTP_FORBIDDEN,
    NOT_FOUND as HTTP_NOT_FOUND,
    OK as HTTP_OK,
)
from imghdr import what
from io import BytesIO
from json import dumps as json_dumps, loads as json_loads
from json.decoder import JSONDecodeError
from logging import getLogger
from pathlib import Path
from depot.manager import DepotManager
from flask import Blueprint, abort, jsonify, make_response, request, send_file
from flask_classful import route
from flask_login import current_user
from marshmallow import ValidationError
from sqlalchemy import desc, func
from sqlalchemy.exc import DataError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import (
    joinedload,
    noload,
    selectin_polymorphic,
    selectinload,
    undefer,
)
from sqlalchemy.orm.exc import NoResultFound
from wtforms import ValidationError as WTFormsValidationError
from faraday.server.api.base import (
    BulkDeleteMixin,
    BulkUpdateMixin,
    ContextMixin,
    CountMultiWorkspacedMixin,
    FilterAlchemyMixin,
    InvalidUsage,
    PaginatedMixin,
    ReadOnlyView,
    get_filtered_data,
    get_workspace,
)
from faraday.server.config import faraday_server
from faraday.server.debouncer import debounce_workspace_update
from faraday.server.fields import FaradayUploadedFile
try:
    from faraday.domain.vulnerability.models import VulnerabilityGeneric
except ImportError:
    from faraday.server.models import VulnerabilityGeneric
from faraday.server.models import (
    CustomFieldsSchema,
    File,
    Host,
    Service,
    User,
    Vulnerability,
    VulnerabilityABC,
    VulnerabilityReference,
    VulnerabilityWeb,
    Workspace,
    db,
)
from faraday.server.utils.csrf import validate_file
from faraday.server.utils.cwe import create_cwe
from faraday.server.utils.database import get_or_create
from faraday.server.utils.export import export_vulns_to_csv, export_vulns_to_csv_limited
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.utils.search import search
from faraday.server.utils.vulns import (
    LARGE_VULN_FIELDS,
    bulk_update_custom_attributes,
    VALID_FILTER_VULN_COLUMNS,
)
from faraday.settings import get_settings

# P4b: re-exports para compatibilidad (los consumidores siguen importando
# VulnerabilitySchema/FilterSet etc. desde vulns_base — wire intacto)
from faraday.server.api.modules.vulns_schemas import (  # noqa: F401
    EvidenceSchema,
    ImpactSchema,
    PatchAttachmentSchema,
    CustomMetadataSchema,
    CVESchema,
    CVSS2Schema,
    CVSS3Schema,
    CVSS4Schema,
    RiskSchema,
    CWESchema,
    OWASPSchema,
    ReferenceSchema,
    VulnerabilitySchema,
    VulnerabilityWebSchema,
)
from faraday.server.api.modules.vulns_filters import (  # noqa: F401
    IDFilter,
    StatusCodeFilter,
    TargetFilter,
    TypeFilter,
    CreatorFilter,
    ServiceFilter,
    HostnamesFilter,
    CustomILike,
    VulnerabilityFilterSet,
)

vulns_api = Blueprint('vulns_api', __name__)
logger = getLogger(__name__)


def _truncate_large_fields(vulns, limit=100):
    for vuln in vulns:
        for field in LARGE_VULN_FIELDS:
            value = vuln.get(field)
            if isinstance(value, str) and len(value) > limit:
                vuln[field] = value[:limit] + '...'


class VulnerabilityView(
    PaginatedMixin,
    FilterAlchemyMixin,
    ReadOnlyView,
    CountMultiWorkspacedMixin,
    ContextMixin,
    BulkDeleteMixin,
    BulkUpdateMixin,
):
    route_base = 'vulns'
    filterset_class = VulnerabilityFilterSet
    sort_model_class = VulnerabilityWeb  # It has all the fields
    sort_pass_silently = True  # For compatibility with the Web UI
    order_field = desc(VulnerabilityGeneric.confirmed), VulnerabilityGeneric.severity, VulnerabilityGeneric.create_date
    # NOTE: Vulnerability.evidence is intentionally NOT in get_joinedloads because
    # subclasses choose between joinedload(evidence) and noload(evidence) based on
    # the ``get_evidence`` query param. Having both options on the same path is an
    # error in SQLAlchemy 2.0.
    get_joinedloads = [Vulnerability.creator]

    model_class_dict = {
        'Vulnerability': Vulnerability,
        'VulnerabilityWeb': VulnerabilityWeb,
        'VulnerabilityGeneric': VulnerabilityGeneric,  # For listing objects
    }
    schema_class_dict = {
        'Vulnerability': VulnerabilitySchema,
        'VulnerabilityWeb': VulnerabilityWebSchema
    }

    def _get_schema_instance(self, route_kwargs, **kwargs):
        schema = super()._get_schema_instance(route_kwargs, **kwargs)

        return schema

    @staticmethod
    def _process_attachments(obj, attachments):
        old_attachments = db.session.query(File).options(
            joinedload(File.creator),
            joinedload(File.update_user)
        ).filter_by(
            object_id=obj.id,
            object_type='vulnerability',
        )

        for old_attachment in old_attachments:
            db.session.delete(old_attachment)

        for filename, attachment in attachments.items():
            if 'image' in attachment['content_type']:
                image_format = what(None, h=b64decode(attachment['data']))
                if image_format and image_format.lower() == "webp":
                    logger.info("Evidence can not be webp format")
                    abort(HTTP_BAD_REQUEST, "Evidence can not be webp format")

            faraday_file = FaradayUploadedFile(b64decode(attachment['data']))
            filename = filename.replace(" ", "_")
            description = attachment.get('description')
            get_or_create(
                db.session,
                File,
                object_id=obj.id,
                object_type='vulnerability',
                name=Path(filename).stem,
                filename=Path(filename).name,
                content=faraday_file,
                description=description,
            )

    def _perform_bulk_update(self, ids, data, **kwargs):
        returning_rows = [
            VulnerabilityGeneric.id,
            VulnerabilityGeneric.name,
            VulnerabilityGeneric.severity,
            VulnerabilityGeneric.risk,
            VulnerabilityGeneric.host_id,
            Vulnerability.service_id,
        ]
        kwargs['returning'] = returning_rows

        workspace_name = kwargs.get('workspace_name')
        if workspace_name:
            debounce_workspace_update(workspace_name)

        if (len(data) > 0 and len(ids) > 0) and 'custom_fields' in data.keys():
            return bulk_update_custom_attributes(ids, data)
        return super()._perform_bulk_update(ids, data, **kwargs)

    def _get_eagerloaded_query(self, *args, **kwargs):
        """
        Eager hostnames loading.
        This is too complex to get_joinedloads, so I have to override the function.
        """
        query = super()._get_eagerloaded_query(*args, **kwargs)
        options = [
            joinedload(Vulnerability.host).
            load_only(Host.id).  # Only hostnames are needed
            selectinload(Host.hostnames),

            joinedload(Vulnerability.service).
            joinedload(Service.host).
            selectinload(Host.hostnames),

            joinedload(VulnerabilityWeb.service).
            joinedload(Service.host).
            selectinload(Host.hostnames),

            joinedload(VulnerabilityGeneric.update_user),
            undefer(VulnerabilityGeneric.creator_command_id),
            undefer(VulnerabilityGeneric.creator_command_tool),
            undefer(VulnerabilityGeneric.target_host_ip),
            undefer(VulnerabilityGeneric.target_host_os),
            joinedload(VulnerabilityGeneric.tags),
            joinedload(VulnerabilityGeneric.cwe),
            joinedload(VulnerabilityGeneric.owasp),
            joinedload(Vulnerability.owasp),
            joinedload(VulnerabilityWeb.owasp),
            joinedload(VulnerabilityGeneric.workspace).load_only(Workspace.name),
            selectinload(VulnerabilityGeneric.cve_instances),
            selectinload(VulnerabilityGeneric.refs),
            selectinload(VulnerabilityGeneric.policy_violation_instances),
        ]

        if request.args.get('get_evidence'):
            options.append(joinedload(VulnerabilityGeneric.evidence))
        else:
            options.append(noload(VulnerabilityGeneric.evidence))

        return query.options(selectin_polymorphic(
            VulnerabilityGeneric,
            [Vulnerability, VulnerabilityWeb]
        ), *options)

    def _filter_query(self, query):
        query = super()._filter_query(query)
        search_term = request.args.get('search', None)
        if search_term is not None:
            # TODO migration: add more fields to free text search
            like_term = '%' + search_term + '%'
            match_name = VulnerabilityGeneric.name.ilike(like_term)
            match_desc = VulnerabilityGeneric.description.ilike(like_term)
            query = query.filter(match_name | match_desc)
        return query

    @property
    def model_class(self):
        _json = request.get_json(silent=True)
        if request.method == 'POST' and _json:
            return self.model_class_dict[_json.get('type', 'VulnerabilityGeneric')]
        # We use Generic to list all vulns from all types
        return self.model_class_dict['VulnerabilityGeneric']

    def _get_schema_class(self):
        assert self.schema_class_dict is not None, "You must define schema_class"
        _json = request.get_json(silent=True)
        if request.method == 'POST' and _json:
            requested_type = _json.get('type')
            if not requested_type:
                raise InvalidUsage('Type is required.')
            if requested_type not in self.schema_class_dict:
                raise InvalidUsage('Invalid vulnerability type.')
            return self.schema_class_dict[requested_type]
        # We use web since it has all the fields
        return self.schema_class_dict['VulnerabilityWeb']

    def _envelope_list(self, objects, pagination_metadata=None):
        vulns = []
        for index, vuln in enumerate(objects):
            # we use index when the filter endpoint uses group by and
            # the _id was not used in the group by
            vulns.append({
                'id': vuln.get('_id', index),
                'key': vuln.get('_id', index),
                'value': vuln
            })
        return {
            'vulnerabilities': vulns,
            'count': (pagination_metadata.total
                      if pagination_metadata is not None else len(vulns))
        }

    def count(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability"]
          summary: "Count of all vulnerabilities."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      total_count:
                        type: integer
                        description: Total number of vulnerabilities
        tags: ["Vulnerability"]
        responses:
          200:
            description: Ok
        """

        extra_filters = [Workspace.active == True]  # noqa

        query = (
            db.session.query(func.count(VulnerabilityGeneric.id))
            .join(Workspace)
            .filter(*extra_filters)
        )

        vuln_count = query.scalar()

        res = {"total_count": vuln_count}

        return res

    @route('/<int:vuln_id>/attachment', methods=['POST'])
    def post_attachment(self, vuln_id, **kwargs):
        """
        ---
        post:
          tags: ["Vulnerability", "File"]
          description: Creates a new attachment in the vuln
          responses:
            201:
              description: Created
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).options(
                joinedload(VulnerabilityGeneric.host).selectinload(Host.hostnames),
                joinedload(VulnerabilityGeneric.service).joinedload(Service.host).selectinload(Host.hostnames),
                joinedload(VulnerabilityGeneric.workspace).load_only(Workspace.name),
                joinedload(VulnerabilityGeneric.creator).load_only(User.username),
                selectinload(VulnerabilityGeneric.cve_instances),
                selectinload(VulnerabilityGeneric.refs),
                noload(VulnerabilityGeneric.evidence),
            ).filter(VulnerabilityGeneric.id == vuln_id),
            operation="write"
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        try:
            validate_file(request)
        except FileNotFoundError:
            abort(HTTP_BAD_REQUEST, "File not found in request")
        except WTFormsValidationError as e:
            abort(HTTP_FORBIDDEN, str(e))

        vuln = VulnerabilitySchema().dump(vuln_permission_check)
        filename = request.files['file'].filename
        _attachments = vuln['_attachments']

        if filename in _attachments:
            message = 'Evidence already exists in vuln'
            return make_response(jsonify(message=message, success=False, code=HTTP_BAD_REQUEST), HTTP_BAD_REQUEST)

        description = request.form.get('description')

        faraday_file = FaradayUploadedFile(request.files['file'].read())
        get_or_create(
            db.session,
            File,
            object_id=vuln_id,
            object_type='vulnerability',
            name=filename,
            filename=filename,
            content=faraday_file,
            description=description,
        )
        db.session.commit()
        debounce_workspace_update(vuln_permission_check.workspace.name)
        message = 'Evidence upload was successful'
        logger.info(message)
        return jsonify({'message': message})

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['PATCH'])
    def patch_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        patch:
          tags: ["Vulnerability", "File"]
          description: Updates the description of an attachment.
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    description:
                      type: string
                      example: "Updated attachment description"
          responses:
            200:
              description: Updated successfully
            404:
              description: Attachment or Vulnerability not found
            400:
              description: Validation error
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).options(
                joinedload(VulnerabilityGeneric.workspace).load_only(Workspace.name),
            ).filter(VulnerabilityGeneric.id == vuln_id),
            operation="write"
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        # Validate JSON input
        schema = PatchAttachmentSchema()
        try:
            data = schema.load(request.get_json())
        except ValidationError as e:
            abort(HTTP_BAD_REQUEST, str(e.messages))

        # Check if attachment exists
        try:
            attachment = db.session.query(File).filter_by(
                object_type='vulnerability',
                object_id=vuln_id,
                filename=attachment_filename
            ).one()
        except NoResultFound:
            abort(HTTP_NOT_FOUND, "Attachment or Vulnerability not found")

        # Update and commit the changes
        attachment.description = data["description"]
        db.session.commit()
        debounce_workspace_update(vuln_permission_check.workspace.name)

        return jsonify({"message": "Attachment updated successfully"}), HTTP_OK

    @route('/filter')
    def filter(self, **kwargs):
        """
        ---
        get:
          tags: ["Filter", "Vulnerability"]
          description: Filters, sorts and groups vulnerabilities using a json with parameters. These parameters must be part of the model.
          parameters:
          - in: query
            name: q
            description: Recursive json with filters that supports operators. The json could also contain sort and group.
            schema:
              type: string
          responses:
            200:
              description: Returns filtered, sorted and grouped results
              content:
                application/json:
                  schema: FlaskRestlessSchema
            400:
              description: Invalid q was sent to the server
        tags: ["Filter", "Vulnerability"]
        responses:
          200:
            description: Ok
        """
        workspace_name = kwargs.get('workspace_name')
        filters = request.args.get('q', '{}')
        export_csv = request.args.get('export_csv', '')
        export_csv_limited = request.args.get('export_csv_limited', '')

        is_full_export = export_csv.lower() == 'true'
        is_limited_export = export_csv_limited.lower() == 'true'

        if is_full_export and is_limited_export:
            abort(HTTP_BAD_REQUEST, "export_csv and export_csv_limited are mutually exclusive")

        # For limited export with explicit columns: extract them before _filter pops them,
        # and use a minimal exclude_list so requested large fields are serialized.
        selected_columns_for_export = None
        if is_limited_export:
            try:
                raw = json_loads(filters) or {}
                cols = raw.get('columns') if isinstance(raw, dict) else None
                if isinstance(cols, list) and all(isinstance(c, str) for c in cols):
                    selected_columns_for_export = cols
            except Exception as e:
                logger.debug(f"Could not parse columns from filters query param: {e}")

        if is_full_export:
            exclude_list = ('_attachments', 'desc')
        elif is_limited_export and selected_columns_for_export:
            exclude_list = ('_attachments',)
        elif is_limited_export:
            exclude_list = ('_attachments', 'description', 'desc', 'refs', 'request',
                            'resolution', 'response', 'policyviolations', 'data')
        else:
            exclude_list = None

        filtered_vulns, count = self._filter(
            filters,
            exclude_list=exclude_list,
            skip_columns_restriction=is_full_export,
            **kwargs
        )

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count

        # Handle CSV exports
        if is_full_export:
            custom_fields_columns = []
            for custom_field in db.session.query(CustomFieldsSchema).order_by(CustomFieldsSchema.field_order):
                custom_fields_columns.append(custom_field.field_name)
            memory_file = export_vulns_to_csv(filtered_vulns, custom_fields_columns)
            default_filename = "Faraday-SR-Context.csv"
        elif is_limited_export:
            memory_file = export_vulns_to_csv_limited(filtered_vulns,
                                                      selected_columns=selected_columns_for_export)
            default_filename = "Faraday-SR-Limited.csv"
        else:
            return self._envelope_list(filtered_vulns, pagination_metadata)

        file_name = f"Faraday-SR-{workspace_name}.csv" if workspace_name else default_filename
        return send_file(memory_file,
                            download_name=file_name,
                            as_attachment=True,
                            max_age=0)

    def _hostname_filters(self, filters):
        res_filters = []
        hostname_filters = []
        for search_filter in filters:
            if 'or' not in search_filter and 'and' not in search_filter:
                fieldname = search_filter.get('name')
                operator = search_filter.get('op')
                argument = search_filter.get('val')
                otherfield = search_filter.get('field')
                field_filter = {
                    "name": fieldname,
                    "op": operator,
                    "val": argument
                }
                if otherfield:
                    field_filter.update({"field": otherfield})
                if fieldname == 'hostnames':
                    hostname_filters.append(field_filter)
                else:
                    res_filters.append(field_filter)
            elif 'or' in search_filter:
                or_filters, deep_hostname_filters = self._hostname_filters(search_filter['or'])
                if or_filters:
                    res_filters.append({"or": or_filters})
                hostname_filters += deep_hostname_filters
            elif 'and' in search_filter:
                and_filters, deep_hostname_filters = self._hostname_filters(search_filter['and'])
                if and_filters:
                    res_filters.append({"and": and_filters})
                hostname_filters += deep_hostname_filters

        return res_filters, hostname_filters

    def _generate_filter_query(
            self,
            vulnerability_class,
            filters,
            hostname_filters,
            marshmallow_params,
            is_csv=False,
            **kwargs,
    ):
        workspace = kwargs.get('workspace')

        hosts_os_filter = [host_os_filter for host_os_filter in filters.get('filters', []) if
                           host_os_filter.get('name') == 'host__os']

        if hosts_os_filter:
            # remove host__os filters from filters due to a bug
            hosts_os_filter = hosts_os_filter[0]
            filters['filters'] = [host_os_filter for host_os_filter in filters.get('filters', []) if
                                  host_os_filter.get('name') != 'host__os']

        vulns = search(db.session, vulnerability_class, filters)

        if workspace:
            vulns = vulns.filter(VulnerabilityGeneric.workspace == workspace)
        else:
            vulns = self._apply_filter_context(vulns)
            vulns = vulns.filter(vulnerability_class.workspace.has(active=True))

        if hosts_os_filter:
            os_value = hosts_os_filter['val']
            vulns = vulns.join(Host).join(Service).filter(Host.os == os_value)

        if 'group_by' not in filters:
            options = [
                selectinload(VulnerabilityGeneric.cve_instances),
                selectinload(VulnerabilityGeneric.owasp),
                selectinload(VulnerabilityGeneric.cwe),
                selectinload(VulnerabilityGeneric.tags),
                joinedload(VulnerabilityGeneric.host).selectinload(Host.hostnames),
                # service is declared on each subclass, so the relationship on
                # VulnerabilityGeneric is not the one the loaded instances use.
                joinedload(Vulnerability.service).joinedload(Service.host).selectinload(Host.hostnames),
                joinedload(VulnerabilityWeb.service).joinedload(Service.host).selectinload(Host.hostnames),
                joinedload(VulnerabilityGeneric.creator),
                joinedload(VulnerabilityGeneric.update_user),
                joinedload(VulnerabilityGeneric.group),
                joinedload(VulnerabilityGeneric.workspace).load_only(Workspace.name),
                undefer(VulnerabilityGeneric.target),
                undefer(VulnerabilityGeneric.target_host_os),
                undefer(VulnerabilityGeneric.target_host_ip),
                undefer(VulnerabilityGeneric.creator_command_tool),
                undefer(VulnerabilityGeneric.creator_command_id),
                noload(VulnerabilityGeneric.evidence)
            ]
            if is_csv:
                options = options + [
                    selectinload(VulnerabilityGeneric.policy_violation_instances),
                    selectinload(VulnerabilityGeneric.refs)
                ]

            vulns = vulns.options(selectin_polymorphic(
                VulnerabilityGeneric,
                [Vulnerability, VulnerabilityWeb]
            ), *options)
        return vulns

    def _filter(self, filters, exclude_list=None, skip_columns_restriction=False, **kwargs):
        hostname_filters = []
        vulns = None
        try:
            filters = FlaskRestlessSchema().load(json_loads(filters)) or {}
            if filters:
                filters['filters'], hostname_filters = self._hostname_filters(filters.get('filters', []))
        except (ValidationError, JSONDecodeError, AttributeError) as ex:
            logger.exception(ex)
            abort(HTTP_BAD_REQUEST, "Invalid filters")

        workspace_name = kwargs.get('workspace_name')
        if workspace_name:
            kwargs['workspace'] = get_workspace(workspace_name)

        marshmallow_params = {'many': True, 'context': {}, 'exclude': (
            '_attachments',
            'description',
            'desc',
            'refs',
            'request',
            'resolution',
            'response',
            'policyviolations',
            'data',
        ) if not exclude_list else exclude_list}
        if 'columns' in filters:
            columns = filters.pop('columns')
            if len(columns) > 0:
                for column in columns:
                    if column not in VALID_FILTER_VULN_COLUMNS:
                        abort(400, f"Invalid column {column}")
                if not skip_columns_restriction:
                    for column in columns:
                        marshmallow_params.setdefault('only', []).append(column)
                    # Marshmallow applies 'exclude' after 'only', so user-requested fields
                    # must be removed from 'exclude' to avoid being silently dropped.
                    if not exclude_list:
                        requested = set(marshmallow_params['only'])
                        marshmallow_params['exclude'] = tuple(
                            f for f in marshmallow_params['exclude'] if f not in requested
                        )
        if 'group_by' not in filters:
            offset = None
            if 'offset' in filters:
                offset = filters.pop('offset')

            limit = get_settings("query_limits").vuln_query_limit
            if 'limit' in filters:
                if limit:
                    filter_limit = filters.pop('limit')
                    if limit > filter_limit > 0:
                        limit = filter_limit
                else:
                    limit = filters.pop('limit')

            try:
                vulns = self._generate_filter_query(
                    VulnerabilityGeneric,
                    filters,
                    hostname_filters,
                    marshmallow_params,
                    bool(exclude_list),
                    **kwargs,
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            try:
                total_count = vulns.order_by(None).with_entities(func.count(VulnerabilityGeneric.id)).scalar()
            except DataError as e:
                logger.warning("DataError on vuln count query: %s", e)
                abort(HTTP_BAD_REQUEST, "Invalid filters")
            if limit:
                vulns = vulns.limit(limit)
            if offset:
                vulns = vulns.offset(offset)

            vulns = self.schema_class_dict['VulnerabilityWeb'](**marshmallow_params).dump(vulns)
            if exclude_list is None:
                _truncate_large_fields(vulns)
            return vulns, total_count

        else:
            try:
                vulns = self._generate_filter_query(
                    VulnerabilityGeneric,
                    filters,
                    hostname_filters,
                    marshmallow_params,
                    **kwargs,
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            vulns_data, rows_count = get_filtered_data(filters, vulns)

            return vulns_data, rows_count

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['GET'])
    def get_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Get a vuln attachment
          responses:
            200:
              description: Ok
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename.replace(" ", "%20")).first()

        if not vuln_permission_check or not file_obj:
            abort(HTTP_NOT_FOUND, "File not found")

        depot = DepotManager.get()
        depot_file = depot.get(file_obj.content.get('file_id'))

        if not depot_file:
            abort(HTTP_NOT_FOUND, "File not found")

        if depot_file.content_type.startswith('image/'):
            # Image content types are safe (they can't be executed like
            # html) so we don't have to force the download of the file
            as_attachment = False
        else:
            as_attachment = True

        return send_file(
            BytesIO(depot_file.read()),
            download_name=depot_file.filename,
            as_attachment=as_attachment,
            mimetype=depot_file.content_type
        )

    @route('/<int:vuln_id>/attachment', methods=['GET'])
    def get_attachments_by_vuln(self, vuln_id, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Gets an attachment for a vulnerability
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: EvidenceSchema
            403:
              description: Workspace disabled or no permission
            404:
              description: Not Found
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        files = db.session.query(File).filter_by(object_type='vulnerability', object_id=vuln_id).all()

        res = {}
        for file_obj in files:
            ret = EvidenceSchema().dump(file_obj)
            res[file_obj.filename] = ret

        return jsonify(res)

    @route('/<int:vuln_id>/attachment/<attachment_filename>', methods=['DELETE'])
    def delete_attachment(self, vuln_id, attachment_filename, **kwargs):
        """
        ---
        delete:
          tags: ["Vulnerability", "File"]
          description: Remove a vuln attachment
          responses:
            200:
              description: Ok
        """
        vuln_permission_check = self._apply_filter_context(
            db.session.query(VulnerabilityGeneric).filter(VulnerabilityGeneric.id == vuln_id)
        ).first()

        if not vuln_permission_check:
            abort(HTTP_NOT_FOUND, "Vulnerability not found")

        file_obj = db.session.query(File).filter_by(object_type='vulnerability',
                                                    object_id=vuln_id,
                                                    filename=attachment_filename).first()
        if not file_obj:
            abort(HTTP_NOT_FOUND, "File not found")

        db.session.delete(file_obj)
        db.session.commit()
        depot = DepotManager.get()
        depot.delete(file_obj.content.get('file_id'))
        message = 'Attachment was successfully deleted'
        logger.info(message)
        return jsonify({'message': message})

    @route('export_csv', methods=['GET'])
    def export_csv(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability", "File"]
          description: Get a CSV file with all vulns from a workspace
          parameters:
          - in: query
            name: confirmed
            description: "If truthy, only export confirmed vulnerabilities."
            schema:
              type: boolean
          - in: query
            name: q
            description: "JSON-encoded flask-restless filter object."
            schema:
              type: string
          responses:
            200:
              description: Ok
        tags: ["Vulnerability", "File"]
        responses:
          200:
            description: Ok
        """
        workspace_name = kwargs.get('workspace_name')
        confirmed = bool(request.args.get('confirmed'))
        filters = request.args.get('q', '{}')
        custom_fields_columns = []

        for custom_field in db.session.query(CustomFieldsSchema).order_by(CustomFieldsSchema.field_order):
            custom_fields_columns.append(custom_field.field_name)

        if confirmed:
            if 'filters' not in filters:
                filters = {'filters': []}
            filters['filters'].append({
                "name": "confirmed",
                "op": "==",
                "val": "true"
            })
            filters = json_dumps(filters)

        vulns_query, _ = self._filter(filters, exclude_list=('_attachments', 'desc'), **kwargs)
        memory_file = export_vulns_to_csv(vulns_query, custom_fields_columns)

        if workspace_name:
            logger.info(f"CSV file with vulnerabilities from workspace {workspace_name} exported")
            return send_file(memory_file,
                             download_name=f"Faraday-SR-{workspace_name}.csv",
                             as_attachment=True,
                             max_age=0)
        else:
            logger.info("CSV file exported with context vulnerabilities")
            return send_file(memory_file,
                             download_name="Faraday-SR-Context.csv",
                             as_attachment=True,
                             max_age=0)

    @route('top_users', methods=['GET'])
    def top_users(self, **kwargs):
        """
        ---
        get:
          tags: ["Vulnerability"]
          description: Gets a list of top users having account its uploaded vulns
          parameters:
          - in: query
            name: limit
            description: "Maximum number of users to return (default 1)."
            schema:
              type: integer
              default: 1
          responses:
            200:
              description: List of top users
        tags: ["Vulnerability"]
        responses:
          200:
            description: Ok
        """
        limit = request.args.get('limit', 1)
        workspace_name = kwargs.get('workspace_name')

        if workspace_name:
            workspace = get_workspace(workspace_name)
            data = db.session.query(User, func.count(VulnerabilityGeneric.id)).join(VulnerabilityGeneric.creator) \
                .filter(VulnerabilityGeneric.workspace_id == workspace.id).group_by(User.id) \
                .order_by(desc(func.count(VulnerabilityGeneric.id))).limit(int(limit)).all()
        else:
            data = self._apply_filter_context(
                db.session.query(User, func.count(VulnerabilityGeneric.id)).join(VulnerabilityGeneric.creator)
                .group_by(User.id)
            ).order_by(desc(func.count(VulnerabilityGeneric.id))).limit(int(limit)).all()

        users = []
        for item in data:
            user = {
                'id': item[0].id,
                'username': item[0].username,
                'count': item[1]
            }
            users.append(user)
        response = {'users': users}
        return jsonify(response)

    @route('', methods=['DELETE'])
    def bulk_delete(self, **kwargs):
        # TODO BULK_DELETE_SCHEMA
        _json = request.get_json(silent=True)
        if not _json or 'severities' not in _json:
            return super().bulk_delete(self, **kwargs)
        return self._perform_bulk_delete(_json['severities'], by='severity', **kwargs), HTTP_OK
    bulk_delete.__doc__ = BulkDeleteMixin.bulk_delete.__doc__

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        if kwargs.get("by", "id") != "severity":
            query = self.model_class.query.filter(self.model_class.id.in_(ids))
        else:
            query = self.model_class.query.filter(self.model_class.severity.in_(ids))
        return self._apply_filter_context(query)

    def _get_model_association_proxy_fields(self):
        return [
            field.target_collection
            for field in inspect(self.model_class).all_orm_descriptors
            if field.extension_type.name == "ASSOCIATION_PROXY"
        ]

    def _get_bulk_update_objects(self, ids, **kwargs):
        # The vulns schema never reads context['objects'], so we only need IDs.
        # Fetch just the id column instead of loading full ORM instances.
        return self._bulk_update_query(ids, **kwargs).with_entities(self.model_class.id).all()

    def _pre_bulk_update(self, data, **kwargs):
        data.pop('type', '')  # It's forbidden to change vuln type!
        data.pop('tool', '')
        data.pop('service_id', '')
        data.pop('host_id', '')

        custom_behaviour_fields = {}

        # This fields (cvss2 and cvss3) are better to be processed in this way because the model parse
        # vector string into fields and calculates the scores
        if 'cvss2_vector_string' in data:
            custom_behaviour_fields['cvss2_vector_string'] = data.pop('cvss2_vector_string')
        if 'cvss3_vector_string' in data:
            custom_behaviour_fields['cvss3_vector_string'] = data.pop('cvss3_vector_string')
        if 'cvss4_vector_string' in data:
            custom_behaviour_fields['cvss_4_vector_string'] = data.pop('cvss4_vector_string')

        cwe_list = data.pop('cwe', None)
        if cwe_list is not None:
            custom_behaviour_fields['cwe'] = create_cwe(cwe_list)
        refs = data.pop('refs', None)
        if refs is not None:
            custom_behaviour_fields['refs'] = refs

        # TODO For now, we don't want to accept multiples attachments; moreover, attachments have its own endpoint
        data.pop('_attachments', [])
        super()._pre_bulk_update(data, **kwargs)

        model_association_proxy_fields = self._get_model_association_proxy_fields()
        for key in list(data):
            parent = getattr(VulnerabilityWeb, key).parent
            field_name = getattr(parent, "target_collection", None)
            if field_name and field_name in model_association_proxy_fields:
                custom_behaviour_fields[key] = data.pop(key)

        return custom_behaviour_fields

    def _post_bulk_update(self, ids, extracted_data, **kwargs):
        workspaces = (db.session.query(Workspace)
                      .join(VulnerabilityGeneric)
                      .filter(VulnerabilityGeneric.id.in_(ids))
                      .distinct().all())

        if extracted_data:
            # refs: bulk INSERT ON CONFLICT DO NOTHING — no ORM objects needed
            if 'refs' in extracted_data:
                refs_data = extracted_data.pop('refs')
                if refs_data:
                    now = datetime.utcnow()
                    rows = [
                        {
                            'name': ref['name'],
                            'type': ref['type'],
                            'vulnerability_id': vuln_id,
                            'create_date': now,
                            'update_date': now,
                        }
                        for vuln_id in ids
                        for ref in refs_data
                    ]
                    stmt = pg_insert(VulnerabilityReference).values(rows)
                    db.session.execute(stmt.on_conflict_do_nothing(
                        constraint='uix_vulnerability_reference_table_vuln_id_name_type'
                    ))

            # remaining fields (cvss*, cwe) require ORM setters — process in chunks
            if extracted_data:
                CHUNK_SIZE = 500
                queryset = self._bulk_update_query(ids, **kwargs)
                for obj in queryset.yield_per(CHUNK_SIZE):
                    for (key, value) in extracted_data.items():
                        setattr(obj, key, value)
                    db.session.flush()
                    db.session.expire(obj)

        if workspaces:
            # Commit UPDATE + extracted_data changes before dispatching the async task.
            # Values are captured now to preserve request context (current_user, timestamp).
            db.session.commit()
            user_id = None
            try:
                if hasattr(current_user, 'id'):
                    user_id = current_user.id
            except AttributeError as e:
                logger.debug("Current user not found", exc_info=e)
            from faraday.server.tasks import create_bulk_update_commands_task  # pylint: disable=import-outside-toplevel
            args = (list(ids), [ws.id for ws in workspaces], user_id, datetime.utcnow())
            if faraday_server.celery_enabled:
                create_bulk_update_commands_task.delay(*args)
            else:
                create_bulk_update_commands_task(*args)

        if 'returning' in kwargs and kwargs['returning']:
            # update host stats
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel
            host_id_list = [data[4] for data in kwargs['returning'] if data[4]]
            service_id_list = [data[5] for data in kwargs['returning'] if data[5]]
            workspace_ids = [ws.id for ws in workspaces]
            if faraday_server.celery_enabled:
                update_host_stats.delay(host_id_list, service_id_list, workspace_ids=workspace_ids)
            else:
                update_host_stats(host_id_list, service_id_list, workspace_ids=workspace_ids)

        for ws in workspaces:
            debounce_workspace_update(ws.name)

    def _perform_bulk_delete(self, values, **kwargs):
        # Get host and service ids in order to update host stats
        host_ids = db.session.query(
            VulnerabilityGeneric.host_id,
            VulnerabilityGeneric.service_id
        )

        by_severity = kwargs.get('by', None) == 'severity'
        if by_severity:
            for severity in values:
                if severity not in VulnerabilityABC.SEVERITIES:
                    abort(HTTP_BAD_REQUEST, "Severity type not valid")

            host_ids = host_ids.filter(
                VulnerabilityGeneric.severity.in_(values)
            ).all()

            workspaces = (self._get_context_workspace_query(operation='write')
                          .join(VulnerabilityGeneric)
                          .filter(VulnerabilityGeneric.severity.in_(values))
                          .distinct(Workspace.id).all())
        else:
            host_ids = host_ids.filter(
                VulnerabilityGeneric.id.in_(values)
            ).all()

            workspaces = (self._get_context_workspace_query(operation='write')
                          .join(VulnerabilityGeneric)
                          .filter(VulnerabilityGeneric.id.in_(values))
                          .distinct(Workspace.id).all())

        response = super()._perform_bulk_delete(values, **kwargs)
        deleted = response.json.get('deleted', 0)
        if deleted > 0:
            from faraday.server.tasks import update_host_stats  # pylint:disable=import-outside-toplevel

            for workspace in workspaces:
                debounce_workspace_update(workspace.name)

            host_id_list = [data[0] for data in host_ids if data[0]]
            service_id_list = [data[1] for data in host_ids if data[1]]
            workspace_ids = [workspace.id for workspace in workspaces]

            if faraday_server.celery_enabled:
                update_host_stats.delay(host_id_list, service_id_list, workspace_ids=workspace_ids)
            else:
                update_host_stats(host_id_list, service_id_list, workspace_ids=workspace_ids)

        return response

    def _paginate(self, query, hard_limit=0):
        limit = get_settings("query_limits").vuln_query_limit
        return super()._paginate(query, hard_limit=limit)


VulnerabilityView.register(vulns_api)
