"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""API base — vistas concretas + re-exports de core/mixins (Y3 split, wire intacto)."""
from collections import defaultdict
from datetime import timezone
from http.client import (
    BAD_REQUEST as HTTP_BAD_REQUEST,
    CONFLICT as HTTP_CONFLICT,
)
from time import time

# Related third party imports
from flask import abort, jsonify, request
from flask_classful import FlaskView, route  # noqa: F401  (route: re-export para modules/*)
from flask_login import current_user
from marshmallow import EXCLUDE, Schema, fields
from marshmallow_sqlalchemy import ModelConverter
from marshmallow_sqlalchemy.schema import SQLAlchemyAutoSchemaMeta
from sqlalchemy import and_, asc, column, desc, func, update as sqlalchemy_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.inspection import inspect
from webargs.core import ValidationError
from webargs.flaskparser import FlaskParser

# Local application imports
from faraday.server.models import (
    Workspace,
    WorkspacePermission,
    db,
)
from faraday.server.schemas import NullToBlankString
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation,
)

from faraday.server.api.core import (  # noqa: F401
    logger,
    output_json,
    get_filtered_data,
    hydrate_sample_for_conflict,
    get_group_by_and_sort_dir,
    get_workspace,
    InvalidUsage,
    GenericView,
    GenericWorkspacedView,
    GenericMultiWorkspacedView,
    CustomModelConverter,
    CustomSQLAlchemyAutoSchemaOpts,
)

from faraday.server.api.mixins import (  # noqa: F401
    ListMixin,
    SortableMixin,
    PaginatedMixin,
    FilterAlchemyMixin,
    FilterWorkspacedMixin,
    FilterObjects,
    FilterMixin,
    ListWorkspacedMixin,
    RetrieveMixin,
    RetrieveWorkspacedMixin,
    RetrieveMultiWorkspacedMixin,
    ReadOnlyView,
    ReadOnlyWorkspacedView,
    ReadOnlyMultiWorkspacedView,
    CreateMixin,
    CommandMixin,
    CreateWorkspacedMixin,
    UpdateMixin,
    BulkUpdateMixin,
    UpdateWorkspacedMixin,
    BulkUpdateWorkspacedMixin,
    DeleteMixin,
    BulkDeleteMixin,
    DeleteWorkspacedMixin,
    BulkDeleteWorkspacedMixin,
    CountWorkspacedMixin,
    CountMultiWorkspacedMixin,
)


class ReadWriteView(CreateMixin,
                    UpdateMixin,
                    DeleteMixin,
                    ReadOnlyView):
    """A generic view with list, retrieve and create endpoints

    It is just a GenericView inheriting also from ListMixin,
    RetrieveMixin, SortableMixin, CreateMixin, UpdateMixin and
    DeleteMixin.
    """


class ReadWriteWorkspacedView(CreateWorkspacedMixin,
                              UpdateWorkspacedMixin,
                              DeleteWorkspacedMixin,
                              CountWorkspacedMixin,
                              ReadOnlyWorkspacedView):
    """A generic workspaced view with list, retrieve and create
    endpoints

    It is just a GenericWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveWorkspacedMixin, SortableMixin,
    CreateWorkspacedMixin, DeleteWorkspacedMixin and
    CountWorkspacedMixin.
    """


def old_isoformat(dt, *args, **kwargs):
    """Return the ISO8601-formatted UTC representation of a datetime object."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(*args, **kwargs)


fields.DateTime.SERIALIZATION_FUNCS['iso'] = old_isoformat


class AutoSchema(Schema, metaclass=SQLAlchemyAutoSchemaMeta):
    """
    A Marshmallow schema that does field introspection based on
    the SQLAlchemy model specified in Meta.model.
    Unlike the marshmallow_sqlalchemy ModelSchema, it doesn't change
    the serialization and deserialization process.
    """
    OPTIONS_CLASS = CustomSQLAlchemyAutoSchemaOpts

    # Use NullToBlankString instead of fields.String by default on text fields
    TYPE_MAPPING = Schema.TYPE_MAPPING.copy()
    TYPE_MAPPING[str] = NullToBlankString

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = EXCLUDE


class FilterAlchemyModelConverter(ModelConverter):
    """Use this to make all fields of a model not required.

    It is used to make FilterAlchemy support not nullable columns"""

    def _add_column_kwargs(self, kwargs, column):
        super()._add_column_kwargs(kwargs, column)
        kwargs['required'] = False


class AutoSchemaFlaskParser(FlaskParser):
    # It is required to use a schema class that has unknown=EXCLUDE by default.
    # Otherwise, requests would fail if a not defined query parameter is sent
    # (like group_by)
    DEFAULT_SCHEMA_CLASS = AutoSchema


class FilterSetMeta:
    """Base Meta class of FilterSet objects"""
    parser = AutoSchemaFlaskParser(location='query')
    converter = FilterAlchemyModelConverter()


def get_user_permissions(user):
    permissions = defaultdict(dict)

    # Hardcode all permissions to allowed
    ALLOWED = {'allowed': True, 'reason': None}

    # TODO schema
    generic_entities = {
        'licences', 'methodology_templates', 'task_templates', 'users',
        'vulnerability_template', 'workspaces',
        'agents', 'agents_schedules', 'commands', 'comments', 'hosts',
        'executive_reports', 'services', 'methodologies', 'tasks', 'vulns'
        }

    for entity in generic_entities:
        permissions[entity]['view'] = ALLOWED
        permissions[entity]['create'] = ALLOWED
        permissions[entity]['update'] = ALLOWED
        permissions[entity]['delete'] = ALLOWED

    extra_permissions = {
        'vulns.status_change',
        'settings.view',
        'settings.update',
        'ticketing.jira',
        'ticketing.servicenow',
        'bulk_create.bulk_create',
        'agents.run',
        'workspace_comparison.compare',
        'data_analysis.view',
    }

    for permission in extra_permissions:
        (entity, action) = permission.split('.')
        permissions[entity][action] = ALLOWED

    return permissions


class ContextMixin(GenericView):

    count_extra_filters = []

    def _get_base_query(self, operation="", *args, **kwargs):
        if not operation:
            operation = "read" if request.method in ['GET', 'HEAD', 'OPTIONS'] else "write"
        query = super()._get_base_query(*args, **kwargs)
        return self._apply_filter_context(query, operation)

    def _apply_filter_context(self, query, operation="read"):
        filters = and_()
        if operation == "write":
            filters = filters & self._get_context_write_filter()
        query = query.filter(
            self.model_class.workspace_id.in_(
                self._get_context_workspace_ids(filters)
            )
        )
        return query

    @staticmethod
    def _get_context_workspace_ids(filter):
        return [
            row[0]
            for row in db.session.query(Workspace.id)
            .join(WorkspacePermission, Workspace.id == WorkspacePermission.workspace_id, isouter=True)
            .filter(filter).all()
        ]

    @staticmethod
    def _get_context_workspace_filter():
        return (
                (WorkspacePermission.user_id == current_user.id) | (Workspace.public == True) # noqa: E712, E261
        )

    @staticmethod
    def _get_context_write_filter():
        return (
                Workspace.readonly == False # noqa: E712, E261
        )

    def _get_context_workspace_query(self, operation="write"):
        workspace_query = Workspace.query
        return workspace_query

    def _bulk_delete_query(self, ids, **kwargs):
        return self._get_base_query(operation="write", **kwargs).filter(self.model_class.id.in_(ids))

    def _bulk_update_query(self, ids, **kwargs):
        return self._get_base_query(operation="write", **kwargs).filter(self.model_class.id.in_(ids))

    def count(self, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Group {class_model} by the field set in the group_by GET parameter."
          parameters:
          - in: query
            name: group_by
            required: true
            description: "Column to group by. Endpoint returns 404 if omitted."
            schema:
              type: string
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            404:
              description: group_by is not specified
        """
        res = {
            'groups': [],
            'total_count': 0
        }
        group_by, sort_dir = get_group_by_and_sort_dir(self.model_class)

        # using format is not a great practice.
        # the user input is group_by, however it's filtered by column name.
        table_name = inspect(self.model_class).tables[0].name
        group_by = column(f'{table_name}.{group_by}', is_literal=True)

        query_count = self._apply_filter_context(
            self._filter_query(
                db.session.query(self.model_class).
                group_by(group_by).
                filter(*self.count_extra_filters)
            )
        )
        # order
        order_by = group_by
        if sort_dir == 'desc':
            query_count = query_count.order_by(desc(order_by))
        else:
            query_count = query_count.order_by(asc(order_by))
        for key, query_count in query_count.with_entities(group_by, func.count(group_by)).all():
            res['groups'].append(
                {'count': query_count,
                 'name': key,
                 # To add compatibility with the web ui
                 request.args.get('group_by'): key,
                 }
            )
            res['total_count'] += query_count
        return res

    def _perform_bulk_update(self, ids, data, workspace_name=None, **kwargs):
        try:
            post_bulk_update_data = self._pre_bulk_update(data, workspace_name=workspace_name, **kwargs)
            if (len(data) > 0 or len(post_bulk_update_data) > 0) and len(ids) > 0:
                returns = None
                _time = time()
                if 'returning' in kwargs:
                    smt = (sqlalchemy_update(self.model_class)
                           .where(self.model_class.id.in_(ids))
                           .values(data).returning(*kwargs['returning']))
                    returns = db.session.execute(smt)
                    returns = returns.fetchall()
                    updated = len(returns)
                else:
                    queryset = self._bulk_update_query(ids, workspace_name=workspace_name, **kwargs)
                    updated = queryset.update(data, synchronize_session=False)
                logger.debug(f"Updated {updated} {self.model_class.__name__} in {time() - _time} seconds")
                self._post_bulk_update(
                    ids, post_bulk_update_data, workspace_name=workspace_name, data=data, returning=returns
                )
            else:
                updated = 0
            db.session.commit()
            response = {'updated': updated}
            return jsonify(response)
        except ValueError as e:
            db.session.rollback()
            abort(HTTP_BAD_REQUEST, ValidationError(
               {
                   'message': str(e),
               }
            ))
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = None
            if workspace_name:
                workspace = db.session.query(Workspace).filter_by(name=workspace_name).first()
            sample_obj = hydrate_sample_for_conflict(self.model_class, ids)
            conflict_obj = get_conflict_object(db.session, sample_obj, data, workspace, ids)
            if conflict_obj is not None:
                abort(HTTP_CONFLICT, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            elif len(ids) >= 2:
                abort(HTTP_CONFLICT, ValidationError(
                    {
                        'message': 'Updating more than one object with unique data',
                        'data': data
                    }
                ))
            else:
                raise
