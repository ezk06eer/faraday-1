"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""API mixins: list/create/update/delete/filter/count (extraído de base.py, Y3)."""
from collections import defaultdict
from http.client import (
    BAD_REQUEST as HTTP_BAD_REQUEST,
    CONFLICT as HTTP_CONFLICT,
    CREATED as HTTP_CREATED,
    NO_CONTENT as HTTP_NO_CONTENT,
    NOT_FOUND as HTTP_NOT_FOUND,
    OK as HTTP_OK,
)
from json import JSONDecodeError, loads as json_loads
from time import time
from typing import Tuple, List, Dict

# Related third party imports
from flask import abort, jsonify, make_response, request
from flask_classful import route
from flask_login import current_user
from sqlalchemy import asc, column, desc, func, update as sqlalchemy_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import joinedload, undefer
from sqlalchemy.sql.elements import BooleanClauseList
from webargs.core import ValidationError

# Local application imports
from faraday.server.models import (
    Command,
    CommandObject,
    User,
    Workspace,
    db,
)
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation,
    not_null_constraint_violation,
)
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.utils.search import (
    search,
    delete_returning_only_ids,
    search_retrieve_only_ids,
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


class ListMixin:
    """Add GET / route"""

    #: If set (to a SQLAlchemy attribute instance) use this field to order the
    #: query by default
    order_field = None

    def _filter_eagerload_options(self):
        """Loader options for the /filter endpoints.

        Filter endpoints build their query from scratch instead of going
        through _get_eagerloaded_query, so each view returns here whatever
        its schema reads, to avoid a lazy load per dumped row (n+1).
        """
        return []

    def _envelope_list(self, objects, pagination_metadata=None):
        """Override this method to define how a list of objects is
        rendered.

        See the example of:ref:`envelope-list-example` to learn
        when and how it should be used.
        """
        return objects

    @staticmethod
    def _paginate(query):
        """Overwrite this to implement pagination in the list endpoint.

        This is typically overwritten by SortableMixin.

        The method takes a query as argument and should return a tuple
        containing a new filtered query and a "pagination metadata"
        object that will be used by _envelope_list. If you don't need
        the latter just set is as None.
        """
        return query, None

    def _get_order_field(self, **kwargs):
        """Return the field used to sort the query.

        By default it returns the value of self.order_field, but it
        can be overwritten to something else, as SortableMixin does.
        """
        return self.order_field

    def index(self, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Get a list of {class_model}."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        exclude = kwargs.pop('exclude', [])
        query = self._filter_query(self._get_eagerloaded_query(**kwargs))
        order_field = self._get_order_field(**kwargs)
        if order_field is not None:
            if isinstance(order_field, tuple):
                query = query.order_by(*order_field)
            else:
                query = query.order_by(order_field)
        objects, pagination_metadata = self._paginate(query)
        if not isinstance(objects, list):
            objects = objects.limit(None).offset(0)
        return self._envelope_list(self._dump(objects, kwargs, many=True, exclude=exclude),
                                   pagination_metadata)


class SortableMixin:
    """Enables custom sorting by a field specified by the user

    See the example of :ref:`pagination-and-sorting-recipe` to learn
    how is it used.

    Works for both workspaced and non-workspaced views.
    """
    sort_field_parameter_name = "sort"
    sort_direction_parameter_name = "sort_dir"
    sort_pass_silently = False
    default_sort_direction = "asc"
    sort_model_class = None  # Override to use a model with more fields

    def _get_order_field(self, **kwargs):
        # Delegates to SortingService (ponytail composition, keeps contract)
        # Lazy import avoids circular dependency with faraday.services.sorting
        try:
            from faraday.services.sorting import SortingService  # pylint: disable=import-outside-toplevel

            return SortingService.get_order_field(self, **kwargs)
        except ImportError:
            # Fallback to legacy implementation if services not available (tests without deps)
            try:
                order_field = request.args[self.sort_field_parameter_name]
            except KeyError:
                return self.order_field
            schema = self._get_schema_instance(kwargs)
            try:
                metadata_field = schema.fields.pop('metadata')
            except KeyError:
                pass
            else:
                for (key, value) in metadata_field.target_schema.fields.items():
                    schema.fields['metadata.' + key] = value
                    schema.fields[key] = value
            try:
                field_instance = schema.fields[order_field]
            except KeyError as e:
                if self.sort_pass_silently:
                    logger.warning(f"Unknown field: {order_field}")
                    return self.order_field
                raise InvalidUsage(f"Unknown field: {order_field}") from e
            order_field = field_instance.attribute or order_field
            model_class = self.sort_model_class or self.model_class
            if order_field not in inspect(model_class).attrs:
                if self.sort_pass_silently:
                    logger.warning(f"Field not in the DB: {order_field}")
                    return self.order_field
                raise InvalidUsage(f"Field not in the DB: {order_field}")
            if hasattr(model_class, order_field + '_id'):
                field = getattr(model_class, order_field + '_id')
            else:
                field = getattr(model_class, order_field)
            sort_dir = request.args.get(self.sort_direction_parameter_name,
                                               self.default_sort_direction)
            if sort_dir not in ('asc', 'desc'):
                if self.sort_pass_silently:
                    logger.warning(f"Invalid value for sorting direction: {sort_dir}")
                    return self.order_field
                raise InvalidUsage(f"Invalid value for sorting direction: {sort_dir}")
            try:
                if self.order_field is not None:
                    if not isinstance(self.order_field, tuple):
                        self.order_field = (self.order_field,)
                    return (getattr(field, sort_dir)(),) + self.order_field
                else:
                    return getattr(field, sort_dir)()
            except NotImplementedError as e:
                if self.sort_pass_silently:
                    logger.warning(f"field {order_field} doesn't support sorting")
                    return self.order_field
                raise InvalidUsage(f"field {order_field} doesn't support sorting") from e


class PaginatedMixin:
    """Add pagination for list route"""
    per_page_parameter_name = 'page_size'
    page_number_parameter_name = 'page'

    def _paginate(self, query, hard_limit=0):
        # Delegates to PaginationService (ponytail composition)
        try:
            from faraday.services.pagination import PaginationService  # pylint: disable=import-outside-toplevel

            result = PaginationService.paginate(query, hard_limit=hard_limit)
            # Service returns (query, None) when no pagination; fall back to super for chain
            if result[1] is None and result[0] is query and self.per_page_parameter_name not in request.args and hard_limit == 0:
                return super()._paginate(query)
            return result
        except ImportError:
            page, per_page = None, None
            if self.per_page_parameter_name in request.args:
                try:
                    page = int(request.args.get(
                        self.page_number_parameter_name, 1))
                except (TypeError, ValueError):
                    abort(HTTP_NOT_FOUND, 'Invalid page number')
                try:
                    per_page = int(request.args[
                                       self.per_page_parameter_name])
                except (TypeError, ValueError):
                    abort(HTTP_NOT_FOUND, 'Invalid per_page value')
                pagination_metadata = query.paginate(page=page, per_page=per_page, error_out=False)
                return pagination_metadata.items, pagination_metadata
            elif hard_limit != 0:
                pagination_metadata = query.paginate(page=1, per_page=hard_limit, error_out=False)
                return pagination_metadata.items, pagination_metadata
            return super()._paginate(query)


class FilterAlchemyMixin:
    """Add querystring parameter filtering to list route

    It is done by setting the ViewClass.filterset_class class
    attribute
    """

    filterset_class = None

    def _filter_query(self, query):
        # Delegates to FilteringService (ponytail composition, keeps contract)
        # Lazy import avoids circular dependency with faraday.services.filtering
        try:
            from faraday.services.filtering import FilteringService  # pylint: disable=import-outside-toplevel

            return FilteringService.filter_query_alchemy(self, query)
        except ImportError:
            assert self.filterset_class is not None, 'You must define a filterset'
            return self.filterset_class(query).filter()


class FilterWorkspacedMixin(ListMixin):
    """Add filter endpoint for searching on any workspaced objects columns
    """

    @route('/filter')
    def filter(self, workspace_name):
        """
        ---
        tags: [Filter, {tag_name}]
        description: Filters, sorts and groups workspaced objects using a json with parameters. These parameters must be part of the model.
        parameters:
        - in: query
          name: q
          description: recursive json with filters that supports operators. The json could also contain sort and group.
          schema:
            type: string
        responses:
          200:
            description: returns filtered, sorted and grouped results
            content:
              application/json:
                schema: FlaskRestlessSchema
          400:
            description: invalid q was sent to the server
        """
        filters = request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, workspace_name)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    def _generate_filter_query(self, filters, workspace, severity_count=False):
        filter_query = search(db.session,
                              self.model_class,
                              filters)

        filter_query = filter_query.filter(self.model_class.workspace == workspace)
        if 'group_by' not in filters:
            filter_query = filter_query.options(*self._filter_eagerload_options())
        if severity_count and 'group_by' not in filters:
            filter_query = filter_query.options(
                undefer(self.model_class.vulnerability_critical_generic_count),
                undefer(self.model_class.vulnerability_high_generic_count),
                undefer(self.model_class.vulnerability_medium_generic_count),
                undefer(self.model_class.vulnerability_low_generic_count),
                undefer(self.model_class.vulnerability_info_generic_count),
                undefer(self.model_class.vulnerability_unclassified_generic_count),
                undefer(self.model_class.credentials_count),
                undefer(self.model_class.open_service_count),
                joinedload(self.model_class.hostnames),
                joinedload(self.model_class.services),
                joinedload(self.model_class.update_user),
                joinedload(getattr(self.model_class, 'creator')).load_only(User.username),
            )
        return filter_query

    def _filter(self, filters, workspace_name, severity_count=False):
        marshmallow_params = {'many': True, 'context': {}}
        try:
            filters = FlaskRestlessSchema().load(json_loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            abort(HTTP_BAD_REQUEST, "Invalid filters")

        workspace = get_workspace(workspace_name)
        filter_query = None
        if 'group_by' not in filters:
            # Pure pagination extraction via FilteringService (YAGNI lazy import)
            try:
                from faraday.services.filtering import FilteringService  # pylint: disable=import-outside-toplevel

                filters, offset, limit = FilteringService.extract_pagination(filters)
            except ImportError:
                offset = 0
                limit = None
                if 'offset' in filters:
                    offset = filters.pop('offset')
                if 'limit' in filters:
                    limit = filters.pop('limit')
            try:
                filter_query = self._generate_filter_query(
                    filters,
                    workspace,
                    severity_count=severity_count
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            count = filter_query.count()
            filter_query = filter_query.limit(limit).offset(offset)

            objs = self.schema_class(**marshmallow_params).dumps(filter_query)
            return json_loads(objs), count
        else:
            try:
                filter_query = self._generate_filter_query(
                    filters,
                    workspace,
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)
            data, rows_count = get_filtered_data(filters, filter_query)
            return data, rows_count


class FilterObjects:

    def _translate_filters(self, filters):
        """Hook for subclasses to translate pseudo-filters before query execution.
        Returns (translated_filters_json, extra_alchemy_filters).
        """
        return filters, None

    def _process_filter_data(self, filters, workspace_name=None, **kwargs):
        # Delegates to FilteringService (ponytail composition, keeps contract)
        # Lazy import avoids circular dependency with faraday.services.filtering
        try:
            from faraday.services.filtering import FilteringService  # pylint: disable=import-outside-toplevel

            translated, extra = FilteringService.translate_filters(self, filters)
        except ImportError:
            translated, extra = self._translate_filters(filters)
        return self._filter_standalone(translated, extra, workspace_name, **kwargs)

    def _generate_filter_query_standalone(self, filters, workspace=None, delete=False):

        if delete:
            delete_query = delete_returning_only_ids(db.session, self.model_class, filters)
            if workspace:
                delete_query = delete_query.where(self.model_class.workspace == workspace)
            delete_query = delete_query.returning(self.model_class.id)
            return delete_query

        filter_query = search_retrieve_only_ids(db.session, self.model_class, filters)

        if workspace:
            filter_query = filter_query.filter(self.model_class.workspace == workspace)

        return filter_query

    def _key_finder_standalone(self, key: str, data):
        if isinstance(data, dict):
            for k, v in data.items():
                if k == key:
                    yield v

                elif isinstance(v, dict) or isinstance(v, list):
                    yield from self._key_finder_standalone(key, v)

        elif isinstance(data, list):
            for item in data:
                yield from self._key_finder_standalone(key, item)

    def _validate_fields_standalone(self, filters: Dict[str, List[Dict]]) -> bool:
        intersection = set(self.fields_to_exclude).intersection(set(self._key_finder_standalone('name', filters)))
        return not intersection

    def _filter_standalone(
            self, filters: str, extra_alchemy_filters: BooleanClauseList = None, workspace_name=None, **kwargs
    ) -> Tuple[list, int]:

        marshmallow_params = {'many': True, 'context': {}}

        self.schema_class = self.schema_class or self._get_schema_class()

        try:
            filters = FlaskRestlessSchema().load(json_loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            abort(HTTP_BAD_REQUEST, "Invalid filters")

        if hasattr(self, 'fields_to_exclude'):
            if not self._validate_fields_standalone(filters):
                abort(HTTP_BAD_REQUEST, "Invalid filters")

        workspace = get_workspace(workspace_name) if workspace_name else None

        filter_query = None

        offset = None
        limit = None
        if 'offset' in filters:
            offset = filters.pop('offset')
        if 'limit' in filters:
            limit = filters.pop('limit')  # we need to remove pagination, since

        if 'delete' in kwargs and kwargs['delete']:
            try:
                delete_query = self._generate_filter_query_standalone(
                    filters,
                    workspace=workspace,
                    delete=True
                )
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            ids = db.session.execute(delete_query).fetchall()
            ids = [x[0] for x in ids]
            return ids

        try:
            filter_query = self._generate_filter_query_standalone(
                filters,
                workspace=workspace
            )
        except TypeError as e:
            abort(HTTP_BAD_REQUEST, e)
        except AttributeError as e:
            abort(HTTP_BAD_REQUEST, e)

        if extra_alchemy_filters is not None:
            filter_query = filter_query.filter(extra_alchemy_filters)
        if limit:
            filter_query = filter_query.limit(limit)
        if offset:
            filter_query = filter_query.offset(offset)
        try:
            ids = [x[0] for x in filter_query.all()]
        except IntegrityError as e:
            logger.exception(e)
            abort(HTTP_CONFLICT, e)
        return ids


class FilterMixin(ListMixin):
    """Add filter endpoint for searching on any non workspaced objects columns
    """

    @route('/filter')
    def filter(self):
        """
        ---
        tags: ["Filter", {tag_name}]
        description: Filters, sorts and groups non workspaced objects using a json with parameters. These parameters must be part of the model.
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
        """
        filters = request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    def _generate_filter_query(self, filters, severity_count=None):

        #  TODO: Refactor severity count usage, its only used on hosts,
        #  but hosts calls _filter from super class so this param is needed

        filter_query = search(db.session,
                              self.model_class,
                              filters)
        if 'group_by' not in filters:
            filter_query = filter_query.options(*self._filter_eagerload_options())
        return filter_query

    def _filter(self, filters: str, extra_alchemy_filters: BooleanClauseList = None,
                exclude=[], return_objects=False, severity_count=False) -> Tuple[list, int]:
        marshmallow_params = {'many': True, 'context': {}, 'exclude': exclude}
        try:
            filters = FlaskRestlessSchema().load(json_loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            abort(HTTP_BAD_REQUEST, "Invalid filters")

        filter_query = None
        if 'group_by' not in filters:
            # Pure pagination extraction via FilteringService (YAGNI lazy import)
            try:
                from faraday.services.filtering import FilteringService  # pylint: disable=import-outside-toplevel

                filters, offset, limit = FilteringService.extract_pagination(filters)
            except ImportError:
                offset = 0
                limit = None
                if 'offset' in filters:
                    offset = filters.pop('offset')
                if 'limit' in filters:
                    limit = filters.pop('limit')
            try:
                filter_query = self._generate_filter_query(
                    filters, severity_count=severity_count
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            if extra_alchemy_filters is not None:
                filter_query = filter_query.filter(extra_alchemy_filters)
            count = filter_query.order_by(None).with_entities(func.count(self.model_class.id)).scalar()
            if limit:
                filter_query = filter_query.limit(limit)
            if offset:
                filter_query = filter_query.offset(offset)
            filter_query = self._add_to_filter(filter_query)
            if return_objects:
                return filter_query.all(), count
            objs = self.schema_class(**marshmallow_params).dumps(filter_query)
            return json_loads(objs), count
        else:
            try:
                filter_query = self._generate_filter_query(
                    filters, severity_count=severity_count
                )
            except TypeError as e:
                abort(HTTP_BAD_REQUEST, e)
            except AttributeError as e:
                abort(HTTP_BAD_REQUEST, e)

            if extra_alchemy_filters is not None:
                filter_query = filter_query.filter(extra_alchemy_filters)

            data, rows_count = get_filtered_data(filters, filter_query)
            return data, rows_count

    def _add_to_filter(self, filter_query, **kwargs):
        return filter_query


class ListWorkspacedMixin(ListMixin):
    """Add GET /<workspace_name>/<route_base>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough


class RetrieveMixin:
    """Add GET /<id>/ route"""

    def get(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Retrieves {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        return self._dump(self._get_object(object_id, eagerload=True,
                                           **kwargs), kwargs)


class RetrieveWorkspacedMixin(RetrieveMixin):
    """Add GET /<workspace_name>/<route_base>/<id>/ route"""

    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    def get(self, object_id, workspace_name=None):
        """
        ---
          tags: ["{tag_name}"]
          summary: Retrieves {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().get(object_id, workspace_name=workspace_name)


class RetrieveMultiWorkspacedMixin(RetrieveWorkspacedMixin):
    """Control GET /<workspace_name>/<route_base>/<id>/ route"""


class ReadOnlyView(SortableMixin,
                   ListMixin,
                   RetrieveMixin,
                   GenericView):
    """A generic view with list and retrieve endpoints

    It is just a GenericView inheriting also from ListMixin,
    RetrieveMixin and SortableMixin.
    """


class ReadOnlyWorkspacedView(SortableMixin,
                             ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A workspaced generic view with list and retrieve endpoints

    It is just a GenericWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveWorkspacedMixin and SortableMixin"""


class ReadOnlyMultiWorkspacedView(SortableMixin,
                                  ListWorkspacedMixin,
                                  RetrieveMultiWorkspacedMixin,
                                  GenericMultiWorkspacedView):
    """A multi workspaced generic view with list and retrieve endpoints

    It is just a GenericMultiWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveMultiWorkspacedMixin and SortableMixin"""


class CreateMixin:
    """Add POST / route"""

    def post(self, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Creates {class_model}
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        context = {'updating': False}

        data = self._parse_data(self._get_schema_instance(kwargs, context=context), request)
        data.pop('id', None)
        created = self._perform_create(data, **kwargs)
        if not current_user.is_anonymous:
            created.creator = current_user
        db.session.commit()
        return self._dump(created, kwargs), HTTP_CREATED

    def _perform_create(self, data, **kwargs):
        """Check for conflicts and create a new object

        Is is passed the data parsed by the marshmallow schema (it
        transform from raw post data to a JSON)
        """
        obj = self.model_class(**data)
        # assert not db.session.new
        try:
            db.session.add(obj)
            db.session.commit()
            logger.info(f"{obj} created")
        except IntegrityError as ex:
            logger.info(f"Couldn't create {obj}")
            if not is_unique_constraint_violation(ex):
                if not_null_constraint_violation(ex):
                    abort(make_response({'message': 'Be sure to send all required parameters.'}, HTTP_BAD_REQUEST))
                else:
                    raise
            db.session.rollback()
            conflict_obj = get_conflict_object(db.session, obj, data)
            if conflict_obj:
                abort(HTTP_CONFLICT, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            else:
                raise
        return obj


class CommandMixin:
    """
        Created the command obj to log model activity after a command
        execution via the api (ex. from plugins)
        This will use GET parameter command_id.
        NOTE: GET parameters are also available in POST requests
    """

    @staticmethod
    def _set_command_id(obj, created):
        try:
            # validates the data type from user input.
            command_id = int(request.args.get('command_id', None))
        except TypeError:
            command_id = None

        if command_id:
            command = db.session.query(Command).filter(Command.id == command_id,
                                                       Command.workspace == obj.workspace).first()
            if command is None:
                raise InvalidUsage('Command not found.')
            # if the object is created and updated in the same command
            # the command object already exists
            # we skip the creation.
            object_type = obj.__class__.__table__.name

            command_object = CommandObject.query.filter_by(
                object_id=obj.id,
                object_type=object_type,
                command=command,
                workspace=obj.workspace,
            ).first()
            if created or not command_object:
                command_object = CommandObject(
                    object_id=obj.id,
                    object_type=object_type,
                    command=command,
                    workspace=obj.workspace,
                    created_persistent=created
                )

            db.session.add(command)
            db.session.add(command_object)


class CreateWorkspacedMixin(CreateMixin, CommandMixin):
    """Add POST /<workspace_name>/<route_base>/ route

    If a GET parameter command_id is passed, it will create a new
    CommandObject associated to that command to register the change in
    the database.
    """

    def post(self, workspace_name=None):
        """
        ---
          tags: ["{tag_name}"]
          summary: Creates {class_model}
          parameters:
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().post(workspace_name=workspace_name)

    def _perform_create(self, data, workspace_name):
        assert not db.session.new
        workspace = get_workspace(workspace_name)
        obj = self.model_class(**data)
        obj.workspace = workspace
        # assert not db.session.new
        try:
            db.session.add(obj)
            db.session.commit()
            logger.info(f"{obj} created")
        except IntegrityError as ex:
            logger.info(f"Couldn't create {obj}")
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = get_workspace(workspace_name)
            conflict_obj = get_conflict_object(db.session, obj, data, workspace)
            if conflict_obj:
                abort(HTTP_CONFLICT, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            else:
                raise

        self._set_command_id(obj, True)
        return obj


class UpdateMixin:
    """Add PUT /<id>/ route"""

    def put(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """

        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context), request)
        # just in case a schema allows id as writable.
        data.pop('id', None)

        self._update_object(obj, data, partial=False)
        self._perform_update(object_id, obj, data, **kwargs)

        return self._dump(obj, kwargs), HTTP_OK

    def _update_object(self, obj, data, **kwargs):
        """Perform changes in the selected object

        It modifies the attributes of the SQLAlchemy model to match
        the data passed by the Marshmallow schema.

        It is common to overwrite this method to do something strange
        with some specific field. Typically the new method should call
        this one to handle the update of the rest of the fields.
        """
        for (key, value) in data.items():
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, **kwargs):
        """Commit the SQLAlchemy session, check for updating conflicts"""
        try:
            db.session.add(obj)
            db.session.commit()
            logger.info(f"{obj} updated")
        except IntegrityError as ex:
            db.session.rollback()
            logger.info(f"Couldn't update {obj}")
            if not is_unique_constraint_violation(ex):
                raise
            workspace = None
            if workspace_name:
                workspace = db.session.query(Workspace).filter_by(name=workspace_name).first()
            conflict_obj = get_conflict_object(db.session, obj, data, workspace)
            if conflict_obj:
                abort(HTTP_CONFLICT, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            else:
                raise
        return obj

    def patch(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        exclude = kwargs.pop('exclude', [])
        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context, partial=True), request)
        # just in case a schema allows id as writable.
        data.pop('id', None)
        self._update_object(obj, data, partial=True)
        self._perform_update(object_id, obj, data, partial=True, **kwargs)

        return self._dump(obj, kwargs, exclude=exclude), HTTP_OK


class BulkUpdateMixin(FilterObjects):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['PATCH'])
    def bulk_update(self, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Update a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        workspace_name = kwargs.get('workspace_name') if 'workspace_name' in kwargs else None

        # Try to get ids
        _json = request.get_json(silent=True)
        if _json and 'ids' in _json:
            ids = list(filter(lambda x: type(x) is self.lookup_field_type, _json['ids']))

        # Try filter if no ids
        elif request.args.get('q', None) is not None:
            _time = time()
            ids = self._process_filter_data(request.args.get('q', '{"filters": []}'), workspace_name)
            logger.debug(f"Filtering took {time() - _time} seconds")
        else:
            abort(HTTP_BAD_REQUEST)

        _time = time()
        objects = self._get_bulk_update_objects(ids, **kwargs)
        if objects and isinstance(objects[0], Workspace):
            ids = [obj.name for obj in objects]  # had to do this because lookup field is name in workspaces.
        else:
            ids = [obj.id for obj in objects]
        logger.debug(f"Getting objects took {time() - _time} seconds")
        context = {'updating': True, 'objects': objects}
        _time = time()
        data = self._parse_data(self._get_schema_instance(kwargs, context=context, partial=True), request)
        logger.debug(f"Parsing data took {time() - _time} seconds")
        # just in case a schema allows id as writable.
        data.pop('id', None)
        data.pop('ids', None)

        return self._perform_bulk_update(ids, data, **kwargs), HTTP_OK

    def _get_bulk_update_objects(self, ids, **kwargs):
        """Load objects needed for bulk_update context and id extraction.

        Override this to avoid loading full ORM instances when the schema
        does not use context['objects'] (e.g. vulns).
        """
        return self._get_objects(ids, **kwargs)

    def _bulk_update_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        return self.model_class.query.filter(self.model_class.id.in_(ids))

    def _pre_bulk_update(self, data, **kwargs):
        return {}

    def _post_bulk_update(self, ids, extracted_data, workspace_name=None, data=None, **kwargs):
        pass

    def _perform_bulk_update(self, ids, data, workspace_name=None, **kwargs):
        try:
            post_bulk_update_data = self._pre_bulk_update(data, workspace_name=workspace_name, **kwargs)
            if (len(data) > 0 or len(post_bulk_update_data) > 0) and len(ids) > 0:
                returns = None
                _time = time()
                if 'returning' in kwargs:
                    returns = db.session.execute(sqlalchemy_update(self.model_class)
                                                 .where(self.model_class.id.in_(ids))
                                                 .values(data).returning(*kwargs['returning']))
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


class UpdateWorkspacedMixin(UpdateMixin, CommandMixin):
    """Add PUT /<workspace_name>/<route_base>/<id>/ route

    If a GET parameter command_id is passed, it will create a new
    CommandObject associated to that command to register the change in
    the database.
    """

    def put(self, object_id, workspace_name=None, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().put(object_id, workspace_name=workspace_name, **kwargs)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False):
        # # Make sure that if I created new objects, I had properly committed them
        # assert not db.session.new

        with db.session.no_autoflush:
            obj.workspace = get_workspace(workspace_name)

        self._set_command_id(obj, False)
        return super()._perform_update(object_id, obj, data, workspace_name)

    def patch(self, object_id, workspace_name=None, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().patch(object_id, workspace_name=workspace_name, **kwargs)


class BulkUpdateWorkspacedMixin(BulkUpdateMixin):

    @route('', methods=['PATCH'])
    def bulk_update(self, workspace_name, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        return super().bulk_update(workspace_name=workspace_name)

    def _bulk_update_query(self, ids, **kwargs):
        workspace = get_workspace(kwargs["workspace_name"])
        return super()._bulk_update_query(ids).filter(self.model_class.workspace_id == workspace.id)


class DeleteMixin:
    """Add DELETE /<id>/ route"""

    def delete(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Deletes {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
                type: integer
          responses:
            204:
              description: The resource was deleted successfully
        """
        obj = self._get_object(object_id, **kwargs)
        self._perform_delete(obj, **kwargs)
        # TODO: Check _post_delete def differences with corp
        return None, HTTP_NO_CONTENT

    def _perform_delete(self, obj, workspace_name=None):
        db.session.delete(obj)
        db.session.commit()
        logger.info(f"{obj} deleted")


class BulkDeleteMixin(FilterObjects):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['DELETE'])
    def bulk_delete(self, *args, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        # TODO BULK_DELETE_SCHEMA
        # Try to get ids
        _json = request.get_json(silent=True)
        if _json and 'ids' in _json:
            ids = list(filter(lambda x: type(x) is self.lookup_field_type, _json['ids']))

        # Try filter if no ids
        elif request.args.get('q', None) is not None:
            filtered_objects = self._process_filter_data(request.args.get('q', '{"filters": []}'))
            ids = filtered_objects
        else:
            abort(HTTP_BAD_REQUEST)

        if not self.__class__.model_class == Workspace:
            objects = self._get_objects(ids, **kwargs)
            ids = [obj.id for obj in objects]

        response = self._perform_bulk_delete(ids, **kwargs), HTTP_OK
        self._post_bulk_delete(ids, **kwargs)
        return self._bulk_delete_response(ids, response, **kwargs)

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        return self.model_class.query.filter(self.model_class.id.in_(ids))

    def _perform_bulk_delete(self, values, **kwargs):
        deleted = self._bulk_delete_query(values, **kwargs).delete(synchronize_session='fetch')
        db.session.commit()
        response = {'deleted': deleted}
        return jsonify(response)

    def _post_bulk_delete(self, ids, **kwargs):
        pass

    def _bulk_delete_response(self, ids, response, **kwargs):
        return response


class DeleteWorkspacedMixin(DeleteMixin):
    """Add DELETE /<workspace_name>/<route_base>/<id>/ route"""

    def delete(self, object_id, workspace_name=None):
        """
          ---
            tags: ["{tag_name}"]
            summary: Deletes {class_model}
            parameters:
            - in: path
              name: object_id
              required: true
              schema:
                type: integer
            - in: path
              name: workspace_name
              required: true
              schema:
                type: string
            responses:
              204:
                description: The resource was deleted successfully
        """
        return super().delete(object_id, workspace_name=workspace_name)

    def _perform_delete(self, obj, workspace_name=None):
        with db.session.no_autoflush:
            obj.workspace = get_workspace(workspace_name)
        return super()._perform_delete(obj, workspace_name)


class BulkDeleteWorkspacedMixin(BulkDeleteMixin):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['DELETE'])
    def bulk_delete(self, workspace_name, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        return super().bulk_delete(workspace_name=workspace_name)

    def _bulk_delete_query(self, ids, **kwargs):
        workspace = get_workspace(kwargs.pop("workspace_name"))
        return super()._bulk_delete_query(ids).filter(self.model_class.workspace_id == workspace.id)


class CountWorkspacedMixin:
    """Add GET /<workspace_name>/<route_base>/count/ route

    Group objects by the field set in the group_by GET parameter. If it
    isn't specified, the view will return a 404 error. For each group,
    show the count of elements and its value.

    This view is often used by some parts of the web UI. It was designed
    to keep backwards compatibility with the count endpoint of Faraday
    v2.
    """

    #: List of SQLAlchemy query filters to apply when counting
    count_extra_filters = []

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

        workspace_name = kwargs.pop('workspace_name')
        # using format is not a great practice.
        # the user input is group_by, however it's filtered by column name.
        table_name = inspect(self.model_class).tables[0].name
        group_by = column(f'{table_name}.{group_by}', is_literal=True)

        query_count = self._filter_query(
            db.session.query(self.model_class).
            join(Workspace, Workspace.id == self.model_class.workspace_id).
            group_by(group_by).
            filter(Workspace.name == workspace_name,
                   *self.count_extra_filters)
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


class CountMultiWorkspacedMixin:
    """Add GET /<workspace_name>/<route_base>/count_multi_workspace/ route

    Receives a list of workspaces separated by comma in the workspaces
    GET parameter.
    If no workspace is specified, the view will return a 400 error.

    Group objects by the field set in the group_by GET parameter. If it
    isn't specified, the view will return a 400 error. For each group,
    show the count of elements and its value.

    This view is often used by some parts of the web UI. It was designed
    to keep backwards compatibility with the count endpoint of Faraday
    v2.
    """

    #: List of SQLAlchemy query filters to apply when counting
    count_extra_filters = []

    def count_multi_workspace(self, **kwargs):
        """
        ---
          tags: [{tag_name}]
          summary: "Count {class_model} by multiples workspaces"
          parameters:
          - in: query
            name: workspaces
            required: true
            description: "Comma-separated workspace names to count across. Endpoint returns 400 if omitted."
            schema:
              type: string
          - in: query
            name: group_by
            required: true
            description: "Column to group by. Endpoint returns 400 if omitted."
            schema:
              type: string
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            400:
              description: No workspace passed or group_by is not specified
        """
        res = {
            'groups': defaultdict(dict),
            'total_count': 0
        }

        workspace_names_list = request.args.get('workspaces', None)

        if not workspace_names_list:
            abort(HTTP_BAD_REQUEST, {"message": "workspaces is a required parameter"})

        workspace_names_list = workspace_names_list.split(',')

        # Enforce workspace permission checking for each workspace
        for workspace_name in workspace_names_list:
            get_workspace(workspace_name)

        group_by, sort_dir = get_group_by_and_sort_dir(self.model_class)

        grouped_attr = getattr(self.model_class, group_by)

        q = db.session.query(
            Workspace.name,
            grouped_attr,
            func.count(grouped_attr)
        ) \
            .join(Workspace) \
            .group_by(grouped_attr, Workspace.name) \
            .filter(Workspace.name.in_(workspace_names_list))

        # order
        order_by = grouped_attr
        if sort_dir == 'desc':
            q = q.order_by(desc(Workspace.name), desc(order_by))
        else:
            q = q.order_by(asc(Workspace.name), asc(order_by))

        for workspace, key, count in q.all():
            res['groups'][workspace][key] = count
            res['total_count'] += count

        return res
