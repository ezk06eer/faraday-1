"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""Core API: GenericView, helpers y conversiones (extraído de base.py, Y3)."""
from http.client import (
    BAD_REQUEST as HTTP_BAD_REQUEST,
    CONFLICT as HTTP_CONFLICT,
    FORBIDDEN as HTTP_FORBIDDEN,
    INTERNAL_SERVER_ERROR as HTTP_INTERNAL_SERVER_ERROR,
    NOT_FOUND as HTTP_NOT_FOUND,
    UNAUTHORIZED as HTTP_UNAUTHORIZED,
    UNPROCESSABLE_ENTITY as HTTP_UNPROCESSABLE_ENTITY,
)
from json import dumps as json_dumps
from logging import getLogger

# Related third party imports
from flask import abort, jsonify, make_response, request
from flask_classful import FlaskView
from flask_login import current_user
from marshmallow import EXCLUDE
from marshmallow.validate import Length
from marshmallow_sqlalchemy import ModelConverter
from marshmallow_sqlalchemy.schema import SQLAlchemyAutoSchemaOpts
from sqlalchemy.engine import CursorResult, MappingResult, Result, ResultProxy
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import joinedload, undefer
from sqlalchemy.orm.exc import NoResultFound, ObjectDeletedError
from webargs.flaskparser import FlaskParser

# Local application imports
from faraday.server.config import faraday_server
from faraday.server.models import (
    User,
    Workspace,
    db,
)


logger = getLogger(__name__)


def output_json(data, code, headers=None):
    content_type = 'application/json'
    dumped = json_dumps(data)
    if headers:
        headers.update({'Content-Type': content_type})
    else:
        headers = {'Content-Type': content_type}
    response = make_response(dumped, code, headers)
    return response


def get_filtered_data(filters, filter_query):
    column_names = ['count'] + [field['field'] for field in filters.get('group_by', [])]
    rows = [list(zip(column_names, row)) for row in filter_query.all()]
    data = []
    for row in rows:
        data.append({field[0]: field[1] for field in row})

    return data, len(rows)


def hydrate_sample_for_conflict(model_class, ids):
    # Hydrate from the first id so get_conflict_object can fall back to real
    # column values for unique-index fields absent from `data`. See ticket 8232:
    # empty model instances synthesize a filter that never matches the real
    # conflicting row, turning the 409 into a 500.
    sample = model_class()
    if ids:
        sample = (
            db.session.query(model_class)
            .filter(model_class.id == ids[0])
            .first()
        ) or sample
    return sample


def get_group_by_and_sort_dir(model_class):
    group_by = request.args.get('group_by', None)
    sort_dir = request.args.get('order', "asc").lower()

    # TODO migration: whitelist fields to avoid leaking a confidential
    # field's value.
    # Example: /users/count/?group_by=password
    # Also we should check that the field exists in the db and isn't, for
    # example, a relationship
    if not group_by or group_by not in inspect(model_class).attrs:
        abort(HTTP_BAD_REQUEST, {"message": "group_by is a required parameter"})

    if sort_dir and sort_dir not in ('asc', 'desc'):
        abort(HTTP_BAD_REQUEST, {"message": "order must be 'desc' or 'asc'"})

    return group_by, sort_dir


def get_workspace(workspace_name):
    # Delegates to WorkspaceRepository (ponytail repo layer, keeps contracts.md wire)
    try:
        from faraday.repo.workspace_repo import WorkspaceRepository  # pylint: disable=import-outside-toplevel

        return WorkspaceRepository.get_by_name(workspace_name)
    except ImportError:
        # Fallback legacy (tests without repo deps)
        ws = None
        if not current_user.is_anonymous:
            try:
                ws = Workspace.query.filter_by(name=workspace_name).one()
                if not ws.active:
                    abort(HTTP_FORBIDDEN, f"Disabled workspace: {workspace_name}")
            except NoResultFound:
                abort(HTTP_NOT_FOUND, f"No such workspace: {workspace_name}")
        else:
            try:
                ws = Workspace.query.filter_by(name=workspace_name).one()
                if not ws.active:
                    abort(HTTP_UNAUTHORIZED)
            except NoResultFound:
                abort(HTTP_UNAUTHORIZED)
        return ws


class InvalidUsage(Exception):
    status_code = HTTP_BAD_REQUEST

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


# TODO: Require @view decorator to enable custom routes
class GenericView(FlaskView):
    """Abstract class to provide generic views. Inspired in `Django REST
    Framework generic viewsets`_.

    To create new views, you should create a class inheriting from
    GenericView (or from one of its subclasses) and set the model_class,
    schema_class, and optionally the rest of class attributes.

    Then, you should register it with your app by using the ``register``
    classmethod.

    .. _Django REST Framework generic viewsets: https://www.django-rest-framework.org/api-guide/viewsets/#genericviewset
    """

    # Must-implement attributes

    #: **Required**. The class of the SQLAlchemy model this view will handle
    model_class = None
    #: **Required** (unless _get_schema_class is overwritten).
    #: A subclass of `marshmallow.Schema` to serialize and deserialize the
    #: data provided by the user
    schema_class = None

    # Default attributes

    #: The prefix where the endpoint should be registered.
    #: This is useful for API versioning
    route_prefix = '/v3/'

    #: Arguments that are passed to the view but shouldn't change the route
    #: rule. This should be used when route_prefix is parametrized
    #:
    #: You typically won't need this, unless you're creating nested views.
    #: For example GenericWorkspacedView use this so the workspace name is
    #: prepended to the view URL
    base_args = []

    #: Decides how you want to format the output response. It is set to dump a
    #: JSON object by default.
    #: See http://flask-classful.teracy.org/#adding-resource-representations-get-real-classy-and-put-on-a-top-hat
    #: for more information
    representations = {
        'application/json': output_json,
        'flask-classful/default': output_json,
    }

    ""
    #: Name of the field of the model used to get the object instance in
    #: retrieve, update and delete endpoints.
    #:
    #: For example, if you have a `Tag` model, maybe a `slug` would be good
    #: lookup field.
    #:
    #: .. note::
    #:     You must use a unique field here instead of one allowing
    #:     duplicate values
    #:
    #: .. note::
    #:     By default the lookup field value must be a valid integer. If you
    #:     want to allow any string, like with the slug field, make sure that
    #:     you set lookup_field_type to `string`
    lookup_field = 'id'

    #: A function that converts the string parameter passed in the URL to the
    #: value that will be queried in the database.
    #: It defaults to int to match the type of the default lookup_field_type
    #: (id)
    lookup_field_type = int

    # Attributes to improve the performance of list and retrieve views

    #: List of relationships to eagerload in list and retrieve views.
    #:
    #: This is useful when you when you want to retrieve all children
    #: of an object in an API response, like for example if you want
    #: to have all hostnames of each host in the hosts endpoint.
    get_joinedloads = []  # List of relationships to eagerload

    #: List of columns that will be loaded directly when performing an
    #: eagerloaded query.
    #:
    #: This is useful when you have a column that is typically deferred because
    #: typically is isn't used, like the vuln creator. If you know you will use
    #: it, indicate it here to prevent doing an extra SQL query.
    get_undefer = []  # List of columns to undefer

    trailing_slash = False

    def _get_schema_class(self):
        """By default, it returns ``self.schema_class``.

        You can override it to define a custom behavior to be used
        in all views.
        """
        assert self.schema_class is not None, "You must define schema_class"
        return self.schema_class

    def _get_schema_instance(self, route_kwargs, **kwargs):
        """Instances a model schema.

        It also uses _set_schema_context to set the context of the
        schema.
        """
        kwargs['context'] = self._set_schema_context(
            kwargs.get('context', {}), **route_kwargs)

        # If the client send us fields that are not in the schema, ignore them
        # This is the default in marshmallow 2, but not in marshmallow 3
        kwargs['unknown'] = EXCLUDE

        return self._get_schema_class()(**kwargs)

    def _set_schema_context(self, context, **kwargs):
        """This function can be overridden to update the context passed
        to the schema.
        """
        return context

    def _get_lookup_field(self):
        """Get a Field instance based on ``self.model_class`` and
        ``self.lookup_field``
        """
        return getattr(self.model_class, self.lookup_field)

    def _validate_object_id(self, object_id, raise_error=True):
        """
        By default, it validates the value of the lookup field set by the user
        in the URL by calling ``self.lookup_field_type(object_id)``.
        If that raises a ValueError, que view will fail with error
        code 404.
        """
        try:
            self.lookup_field_type(object_id)
        except ValueError:
            if raise_error:
                abort(HTTP_NOT_FOUND, 'Invalid format of lookup field')
            return False
        return True

    def _get_base_query(self, *args, **kwargs):
        """Return the initial query all views should use

        .. warning::
            When you are creating views, avoid making SQL queries that
            don't inherit from this base query. You could easily forget
            to add workspace permission checks and similar stuff.
        """
        query = self.model_class.query
        return query

    def _get_eagerloaded_query(self, *args, **kwargs):
        """Load objects related to the current model in a single query.

        This is useful to prevent n+1 SQL problems, where a request to an
        object with many childs makes many SQL requests that tends to be
        slow.

        You typically won't need to overwrite this method, but to set
        get_joinedloads and get_undefer attributes that are used by
        this method.

        In really complex cases where good performance is required,
        like in the vulns API endpoint, you will have to overwrite this.
        """
        options = []
        try:
            has_creator = 'owner' in self._get_schema_class().opts.fields
        except AttributeError:
            has_creator = False
        if has_creator:
            # APIs for objects with metadata always return the creator's
            # username. Do a joinedload to prevent doing one query per object
            # (n+1) problem
            options.append(joinedload(
                getattr(self.model_class, 'creator')).load_only(User.username))
        query = self._get_base_query(*args, **kwargs)
        options += [joinedload(relationship)
                    for relationship in self.get_joinedloads]
        options += [undefer(column) for column in self.get_undefer]
        return query.options(*options)

    def _filter_query(self, query):
        """Return a new SQLAlchemy query with some filters applied.

        By default it doesn't do anything. It is overridden by
        :class:`FilterAlchemyMixin` to give support to FilterAlchemy
        filters.

        .. warning::
            This is only used by the list endpoints. Don't use this
            to restrict the user the access for certain elements (like
            for example to restrict the items to one workspace). For
            this you must override _get_base_query instead.

            Always think that this filtering is optional, just a
            feature for the user to only see items he/she is interested
            in, so it is the user who will filter the data, not you

        """
        return query

    def _get_object(self, object_id, workspace_name=None, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        obj = None
        self._validate_object_id(object_id)
        if eagerload:
            query = self._get_eagerloaded_query(**kwargs)
        else:
            query = self._get_base_query(**kwargs)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            abort(HTTP_NOT_FOUND, f'Object with id "{object_id}" not found')
        return obj

    def _get_objects(self, object_ids, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        object_ids = [object_id for object_id in object_ids if self._validate_object_id(object_id, raise_error=False)]
        if eagerload:
            query = self._get_eagerloaded_query(**kwargs)
        else:
            query = self._get_base_query(**kwargs)
        try:
            obj = query.filter(self._get_lookup_field().in_(object_ids)).all()
        except AttributeError:
            # Handle the case where `query` is a raw-SQL Result (e.g. Workspace.query_with_count
            # returns a MappingResult from db.session.execute(text(...)).mappings()). Fall back to
            # a normal ORM query on the model.
            if isinstance(query, (ResultProxy, CursorResult, MappingResult, Result)):
                res = db.session.query(self.model_class).filter(self.model_class.name.in_(object_ids)).all()
                return res
            # If it's another AttributeError, re-raise
            raise
        except NoResultFound:
            return []
        return obj

    def _dump(self, obj, route_kwargs, **kwargs):
        """Serializes an object with the Marshmallow schema class
        returned by ``self._get_schema_class()``. Any passed kwargs
        will be passed to the ``__init__`` method of the schema.

        TODO migration: document route_kwargs
        """
        try:
            return self._get_schema_instance(route_kwargs, **kwargs).dump(obj)
        except ObjectDeletedError:
            return []

    @staticmethod
    def _parse_data(schema, request, *args, **kwargs):
        """Deserializes from a Flask request to a dict with valid
        data. It a ``Marshmallow.Schema`` instance to perform the
        deserialization
        """
        return FlaskParser(unknown=EXCLUDE).parse(schema, request, location="json",
                                                  *args, **kwargs)

    @classmethod
    def register(cls, app, *args, **kwargs):
        """Register and add JSON error handler. Use error code
        400 instead of 409"""
        super().register(app, *args, **kwargs)

        @app.errorhandler(HTTP_UNPROCESSABLE_ENTITY)
        def handle_error(err):  # pylint: disable=unused-variable
            # webargs attaches additional metadata to the `data` attribute
            exc = getattr(err, 'exc')
            if exc:
                # Get validations from the ValidationError object
                messages = exc.messages
            else:
                messages = ['Invalid request']
            return jsonify({
                'messages': messages,
            }), HTTP_BAD_REQUEST

        @app.errorhandler(HTTP_CONFLICT)
        def handle_conflict(err):  # pylint: disable=unused-variable
            # webargs attaches additional metadata to the `data` attribute
            exc = getattr(err, 'exc', None) or getattr(err, 'description', None)
            if exc:
                # Get validations from the ValidationError object
                messages = exc.messages
            else:
                messages = ['Invalid request']
            return jsonify(messages), HTTP_CONFLICT

        @app.errorhandler(HTTP_FORBIDDEN)
        def handle_forbidden(err):  # pylint: disable=unused-variable
            return jsonify({"message": err.description}), HTTP_FORBIDDEN

        @app.errorhandler(InvalidUsage)
        def handle_invalid_usage(error):  # pylint: disable=unused-variable
            response = jsonify(error.to_dict())
            response.status_code = error.status_code
            return response

        """# @app.errorhandler(404)
        def handle_not_found(err):  # pylint: disable=unused-variable
            response = {'success': False, 'message': err.description if faraday_server.debug else err.name}
            return flask.jsonify(response), 404"""

        @app.errorhandler(HTTP_INTERNAL_SERVER_ERROR)
        def handle_server_error(err):  # pylint: disable=unused-variable
            response = {'success': False,
                        'message': f"Exception: {err.original_exception}" if faraday_server.debug else
                        'Internal Server Error'}
            return jsonify(response), HTTP_INTERNAL_SERVER_ERROR


class GenericWorkspacedView(GenericView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL

    .. note::
        This view inherits from GenericView, so make sure you understand
        that first by checking the docs above, or just by looking at the
        source code of server/api/base.py.

    """

    # Default attributes
    route_prefix = '/v3/ws/<workspace_name>/'
    base_args = ['workspace_name']  # Required to prevent double usage of <workspace_name>

    def _get_base_query(self, workspace_name, **kwargs):
        base = super()._get_base_query()
        return base.join(
            Workspace, Workspace.id == self.model_class.workspace_id
        ).filter(
            Workspace.id == get_workspace(workspace_name).id)

    def _get_object(self, object_id, workspace_name=None, eagerload=False, **kwargs):
        self._validate_object_id(object_id)
        obj = None
        if eagerload:
            query = self._get_eagerloaded_query(workspace_name)
        else:
            query = self._get_base_query(workspace_name)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            abort(HTTP_NOT_FOUND, f'Object with id "{object_id}" not found')
        return obj

    def _set_schema_context(self, context, **kwargs):
        """Overridden to pass the workspace name to the schema"""
        context.update(kwargs)
        return context

    def before_request(self, name, *args, **kwargs):
        sup = super()
        if hasattr(sup, 'before_request'):
            sup.before_request(name, *args, **kwargs)
        if (get_workspace(kwargs['workspace_name']).readonly
                and request.method not in ['GET', 'HEAD', 'OPTIONS']):
            abort(HTTP_FORBIDDEN, "Altering a readonly workspace is not allowed")


class GenericMultiWorkspacedView(GenericWorkspacedView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL. The object can be accessed from more than one workspace.

    .. note::
        This view inherits from GenericWorkspacedView and GenericView, so make
        sure you understand those first by checking the docs above, or just
        by looking at the source code of server/api/base.py.

    """

    def _get_base_query(self, workspace_name, **kwargs):
        base = super(GenericWorkspacedView, self)._get_base_query()
        return base.filter(
            self.model_class.workspaces.any(
                name=get_workspace(workspace_name).name
            )
        )


class CustomModelConverter(ModelConverter):
    """
    Model converter that automatically sets minimum length
    validators to not blankable fields
    """

    def _add_column_kwargs(self, kwargs, column):
        super()._add_column_kwargs(kwargs, column)
        if not column.info.get('allow_blank', True):
            kwargs['validate'].append(Length(min=1))


class CustomSQLAlchemyAutoSchemaOpts(SQLAlchemyAutoSchemaOpts):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.model_converter = CustomModelConverter
