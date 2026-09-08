"""
Tests de los cambios ponytail (regresiones P0 + split Y3 + sharding) —
determinísticos, sin Postgres: corren en cualquier entorno (py>=3.11).
"""
import sys
import unittest.mock as mock

import pytest


# ------------------------------------------------- Y3: split base.py re-exports
def test_base_reexports_complete():
    """Contrato: todos los nombres que modules/* importan de base siguen ahí."""
    from faraday.server.api import base
    names = [
        'GenericView', 'GenericWorkspacedView', 'GenericMultiWorkspacedView',
        'ListMixin', 'SortableMixin', 'PaginatedMixin', 'FilterAlchemyMixin',
        'FilterWorkspacedMixin', 'FilterObjects', 'FilterMixin',
        'ListWorkspacedMixin', 'RetrieveMixin', 'RetrieveWorkspacedMixin',
        'RetrieveMultiWorkspacedMixin', 'ReadOnlyView', 'ReadOnlyWorkspacedView',
        'ReadOnlyMultiWorkspacedView', 'CreateMixin', 'CommandMixin',
        'CreateWorkspacedMixin', 'UpdateMixin', 'BulkUpdateMixin',
        'UpdateWorkspacedMixin', 'BulkUpdateWorkspacedMixin', 'DeleteMixin',
        'BulkDeleteMixin', 'DeleteWorkspacedMixin', 'BulkDeleteWorkspacedMixin',
        'CountWorkspacedMixin', 'CountMultiWorkspacedMixin',
        'ReadWriteView', 'ReadWriteWorkspacedView',
        'get_workspace', 'InvalidUsage', 'AutoSchema', 'route', 'FlaskView',
        'CustomModelConverter', 'get_user_permissions', 'ContextMixin',
        'output_json', 'get_filtered_data', 'hydrate_sample_for_conflict',
        'get_group_by_and_sort_dir', 'logger',
    ]
    missing = [n for n in names if not hasattr(base, n)]
    assert not missing, f"re-exports rotos en base.py: {missing}"


def test_core_mixins_modules_import_clean():
    from faraday.server.api import core, mixins  # noqa: F401
    # layering sin ciclos: core no importa mixins ni base
    core_src = open(core.__file__).read()
    assert 'from faraday.server.api.mixins' not in core_src
    assert 'from faraday.server.api.base' not in core_src
    # mixins solo importa de core
    mixins_src = open(mixins.__file__).read()
    assert 'from faraday.server.api.base' not in mixins_src


# ------------------------------------------------- P0: workspace_repo SQL crudo
def test_workspace_repo_sql_has_upstream_column_contract():
    """El transplant del SQL debe conservar las 21 columnas de conteo + stats."""
    from faraday.repo.workspace_repo import WorkspaceRepository
    import inspect
    src = inspect.getsource(WorkspaceRepository.query_with_count)
    for col in [
        'credentials_count', 'host_count', 'last_run_agent_date',
        'open_services', 'total_service_count',
        'vulnerability_web_count', 'vulnerability_code_count',
        'vulnerability_standard_count', 'vulnerability_total_count',
        'vulnerability_critical_count', 'vulnerability_high_count',
        'vulnerability_medium_count', 'vulnerability_low_count',
        'vulnerability_informational_count', 'vulnerability_unclassified_count',
        'vulnerability_open_count', 'vulnerability_confirmed_count',
        'vulnerability_closed_count', 'vulnerability_web_confirmed_count',
        'vulnerability_web_closed_count',
        'vulnerability_confirmed_and_not_closed_count',
        'vulnerability_web_confirmed_and_not_closed_count',
        'scope_raw', 'workspace_name',
    ]:
        assert f'as {col}'.title().replace('As ', 'AS ') in src or col in src, \
            f"falta columna {col} en query_with_count"
    # params determinísticos
    for param in [':active', ':readonly', ':workspace_name']:
        assert param in src


# ------------------------------------------------- P0: debouncer TESTING guard
def test_debouncer_testing_runs_sync():
    """En TESTING la acción corre síncrona (el worker no ve la DB del test)."""
    from faraday.server import debouncer as d
    calls = []

    def action(**kw):
        calls.append(kw)

    fake_server = mock.Mock()
    fake_server.celery_enabled = True
    fake_app = mock.Mock()
    fake_app.config = {'TESTING': True}

    with mock.patch.object(d, 'faraday_server', fake_server), \
         mock.patch('faraday.server.app.faraday_server', fake_server), \
         mock.patch('flask.current_app', fake_app), \
         mock.patch.object(d, 'get_redis_client'), \
         mock.patch('faraday.server.app.logger'):
        class _D(d.Debouncer):
            def __init__(self, wait=10):  # sin redis real
                self.wait = wait

        _D(1).debounce(action, {'workspace_id': 7})
    assert calls == [{'workspace_id': 7}]


def test_debouncer_mocked_server_respects_async_path():
    """Los unit tests que parchean faraday_server prueban el camino async."""
    from faraday.server import debouncer as d
    fake_server = mock.Mock()
    fake_server.celery_enabled = True
    fake_app = mock.Mock()
    fake_app.config = {'TESTING': True}

    enqueued = []
    with mock.patch.object(d, 'faraday_server', fake_server), \
         mock.patch('flask.current_app', fake_app), \
         mock.patch.object(d, 'get_redis_client'), \
         mock.patch('faraday.server.app.logger'), \
         mock.patch.object(d, '_debounce_key_for_workspace',
                           return_value='k'), \
         mock.patch('faraday.server.tasks.execute_debounced_action') as task:
        task.apply_async.side_effect = lambda *a, **kw: enqueued.append(kw)
        d.Debouncer(1).debounce(lambda **kw: None, {'workspace_id': 7})
    assert len(enqueued) == 1 and enqueued[0]['countdown'] == 1


# ------------------------------------------------- P0: tasks._is_testing
def test_tasks_is_testing_guard():
    from faraday.server import tasks as t
    fake_app = mock.Mock()
    fake_app.config = {'TESTING': True}
    with mock.patch('flask.current_app', fake_app):
        assert t._is_testing() is True
    fake_app2 = mock.Mock()
    fake_app2.config = {'TESTING': False}
    with mock.patch('flask.current_app', fake_app2):
        assert t._is_testing() is False


# ------------------------------------------------- P0: eagerloads sin conflictos
def test_agent_view_joinedloads_no_strategy_conflict():
    """A11 fix: un solo strategy por path (nplusone/sqlalchemy no explota)."""
    from faraday.server.api.modules.agent import AgentView
    from faraday.server.models import Agent, db
    opts = AgentView.get_joinedloads()
    assert isinstance(opts, list) and opts
    # aplicar a una query real: SQLAlchemy lanza en caso de conflicto de paths
    q = db.session.query(Agent)
    q.options(*opts)  # no raise


def test_agents_schedule_joinedloads_are_classmethod():
    """V3 fix: classmethod (el atributo con Loads armados hace double-wrap)."""
    from faraday.server.api.modules.agents_schedule import AgentsScheduleView
    from faraday.server.models import AgentsSchedule, db
    assert isinstance(AgentsScheduleView.__dict__.get('get_joinedloads'),
                      (classmethod, staticmethod))
    opts = AgentsScheduleView.get_joinedloads()
    db.session.query(AgentsSchedule).options(*opts)  # no raise


def test_services_filter_keeps_creator_for_owner():
    """P0 fix: /services/filter serializa owner -> creator debe estar eager."""
    from faraday.server.api.modules.services_base import ServiceView
    from faraday.server.api.modules.services_base import Service
    import inspect as _inspect
    src = _inspect.getsource(ServiceView._filter_eagerload_options)
    assert 'joinedload(Service.creator)' in src


# ------------------------------------------------- sharding: identidad domain/server
def test_shard_identity_server_first():
    """Server-first: cada entidad resuelve a la clase del shard domain."""
    import faraday.server.models as s
    pairs = [
        ('faraday.domain.host_service.models', 'Host'),
        ('faraday.domain.host_service.models', 'Service'),
        ('faraday.domain.host_service.models', 'Credential'),
        ('faraday.domain.workspace.models', 'Workspace'),
        ('faraday.domain.user_auth.models', 'User'),
        ('faraday.domain.user_auth.models', 'Role'),
        ('faraday.domain.vulnerability.models', 'Vulnerability'),
        ('faraday.domain.vulnerability.models', 'VulnerabilityGeneric'),
        ('faraday.domain.command.models', 'Command'),
        ('faraday.domain.agent_workflow.models', 'Agent'),
        ('faraday.domain.agent_workflow.models', 'Pipeline'),
        ('faraday.domain.notification.models', 'Notification'),
        ('faraday.domain.notification.models', 'Comment'),
        ('faraday.domain.reporting.models', 'ExecutiveReport'),
        ('faraday.domain.tagging.models', 'Tag'),
    ]
    for mod_name, cls_name in pairs:
        mod = __import__(mod_name, fromlist=[cls_name])
        cls = getattr(mod, cls_name)
        assert getattr(s, cls_name) is cls, (
            f"{cls_name}: server.models y {mod_name} difieren")
