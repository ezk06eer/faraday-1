"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import logging
from datetime import datetime, timedelta

import pytest

from faraday.server.config import faraday_server
from faraday.server.utils.celery import require_celery_enabled
from faraday.server.utils.command import run_failed_command_stats_inline


class TestRequireCeleryEnabled:
    """The standalone faraday-worker/faraday-beat binaries must refuse to start
    when celery is disabled, instead of silently falling back to celery's
    default broker with an empty schedule."""

    def test_exits_when_celery_is_disabled(self, monkeypatch):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        with pytest.raises(SystemExit):
            require_celery_enabled('beat')

    def test_returns_when_celery_is_enabled(self, monkeypatch):
        monkeypatch.setattr(faraday_server, 'celery_enabled', True)
        require_celery_enabled('beat')


class TestRunFailedCommandStatsInline:
    """With celery disabled there is no beat scheduler, so the server runs
    update_failed_command_stats itself on boot."""

    def test_selects_only_hosts_of_recent_failed_commands(
        self,
        monkeypatch,
        caplog,
        app,
        session,
        workspace,
        host_factory,
        vulnerability_factory,
        command_factory,
        command_object_factory,
    ):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        recent_command = command_factory.create(workspace=workspace,
                                                end_date=None,
                                                create_date=datetime.utcnow())
        old_command = command_factory.create(workspace=workspace,
                                             end_date=None,
                                             create_date=datetime.utcnow() - timedelta(days=10))
        recent_host = host_factory.create(workspace=workspace)
        old_host = host_factory.create(workspace=workspace)
        session.add_all([recent_command, old_command, recent_host, old_host])
        session.commit()

        session.add_all([
            command_object_factory.create(command_id=recent_command.id,
                                          object_id=recent_host.id,
                                          object_type='host',
                                          created_persistent=True,
                                          workspace=workspace),
            command_object_factory.create(command_id=old_command.id,
                                          object_id=old_host.id,
                                          object_type='host',
                                          created_persistent=True,
                                          workspace=workspace),
            vulnerability_factory.create(workspace=workspace, host=recent_host,
                                         service=None, confirmed=True,
                                         status='open', severity='high'),
            vulnerability_factory.create(workspace=workspace, host=old_host,
                                         service=None, confirmed=True,
                                         status='open', severity='high'),
        ])
        session.commit()
        recent_host_id, old_host_id = recent_host.id, old_host.id

        with caplog.at_level(logging.DEBUG, logger='faraday.server.tasks'):
            run_failed_command_stats_inline(app)

        stats_calls = [r.message for r in caplog.records
                       if r.message.startswith('Calculating vulns stats for host')]
        assert f'Calculating vulns stats for host {recent_host_id}' in stats_calls
        # Commands older than 7 days are skipped, so this host is left untouched.
        assert f'Calculating vulns stats for host {old_host_id}' not in stats_calls

    def test_does_not_raise_when_there_is_nothing_to_update(self, monkeypatch, app, session, workspace):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        session.commit()
        run_failed_command_stats_inline(app)

    def test_swallows_task_errors_so_the_server_still_boots(self, monkeypatch, caplog, app):
        def boom(*args, **kwargs):
            raise RuntimeError('broken')

        monkeypatch.setattr('faraday.server.tasks.update_failed_command_stats', boom)

        with caplog.at_level(logging.ERROR, logger='faraday.server.utils.command'):
            run_failed_command_stats_inline(app)

        assert any('broken' in r.message for r in caplog.records)
