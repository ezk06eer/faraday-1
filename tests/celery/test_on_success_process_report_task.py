from unittest.mock import patch, MagicMock

from faraday.server import tasks


class TestCallbackDebouncesFinalization:
    """The chord callback no longer finalizes inline; it debounces finalize_report per command."""

    def test_debounces_finalize_report_and_keeps_per_batch_stats(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        session.commit()

        mock_debouncer = MagicMock()
        results = [{'created': True, 'host_id': 1}, {'created': True, 'host_id': 2}]
        with patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                patch.object(tasks, 'calc_vulnerability_stats') as m_calc, \
                patch.object(tasks, 'update_host_stats') as m_update:
            tasks.on_success_process_report_task(results, command_id=command.id)

        # Per-batch host stats still run for each created host...
        assert m_calc.delay.call_count == 2
        # ...finalization is NOT done inline anymore...
        m_update.delay.assert_not_called()
        # ...it is debounced once, per command, with finalize_report.
        assert mock_debouncer.debounce.call_count == 1
        args, kwargs = mock_debouncer.debounce.call_args
        assert args[0] is tasks.finalize_report
        assert args[1] == {"command_id": command.id, "workspace_id": workspace.id}
        assert kwargs["key_suffix"] == f"cmd_id:{command.id}"
        assert "wait" in kwargs

    def test_missing_command_returns_without_debouncing(self, session):
        mock_debouncer = MagicMock()
        with patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                patch.object(tasks, 'calc_vulnerability_stats'):
            tasks.on_success_process_report_task([], command_id=999999)
        mock_debouncer.debounce.assert_not_called()


class TestFinalizeReport:
    """finalize_report performs the once-per-command finalization."""

    def test_runs_finalization_once(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        session.commit()

        with patch.object(tasks, 'update_host_stats') as m_update, \
                patch.object(tasks, 'workflow_task'), \
                patch.object(tasks, 'debounce_workspace_update'):
            tasks.finalize_report(command_id=command.id, workspace_id=workspace.id)

        m_update.delay.assert_called_once()
        _, kwargs = m_update.delay.call_args
        assert kwargs["command_id"] == command.id
        assert kwargs["no_debounce"] is True  # import_source == "report"

    def test_unknown_command_is_noop(self, session, workspace):
        with patch.object(tasks, 'update_host_stats') as m_update, \
                patch.object(tasks, 'workflow_task'):
            tasks.finalize_report(command_id=999999, workspace_id=workspace.id)
        m_update.delay.assert_not_called()
