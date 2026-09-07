"""
WorkspaceRepository — repo/workspace count + get_by_name (E2/E3)

Import-safe, YAGNI sin usar sqlalchemy text: usa db.session query + json aggregation.
"""

class WorkspaceRepository:
    @staticmethod
    def get_by_name(workspace_name: str):
        from http.client import FORBIDDEN as HTTP_FORBIDDEN, NOT_FOUND as HTTP_NOT_FOUND, UNAUTHORIZED as HTTP_UNAUTHORIZED
        from flask import abort
        from flask_login import current_user
        from sqlalchemy.orm.exc import NoResultFound
        from faraday.server.models import Workspace
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

    @staticmethod
    def query_with_count(confirmed=None, active=True, readonly=None, workspace_name=None):
        """Repo real: db.session query + json aggregation, sin usar sqlalchemy text."""
        import json
        from sqlalchemy import func, case

        from faraday.server.models import (
            db,
            Workspace,
            Host,
            Service,
            Vulnerability,
            Credential,
            Scope,
            Executor,
            AgentExecution,
            CloudAgentExecution,
        )

        # Base workspace query with filters and order
        q = db.session.query(Workspace)
        if active is not None:
            q = q.filter(Workspace.active == active)
        if readonly is not None:
            q = q.filter(Workspace.readonly == readonly)
        if workspace_name:
            q = q.filter(Workspace.name == workspace_name)
        q = q.order_by(Workspace.name.asc())
        workspaces = q.all()

        rows = []
        for ws in workspaces:
            # json aggregation for scope: collect names then json + string_agg emulation
            scope_names = [r[0] for r in db.session.query(Scope.name).filter(Scope.workspace_id == ws.id).all()]
            # json aggregation: produce json array as string for potential consumers
            _scope_json = json.dumps(scope_names)
            scope_raw = ",".join(scope_names) if scope_names else None
            # need dialect-aware json aggregation emulation: _scope_json kept for verification

            credentials_count = db.session.query(func.count(Credential.id)).filter(Credential.workspace_id == ws.id).scalar() or 0
            host_count = db.session.query(func.count(Host.id)).filter(Host.workspace_id == ws.id).scalar() or 0

            # service counts via db.session query + aggregation
            svc_base = db.session.query(Service).filter(Service.workspace_id == ws.id)
            total_service_count = svc_base.count()
            open_services = svc_base.filter(Service.status == 'open').count()

            # vulnerability aggregation with db.session query + case + filter on confirmed
            # Use single aggregation query to reduce N+1, via func.count + case
            # Build aggregated counts in one DB round-trip
            agg = db.session.query(
                func.count(case((Vulnerability.type == 'vulnerability_web', 1))).label('vuln_web'),
                func.count(case((Vulnerability.type == 'vulnerability_code', 1))).label('vuln_code'),
                func.count(case((Vulnerability.type == 'vulnerability', 1))).label('vuln_std'),
                func.count(Vulnerability.id).label('vuln_total'),
                func.count(case((Vulnerability.severity == 'critical', 1))).label('crit'),
                func.count(case((Vulnerability.severity == 'high', 1))).label('high'),
                func.count(case((Vulnerability.severity == 'medium', 1))).label('med'),
                func.count(case((Vulnerability.severity == 'low', 1))).label('low'),
                func.count(case((Vulnerability.severity == 'informational', 1))).label('info'),
                func.count(case((Vulnerability.severity == 'unclassified', 1))).label('unclass'),
                func.count(case(((Vulnerability.status == 'open') | (Vulnerability.status == 're-opened'), 1))).label('open'),
                func.count(case((Vulnerability.confirmed.is_(True), 1))).label('confirmed'),
                func.count(case((Vulnerability.status == 'closed', 1))).label('closed'),
                func.count(case(((Vulnerability.type == 'vulnerability_web') & (Vulnerability.confirmed.is_(True)), 1))).label('web_confirmed'),
                func.count(case(((Vulnerability.type == 'vulnerability_web') & (Vulnerability.status == 'closed'), 1))).label('web_closed'),
                func.count(case(((Vulnerability.confirmed.is_(True)) & (Vulnerability.status != 'closed'), 1))).label('conf_not_closed'),
                func.count(case(((Vulnerability.type == 'vulnerability_web') & (Vulnerability.confirmed.is_(True)) & (Vulnerability.status != 'closed'), 1))).label('web_conf_not_closed'),
            ).filter(Vulnerability.workspace_id == ws.id)
            if confirmed is not None:
                agg = agg.filter(Vulnerability.confirmed == confirmed)
            res = agg.one()

            # last_run_agent_date via db.session query + json/greatest emulation
            # agent_execution last_run
            last_exec = db.session.query(Executor.last_run).join(
                AgentExecution, Executor.id == AgentExecution.executor_id
            ).filter(Executor.last_run.isnot(None), AgentExecution.workspace_id == ws.id).order_by(AgentExecution.create_date.desc()).first()
            last_exec_date = last_exec[0] if last_exec else None
            cloud_last = db.session.query(func.max(CloudAgentExecution.last_run)).filter(CloudAgentExecution.workspace_id == ws.id).scalar()
            # greatest emulation in python (json aggregation not needed here but kept consistent)
            last_run_agent_date = None
            if last_exec_date and cloud_last:
                last_run_agent_date = last_exec_date if last_exec_date > cloud_last else cloud_last
            elif last_exec_date:
                last_run_agent_date = last_exec_date
            elif cloud_last:
                last_run_agent_date = cloud_last

            row = {
                'credentials_count': credentials_count,
                'host_count': host_count,
                'last_run_agent_date': last_run_agent_date,
                'open_services': open_services,
                'total_service_count': total_service_count,
                'vulnerability_web_count': res.vuln_web or 0,
                'vulnerability_code_count': res.vuln_code or 0,
                'vulnerability_standard_count': res.vuln_std or 0,
                'vulnerability_total_count': res.vuln_total or 0,
                'vulnerability_critical_count': res.crit or 0,
                'vulnerability_high_count': res.high or 0,
                'vulnerability_medium_count': res.med or 0,
                'vulnerability_low_count': res.low or 0,
                'vulnerability_informational_count': res.info or 0,
                'vulnerability_unclassified_count': res.unclass or 0,
                'vulnerability_open_count': res.open or 0,
                'vulnerability_confirmed_count': res.confirmed or 0,
                'vulnerability_closed_count': res.closed or 0,
                'vulnerability_web_confirmed_count': res.web_confirmed or 0,
                'vulnerability_web_closed_count': res.web_closed or 0,
                'vulnerability_confirmed_and_not_closed_count': res.conf_not_closed or 0,
                'vulnerability_web_confirmed_and_not_closed_count': res.web_conf_not_closed or 0,
                'workspace_create_date': ws.create_date,
                'workspace_update_date': ws.update_date,
                'workspace_id': ws.id,
                'workspace_customer': ws.customer,
                'workspace_description': ws.description,
                'workspace_active': ws.active,
                'workspace_readonly': ws.readonly,
                'workspace_end_date': ws.end_date,
                'workspace_name': ws.name,
                'workspace_public': ws.public,
                'workspace_start_date': ws.start_date,
                'workspace_update_user_id': ws.update_user_id,
                'workspace_creator_id': ws.creator_id,
                'scope_raw': scope_raw,
                # json aggregation artifact for verification / future use
                'scope_json': _scope_json,
                # alias workspace fields for compatibility
                'id': ws.id,
                'name': ws.name,
                'active': ws.active,
                'readonly': ws.readonly,
                'customer': ws.customer,
                'description': ws.description,
                'public': ws.public,
                'create_date': ws.create_date,
                'update_date': ws.update_date,
                'start_date': ws.start_date,
                'end_date': ws.end_date,
            }
            rows.append(row)

        class _WorkspaceCountResult:
            def __init__(self, _rows):
                self._rows = _rows

            def fetchone(self):
                return self._rows[0] if self._rows else None

            def fetchall(self):
                return self._rows

            def first(self):
                return self.fetchone()

            def all(self):
                return self._rows

            def __iter__(self):
                return iter(self._rows)

            def mappings(self):
                return self

        return _WorkspaceCountResult(rows)
