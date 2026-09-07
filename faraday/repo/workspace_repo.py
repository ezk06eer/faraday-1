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
        """SQL crudo upstream (battle-tested, transplanted P2): los contratos
        de columnas (vulnerability_web_count, etc.) y scope_raw/string_agg se
        mantienen idénticos; la reescritura ORM introdujo conteos en 0."""
        from sqlalchemy import text
        from faraday.server.models import db

        query = """
                SELECT
                (SELECT COUNT(credential.id) AS count_1
                    FROM credential
                    WHERE credential.workspace_id = workspace.id
                ) AS credentials_count,
                (SELECT COUNT(host.id) AS count_2
                    FROM host
                    WHERE host.workspace_id = workspace.id
                ) AS host_count,
                (SELECT GREATEST(
                    (SELECT executor.last_run
                        FROM executor
                        JOIN agent_execution ON executor.id = agent_execution.executor_id
                        WHERE executor.last_run is not null and
                        agent_execution.workspace_id = workspace.id
                        ORDER BY agent_execution.create_date DESC
                        LIMIT 1
                    ),
                    (SELECT MAX(cloud_agent_execution.last_run)
                        FROM cloud_agent_execution
                        WHERE cloud_agent_execution.workspace_id = workspace.id
                    )
                )) AS last_run_agent_date,
                p_4.count_3 as open_services,
                p_4.count_4 as total_service_count,
                p_5.count_5 as vulnerability_web_count,
                p_5.count_6 as vulnerability_code_count,
                p_5.count_7 as vulnerability_standard_count,
                p_5.count_8 as vulnerability_total_count,
                p_5.count_9 as vulnerability_critical_count,
                p_5.count_10 as vulnerability_high_count,
                p_5.count_11 as vulnerability_medium_count,
                p_5.count_12 as vulnerability_low_count,
                p_5.count_13 as vulnerability_informational_count,
                p_5.count_14 as vulnerability_unclassified_count,
                p_5.count_15 as vulnerability_open_count,
                p_5.count_16 as vulnerability_confirmed_count,
                p_5.count_17 as vulnerability_closed_count,
                p_5.count_18 as vulnerability_web_confirmed_count,
                p_5.count_19 as vulnerability_web_closed_count,
                p_5.count_20 as vulnerability_confirmed_and_not_closed_count,
                p_5.count_21 as vulnerability_web_confirmed_and_not_closed_count,
                workspace.create_date AS workspace_create_date,
                workspace.update_date AS workspace_update_date,
                workspace.id AS workspace_id,
                workspace.customer AS workspace_customer,
                workspace.description AS workspace_description,
                workspace.active AS workspace_active,
                workspace.readonly AS workspace_readonly,
                workspace.end_date AS workspace_end_date,
                workspace.name AS workspace_name,
                workspace.public AS workspace_public,
                workspace.start_date AS workspace_start_date,
                workspace.update_user_id AS workspace_update_user_id,
                workspace.creator_id AS workspace_creator_id,
                (SELECT {concat_func}(scope.name, ',') FROM scope where scope.workspace_id=workspace.id) as scope_raw
            FROM workspace
            LEFT JOIN (SELECT w.id as wid,
             COUNT(case when service.id IS NOT NULL and service.status = 'open' then 1 else null end) as count_3,
              COUNT(case when service.id IS NOT NULL then 1 else null end) AS count_4
                    FROM service
                    RIGHT JOIN workspace w ON service.workspace_id = w.id
                    GROUP BY w.id
                ) AS p_4 ON p_4.wid = workspace.id
            LEFT JOIN (SELECT w.id as w_id,
             COUNT(case when vulnerability.type = 'vulnerability_web' then 1 else null end) as count_5,
             COUNT(case when vulnerability.type = 'vulnerability_code' then 1 else null end) AS count_6,
             COUNT(case when vulnerability.type = 'vulnerability' then 1 else null end) as count_7,
             COUNT(case when vulnerability.id IS NOT NULL then 1 else null end) AS count_8,
             COUNT(case when vulnerability.severity = 'critical' then 1 else null end) as count_9,
             COUNT(case when vulnerability.severity = 'high' then 1 else null end) as count_10,
             COUNT(case when vulnerability.severity = 'medium' then 1 else null end) as count_11,
             COUNT(case when vulnerability.severity = 'low' then 1 else null end) as count_12,
             COUNT(case when vulnerability.severity = 'informational' then 1 else null end) as count_13,
             COUNT(case when vulnerability.severity = 'unclassified' then 1 else null end) as count_14,
             COUNT(case when vulnerability.status = 'open' OR vulnerability.status='re-opened' then 1 else null end) as count_15,
             COUNT(case when vulnerability.confirmed is True then 1 else null end) as count_16,
             COUNT(case when vulnerability.status = 'closed' then 1 else null end) as count_17,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.confirmed is True then 1 else null end) as count_18,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.status = 'closed' then 1 else null end) as count_19,
             COUNT(case when vulnerability.confirmed is True AND vulnerability.status != 'closed' then 1 else null end) as count_20,
             COUNT(case when vulnerability.type = 'vulnerability_web' AND vulnerability.confirmed is True AND vulnerability.status != 'closed' then 1 else null end) as count_21
                    FROM vulnerability
                    RIGHT JOIN workspace w ON vulnerability.workspace_id = w.id
                    WHERE 1=1 {0}
                    GROUP BY w.id
                ) AS p_5 ON p_5.w_id = workspace.id
        """
        concat_func = 'group_concat' if db.engine.dialect.name == 'sqlite' else 'string_agg'
        filters = []
        params = {}

        confirmed_vuln_filter = ''
        if confirmed is not None:
            if confirmed:
                confirmed_vuln_filter = " AND vulnerability.confirmed "
            else:
                confirmed_vuln_filter = " AND NOT vulnerability.confirmed "
        query = query.format(confirmed_vuln_filter, concat_func=concat_func)

        if active is not None:
            filters.append(" workspace.active = :active ")
            params['active'] = active
        if readonly is not None:
            filters.append(" workspace.readonly = :readonly ")
            params['readonly'] = readonly
        if workspace_name:
            filters.append(" workspace.name = :workspace_name ")
            params['workspace_name'] = workspace_name
        if filters:
            query += ' WHERE ' + ' AND '.join(filters)
        query += " ORDER BY workspace.name ASC"

        return db.session.execute(text(query), params).mappings()
