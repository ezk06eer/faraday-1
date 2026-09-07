"""Bounded contexts registry — des-monolitizar faraday/server/app.py:136 register_blueprints (ponytail YAGNI).

Mantiene contrato wire /_api + /v3, solo extrae registro por BC para que cada BC pueda montarse standalone.
"""
from faraday.server.config import faraday_server  # noqa: F401

def register_workspace_bc(app):
    from faraday.server.api.modules.workspaces import workspace_api  # lazy
    from faraday.server.ui import ui

    app.register_blueprint(ui)
    app.register_blueprint(workspace_api, url_prefix=app.config['APPLICATION_PREFIX'])
    return ["workspace"]

def register_vuln_bc(app):
    from faraday.server.api.modules.vulns_base import vulns_api
    from faraday.server.api.modules.vulns_workspaced import vulns_workspaced_api
    from faraday.server.api.modules.vulnerability_template import vulnerability_template_api

    app.register_blueprint(vulns_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(vulns_workspaced_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(vulnerability_template_api, url_prefix=app.config['APPLICATION_PREFIX'])
    return ["vuln"]

def register_host_bc(app):
    from faraday.server.api.modules.hosts_base import host_api
    from faraday.server.api.modules.hosts_workspaced import host_workspaced_api

    app.register_blueprint(host_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(host_workspaced_api, url_prefix=app.config['APPLICATION_PREFIX'])
    return ["host"]

def register_all_bcs(app):
    """Registra todos los BCs (monolito actual) — mantiene faraday/server/app.py:136."""
    registered = []
    registered += register_workspace_bc(app)
    registered += register_host_bc(app)
    registered += register_vuln_bc(app)
    # Para YAGNI, delega el resto al monolito original vía import lazy (no rompe contrato)
    # Próximos PRs moverán cada uno a su BC: services, credentials, agents, etc.
    try:
        from faraday.server.api.modules.info import info_api
        from faraday.server.api.modules.commandsrun import commandsrun_api
        from faraday.server.api.modules.global_commands import globalcommands_api
        from faraday.server.api.modules.activity_feed import activityfeed_api
        from faraday.server.api.modules.credentials import credentials_api
        from faraday.server.api.modules.licenses import license_api
        from faraday.server.api.modules.services_base import services_api
        from faraday.server.api.modules.services_workspaced import services_workspaced_api
        from faraday.server.api.modules.session import session_api
        from faraday.server.api.modules.handlers import handlers_api
        from faraday.server.api.modules.comments import comment_api
        from faraday.server.api.modules.upload_reports import upload_api
        from faraday.server.api.modules.websocket_auth import websocket_auth_api
        from faraday.server.api.modules.custom_fields import custom_fields_schema_api
        from faraday.server.api.modules.agents_schedule import agents_schedule_api
        from faraday.server.api.modules.agent_auth_token import agent_auth_token_api
        from faraday.server.api.modules.agent import agent_api
        from faraday.server.api.modules.bulk_create import bulk_create_api
        from faraday.server.api.modules.token import token_api
        from faraday.server.api.modules.search_filter import searchfilter_api
        from faraday.server.api.modules.preferences import preferences_api
        from faraday.server.api.modules.export_data import export_data_api
        from faraday.server.api.modules.workflow import workflow_api
        from faraday.server.api.modules.settings_reports import reports_settings_api
        from faraday.server.api.modules.settings_dashboard import dashboard_settings_api
        from faraday.server.api.modules.settings_elk import elk_settings_api
        from faraday.server.api.modules.settings_query_limits import query_limits_settings_api
        from faraday.server.api.modules.agent_execution import agent_execution_api
        from faraday.server.api.modules.swagger import swagger_api

        app.register_blueprint(info_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(license_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(services_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(services_workspaced_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(session_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(commandsrun_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(globalcommands_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(activityfeed_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(credentials_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(handlers_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(comment_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(upload_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(websocket_auth_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(custom_fields_schema_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(agent_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(agent_auth_token_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(bulk_create_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(token_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(searchfilter_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(preferences_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(export_data_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(agents_schedule_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(workflow_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(reports_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(dashboard_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(elk_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(swagger_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(query_limits_settings_api, url_prefix=app.config['APPLICATION_PREFIX'])
        app.register_blueprint(agent_execution_api, url_prefix=app.config['APPLICATION_PREFIX'])
        registered += ["services", "credentials", "agents", "bulk", "token", "search", "prefs", "export", "workflow", "settings", "swagger", "agent_exec"]
    except ImportError:
        pass
    return registered
