"""Host BC standalone real — YAGNI B-host.

No delega a faraday.server.app.create_app completo.
Registra solo host_api + host_workspaced_api + services_api sin vulns.
Mantiene contracts.md /v3/hosts wire.
"""

# YAGNI flags — BC capability (standalone sin vulns)
HAS_HOSTS = True
HAS_VULNS = False
has_hosts = True
has_vulns = False
def create_host_app(db_connection_string=None, testing=None):
    from flask import Flask
    app = Flask(__name__, static_folder=None)
    app.config['APPLICATION_PREFIX'] = '/_api' if not testing else ''
    app.config['SQLALCHEMY_DATABASE_URI'] = db_connection_string or "sqlite:///:memory:"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    if testing:
        app.config['TESTING'] = True
    from faraday.server.models import db
    db.init_app(app)
    from faraday.server.api.modules.hosts_base import host_api
    from faraday.server.api.modules.hosts_workspaced import host_workspaced_api
    from faraday.server.api.modules.services_base import services_api
    app.register_blueprint(host_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(host_workspaced_api, url_prefix=app.config['APPLICATION_PREFIX'])
    app.register_blueprint(services_api, url_prefix=app.config['APPLICATION_PREFIX'])
    return app
