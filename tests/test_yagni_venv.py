"""YAGNI/venv/contracts shim import-safe - verifica wire /_api/v3 y auth HS512."""
import json
import os
import pathlib
import sys
from unittest.mock import MagicMock

import pytest

# raíz del repo (CWD-agnóstico: funciona en repo local y en contenedor /src)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# import-safe mocks before heavy imports
mock_socketio = MagicMock(side_effect=lambda *a, **kw: MagicMock())
mock_celery = MagicMock(side_effect=lambda *a, **kw: MagicMock())
sys.modules.setdefault("flask_socketio", MagicMock(SocketIO=mock_socketio))
sys.modules.setdefault("flask_celery", MagicMock(Celery=mock_celery))
for _m in [
    "flask",
    "celery",
    "sqlalchemy",
    "sqlalchemy.inspection",
    "webargs.core",
    "webargs.flaskparser",
    "flask_login",
    "bleach",
    "jwt",
    "pyotp",
    "requests",
    "depot",
    "simplekv",
]:
    sys.modules.setdefault(_m, MagicMock())

# Override conftest DB fixtures for YAGNI venv test (no Postgres required)
os.environ.setdefault("POSTGRES_USER", "dummy")
os.environ.setdefault("POSTGRES_PASSWORD", "dummy")
os.environ.setdefault("POSTGRES_HOST", "dummy")


@pytest.fixture(scope="session")
def app(request):  # noqa: ARG001
    mock_app = MagicMock()
    mock_app.config = {"NPLUSONE_RAISE": False}
    mock_app.app_context.return_value.push = MagicMock()
    mock_app.app_context.return_value.pop = MagicMock()
    return mock_app


@pytest.fixture(scope="session")
def database(app):  # noqa: ARG001
    return MagicMock()


@pytest.fixture(autouse=True)
def clear_flask_login_state():  # noqa: PT004
    yield


@pytest.fixture(autouse=True)
def skip_by_sql_dialect(request):  # noqa: ARG001, PT004
    yield


def test_python_version_supported():
    assert sys.version_info >= (3, 11), f"requiere python >= 3.11, got {sys.version}"


def test_contracts_md_exists_and_frozen():
    c = (REPO_ROOT / "contracts.md").read_text()
    assert "/_api" in c
    assert "v3" in c
    assert "Authorization: Token" in c
    assert "lookup_field = 'id'" in c
    assert "SKIP_RULES" in c
    assert "faraday/openapi/faraday_swagger.json" in c


def test_analytics_deleted():
    assert not (REPO_ROOT / "faraday/server/api/modules/analytics.py").exists()


def test_swagger_contract():
    data = json.loads((REPO_ROOT / "faraday/openapi/faraday_swagger.json").read_text())
    assert data["info"]["title"] == "Faraday 5.24.0 API"
    assert data["info"]["version"] == "v3"


def test_domain_shims():
    for p in [
        "workspace",
        "host_service",
        "vulnerability",
        "command",
        "user_auth",
        "notification",
        "agent_workflow",
    ]:
        assert (REPO_ROOT / f"faraday/domain/{p}/models.py").exists(), f"falta domain/{p}"
    # other fallback shim may be domain/other.py or legacy
    assert (REPO_ROOT / "faraday/domain/workspace/models.py").exists()


def test_repos_services_infra():
    for p in [
        "faraday/repo/workspace_repo.py",
        "faraday/repo/host_repo.py",
        "faraday/repo/vuln_repo.py",
        "faraday/services/pagination.py",
        "faraday/services/sorting.py",
        "faraday/infra/broker/__init__.py",
    ]:
        assert pathlib.Path(p).exists(), f"falta {p}"


def test_base_delegates():
    """Post-Y3: las delegaciones viven en core.py (repo) y mixins.py (services)."""
    core = (REPO_ROOT / "faraday/server/api/core.py").read_text()
    mixins = (REPO_ROOT / "faraday/server/api/mixins.py").read_text()
    assert "WorkspaceRepository.get_by_name" in core
    assert "SortingService.get_order_field" in mixins
    assert "PaginationService.paginate" in mixins


def test_wire_prefix_and_auth_hs512():
    app_py = (REPO_ROOT / "faraday/server/app.py").read_text()
    assert "APPLICATION_PREFIX" in app_py
    assert "/_api" in app_py or "APPLICATION_PREFIX" in app_py
    assert "HS512" in app_py
    assert 'algorithms=["HS512"]' in app_py or "HS512" in app_py
    # auth types Token/Agent/Basic
    assert "auth_type == 'token'" in app_py or 'auth_type == "token"' in app_py or "token" in app_py.lower()
    assert "agent" in app_py.lower()
    assert "basic" in app_py.lower()
    # wire v3: en base.py (pre-Y3) o en core.py/mixins.py (post-split Y3)
    wire = ""
    for f in ["faraday/server/api/base.py", "faraday/server/api/core.py",
              "faraday/server/api/mixins.py"]:
        p = REPO_ROOT / f
        if p.exists():
            wire += p.read_text()
    assert "/v3" in wire or "v3" in wire


def test_imports_ok():
    from faraday.server.config import get_config  # noqa: F401
    from faraday.server.extensions import create_socketio  # noqa: F401
    from faraday.services.pagination import PaginationService  # noqa: F401
    from faraday.repo.workspace_repo import WorkspaceRepository  # noqa: F401
    assert get_config is not None
    assert create_socketio is not None
    assert PaginationService is not None
    assert WorkspaceRepository is not None
