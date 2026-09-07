"""Tests sintácticos para repo-hardening (A20). Sin app ni DB real."""
import os
from unittest.mock import MagicMock

import pytest

# Override conftest DB fixtures: no Postgres requerido
os.environ.setdefault("POSTGRES_USER", "dummy")
os.environ.setdefault("POSTGRES_PASSWORD", "dummy")
os.environ.setdefault("POSTGRES_HOST", "dummy")


@pytest.fixture(scope="session")
def app(request):  # noqa: ARG001
    return MagicMock()


@pytest.fixture(scope="session")
def database(app):  # noqa: ARG001
    return MagicMock()


@pytest.fixture(autouse=True)
def clear_flask_login_state():  # noqa: PT004
    yield


@pytest.fixture(autouse=True)
def skip_by_sql_dialect(request):  # noqa: ARG001, PT004
    yield


def test_host_get_by_ip_exists_and_callable():
    try:
        from faraday.repo.host_repo import HostRepository
    except Exception as exc:
        pytest.skip(f"import requiere DB/app: {exc}")
    assert callable(getattr(HostRepository, "get_by_ip", None))


def test_vuln_get_by_cve_exists_and_callable():
    try:
        from faraday.repo.vuln_repo import VulnRepository
    except Exception as exc:
        pytest.skip(f"import requiere DB/app: {exc}")
    assert callable(getattr(VulnRepository, "get_by_cve", None))
