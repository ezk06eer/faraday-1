"""
E2E conftest — aísla los tests Playwright del conftest de integración.

Los fixtures autouse del conftest raíz (skip_by_sql_dialect -> app -> DB rand)
no aplican a E2E: estos tests hablan con un stack VIVO por HTTP. Se sobre-
escriben aquí como no-ops (pytest permite override en conftests anidados).
"""
import pytest


@pytest.fixture(autouse=True)
def skip_by_sql_dialect():  # noqa: F811  (override determinístico del raíz)
    yield


@pytest.fixture(autouse=True)
def clear_flask_login_state():  # noqa: F811
    yield
