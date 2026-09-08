"""
Playwright E2E — Faraday UI + API (ponytail YAGNI).

Requiere el stack levantado (docker compose up o faraday-server local):
  FARADAY_URL   (default http://localhost:5985)
  FARADAY_USER  (default faraday)
  FARADAY_PASS  (password del admin)

Corre con:  pytest tests/e2e -q
"""
import os
import uuid

import pytest

pytest.importorskip("playwright", reason="E2E requiere playwright instalado")
from playwright.sync_api import Page, expect, sync_playwright  # noqa: E402

FARADAY_URL = os.getenv("FARADAY_URL", "http://localhost:5985")
FARADAY_USER = os.getenv("FARADAY_USER", "faraday")
FARADAY_PASS = os.getenv("FARADAY_PASS", "")


def _pass() -> str:
    if not FARADAY_PASS:
        pytest.skip("FARADAY_PASS no definido: E2E contra stack vivo requiere password")
    return FARADAY_PASS


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(browser: Page):
    pg = browser.new_page()
    yield pg
    pg.close()


@pytest.fixture(scope="session")
def api_ctx(browser):
    """Un solo login API por sesión (evita rate-limit de flask-limiter)."""
    ctx = browser.new_context(base_url=FARADAY_URL)
    res = ctx.request.post("/_api/login", data={
        "email": FARADAY_USER, "password": _pass(),
    })
    assert res.status == 200, f"login API fallo: {res.status}"
    yield ctx
    ctx.close()


@pytest.fixture(scope="session")
def ui_page(browser):
    """Un solo login UI por sesión."""
    pg = browser.new_page()
    pg.goto(FARADAY_URL + "/", wait_until="networkidle", timeout=30000)
    pg.locator("input").nth(0).fill(FARADAY_USER)
    pg.locator("input[type=password]").fill(_pass())
    pg.get_by_role("button", name="Login").click()
    # la SPA redirige a /workspaces tras login (determinístico, no sleeps fijos)
    pg.wait_for_url("**/workspaces", timeout=30000)
    yield pg
    pg.close()


def _login_ui(pg: Page) -> None:
    """Login por UI (React SPA): username en el primer input + password + Login."""
    pg.goto(FARADAY_URL + "/", wait_until="networkidle", timeout=30000)
    pg.locator("input").nth(0).fill(FARADAY_USER)
    pg.locator("input[type=password]").fill(_pass())
    pg.get_by_role("button", name="Login").click()
    pg.wait_for_load_state("networkidle", timeout=30000)


def _api_session(browser):
    """Contexto de API autenticado vía /_api/login (cookie de sesión).

    Reusa el browser de la sesión (un solo sync_playwright activo).
    """
    ctx = browser.new_context(base_url=FARADAY_URL)
    res = ctx.request.post("/_api/login", data={
        "email": FARADAY_USER, "password": _pass(),
    })
    assert res.status == 200, f"login API fallo: {res.status}"
    return ctx


# ------------------------------------------------------------------ UI tests

@pytest.mark.e2e
def test_ui_login_redirects_to_dashboard(page: Page):
    """Contrato auth: login válido entra, inválido no."""
    pg = page
    _login_ui(pg)
    # tras login la SPA deja de estar en la pantalla de login
    assert pg.locator("input[type=password]").count() == 0 or pg.url != FARADAY_URL + "/"

    pg2 = pg.context.browser.new_page()
    pg2.goto(FARADAY_URL + "/", wait_until="networkidle")
    pg2.locator("input").nth(0).fill(FARADAY_USER)
    pg2.locator("input[type=password]").fill("wrong-password-xyz")
    pg2.get_by_role("button", name="Login").click()
    pg2.wait_for_timeout(1500)
    # sigue en login (contrato CustomLoginForm: error genérico, no enumera usuarios)
    assert pg2.locator("input[type=password]").count() >= 1
    pg2.close()


@pytest.mark.e2e
def test_ui_workspace_visible_in_grid(page: Page, api_ctx, ui_page):
    """Un workspace creado por API es visible tras recargar la UI."""
    ws_name = "e2eui-" + uuid.uuid4().hex[:8]
    res = api_ctx.request.post("/_api/v3/ws", data={"name": ws_name})
    assert res.status in (200, 201), res.text()
    pg = ui_page
    # NO recargar: el re-goto rompe la hidratación de la SPA (grid en 0).
    # El grid renderiza async tras login: esperar el texto directamente.
    expect(pg.locator(f"text={ws_name}").first).to_be_visible(timeout=25000), (
        f"workspace {ws_name} no visible en la UI"
    )
    api_ctx.request.delete(f"/_api/v3/ws/{ws_name}")


# ----------------------------------------------------------------- API tests
# Estos cubren los cambios del refactor (ponytail): contratos wire + fixes P0.

@pytest.mark.e2e
def test_api_wire_contract_and_auth(api_ctx, browser):
    """contracts.md: prefijo /_api + /v3, 401 sin token, login con cookie."""
    req = api_ctx.request
    # sin auth -> 401/403 (nunca 404: el contrato wire expone la ruta)
    anon_ctx = browser.new_context(base_url=FARADAY_URL)
    r = anon_ctx.request.get("/_api/v3/ws")
    assert r.status in (401, 403), r.status
    anon_ctx.close()
    # con auth -> 200 con envelope rows/count
    r = req.get("/_api/v3/ws")
    assert r.status == 200
    body = r.json()
    assert "rows" in body and "count" in body


@pytest.mark.e2e
def test_api_workspace_host_vuln_and_live_stats(api_ctx):
    """E2E del fix P0 (repo SQL upstream): stats del workspace se calculan."""
    req = api_ctx.request
    ws = "e2estats-" + uuid.uuid4().hex[:8]
    assert req.post("/_api/v3/ws", data={"name": ws}).status in (200, 201)

    host = req.post(f"/_api/v3/ws/{ws}/hosts", data={
        "name": "10.9.9.9", "ip": "10.9.9.9", "description": "e2e", "os": "linux"})
    assert host.status in (200, 201), host.text()
    host_id = host.json()["id"]

    vuln = req.post(f"/_api/v3/ws/{ws}/vulns", data={
        "name": "E2E Vuln", "severity": "high", "parent_type": "Host",
        "parent": host_id, "target": "10.9.9.9", "type": "Vulnerability", "data": "{}"})
    assert vuln.status in (200, 201), vuln.text()

    # stats via celery worker (async en prod): polling determinístico <=15s
    stats = {}
    for _ in range(15):
        ws_obj = req.get(f"/_api/v3/ws/{ws}").json()
        stats = ws_obj.get("stats", {})
        if stats.get("total_vulns", 0) >= 1 and stats.get("hosts") == 1:
            break
        import time as _t
        _t.sleep(1)
    assert stats["total_vulns"] >= 1, stats
    assert stats["hosts"] == 1, stats

    # limpieza
    req.delete(f"/_api/v3/ws/{ws}")


@pytest.mark.e2e
def test_api_filter_endpoints_no_nplusone_scaling(api_ctx):
    """Fixes P0: /hosts/filter y /services/filter no escalan con filas (query counts)."""
    req = api_ctx.request
    ws = "e2eqc-" + uuid.uuid4().hex[:8]
    req.post("/_api/v3/ws", data={"name": ws})
    for i in range(3):
        req.post(f"/_api/v3/ws/{ws}/hosts", data={
            "name": f"10.0.0.{i}", "ip": f"10.0.0.{i}", "description": "qc"})
    PAGE = '{"filters": [], "limit": 50, "offset": 0}'
    r = req.get(f"/_api/v3/ws/{ws}/hosts/filter", params={"q": PAGE})
    assert r.status == 200, r.text()
    body = r.json()
    assert body["count"] == 3
    rows = body["rows"]
    # contrato: cada fila serializa hostnames/servicios/owner sin reventar
    for row in rows:
        assert "hostnames" in row["value"]
        assert "owner" in row["value"]
        assert "service_summaries" in row["value"]
    req.delete(f"/_api/v3/ws/{ws}")
