# Contracts — Faraday (No romper durante refactor)

Este documento congela los contratos públicos que el refactor PONyTAIL/YAGNI **no debe cambiar**.
Todo corte de grafo debe mantener compatibilidad wire-level. Si un cambio roza un contrato, crear ADR y test de contrato.

## 1. HTTP API — Prefijo y versiones

- **Prefijo**: `/_api` en prod `faraday/server/app.py:462` (`APPLICATION_PREFIX`), vacío en `testing=True`. No cambiar.
- **Versiones**: `v3` (`/v3/ws/<workspace_name>/...` `faraday/server/api/base.py:189` y `/v3/hosts` `faraday/server/api/base.py:548`). Nuevas capas deben seguir registrando con `route_prefix = '/v3/'`.
- **Swagger JSON** es contrato: `faraday/openapi/faraday_swagger.json:1` (`title: Faraday 5.24.0 API`, `servers: http://localhost:5985`, `security: basicAuth`). Generado desde `register_blueprints` `faraday/server/app.py:136`.

## 2. Autenticación y sesión (no tocar sin ADR)

- **Headers**: `Authorization: Token <jwt>`, `Authorization: Agent <token>`, `Authorization: Basic ...` `faraday/server/app.py:253`.
  - `Token` → `jwt.decode(HS512, SECRET_KEY)` `faraday/server/app.py:237` verifica `fs_uniquifier` + `validation_check` (hash password). Expiración `faraday_server.api_token_expiration` (86400).
  - `Agent` → delegado a `before_request` de agentes, no a `load_user_from_request`.
  - `Basic` → `username/password` `verify_and_update_password`.
- **Login**: `POST /_api/login` `CustomLoginForm` `faraday/server/app.py:726` usa `username` en campo `email` (mapper `uia_username_mapper:414`). Error genérico `Invalid username or password` para no enumerar usuarios; audit log en `audit_logger`.
- **Sesión**: cookie `faraday_session_2` `faraday/server/app.py:545` `Samesite Lax`, `KVSessionExtension` sobre `FilesystemStore` `faraday_server.session_timeout` (12h). `before_request:301` `idle_session_timeout` + `last_access` abort 401 si expira. `user_logged_in_successful:392` limpia sesiones viejas.
- **Endpoints públicos**: solo `security.login`, `security.logout`, `agent_api.AgentView:post`, `ui.index`, `static` `faraday/server/app.py:642,652`. Resto requiere login (`default_login_required:287` → 401/403).

## 3. Semántica REST (base.py)

- **Lookup**: `lookup_field = 'id'` int `faraday/server/api/base.py:223` → 404 si `ValueError`. No cambiar tipo sin migración.
- **List** `GET /` `ListMixin:594` soporta `sort`/`sort_dir` (`SortableMixin:621`), `page`/`page_size` (`PaginatedMixin:703`), `q` filtro (`Filter*Mixin:733`). Orden/envuelve vía `_envelope_list` + `_paginate`.
- **Filtro** `GET /filter?q={filters:[]}` `faraday/server/api/base.py:747` `FilterWorkspacedMixin` y `FilterMixin:966`. Esquema `FlaskRestlessSchema` `faraday/server/utils/filters.py`. `group_by` + `count` vía `get_filtered_data:82`. No cambiar claves `filters`, `limit`, `offset`, `group_by`.
- **Errores**: `400 Bad Request`, `403 Forbidden` (readonly workspace `GenericWorkspacedView:523` + `409 Conflict` en `IntegrityError` `CreateMixin:1215`), `401 Unauthorized`, `422 ValidationError` mapeado a `400` `faraday/server/api/base.py:432`. `output_json:71` `Content-Type: application/json`.
- **Bulk/Command**: `CreateWorkspacedMixin:1282` `?command_id=` crea `CommandObject` `faraday/server/api/base.py:1237` auditado; no romper `command_id` query param.

## 4. Recursos con contrato wire

| Recurso | Blueprint `faraday/server/app.py:136` | Prefijo | Notas |
|---|---|---|---|
| `hosts` | `host_api` `hosts_base.py` + `host_workspaced_api` | `/v3/hosts` y `/v3/ws/<ws>/hosts` | `hostnames` eager `HOST:hostnames`, `services` |
| `vulns` | `vulns_api` + `vulns_workspaced_api` | `/v3/vulns` + `/v3/ws/<ws>/vulns` | `severity` enum `unclassified,informational,low,medium,high,critical` `faraday/server/models.py:504` + CVSS |
| `services` | `services_api` + `services_workspaced_api` | idem | `service_count` en host |
| `workspaces` | `workspace_api` | `/v3/ws` | `active`, `readonly`, `name` único |
| `credentials` | `credentials_api` | `/v3/ws/<ws>/credential` | bulk `import_csv` |
| `commands` | `commandsrun_api`, `globalcommands_api`, `activityfeed_api` | `/v3/ws/<ws>/commands` | `command` + `tool` |
| `agents` | `agent_api`, `agents_schedule_api`, `agent_execution_api` | `/v3/agent` | `is_public` post `agent_api.AgentView:post` `faraday/server/app.py:652` |
| `bulk_create` | `bulk_create_api` | `/v3/ws/<ws>/hosts/bulk_create` | CSV `description,hostnames,ip,os` `faraday_swagger.json:1495` |

No renombrar rutas ni cambiar `route_prefix`/`base_args`. `SKIP_RULES` `faraday/server/app.py:428` son reglas a **eliminar** en v4, no a romper antes.

## 5. Persistencia y migraciones

- **DB**: `SQLAlchemy` `faraday/server/models.py:147` `db = SQLAlchemy(join_transaction_mode=create_savepoint)` + `faraday/server/models.py:150` SQLite `case_sensitive_like` + `register_sqlite_isolation_events`. `Pool` `QueuePool 20/20/60s` `faraday/server/app.py:592`.
- **Migrations**: `faraday/migrations/` alembic, no reescribir historia. Nuevas columnas deben ser `nullable` o con `server_default`.
- **Constraints**: `UniqueConstraint` en `Host(ip, workspace_id)`, `Hostname(name, host_id)`, etc. `is_unique_constraint_violation` `faraday/server/utils/database.py` mapea a `409`.

## 6. Config y secrets

- **Archivos**: `~/.faraday/config/server.ini` `faraday/server/config.py:42` + `faraday/server/default.ini`. Claves `faraday_server.secret_key`, `agent_registration_secret` generadas `save_new_secret_key:335` si falta. No cambiar sección/nombre.
- **Storage**: `depot` `faraday/server/app.py:584` `storage.path` `CONST_FARADAY_HOME_PATH/storage`. No mover sin migración.
- **Celery**: `CELERY_BROKER_URL/BACKEND_URL` `faraday/server/app.py:548` con `global_keyprefix` `celery_queue_prefix`. `Periodic` `cleanup_stuck_pipelines` (1h) + `update_failed_command_stats` (2h) `faraday/server/app.py:557`.

## 7. UI y websockets

- **UI**: `faraday/server/ui.py:ui` sirve `faraday/server/www` `faraday/server/app.py:444` fallback `index.html` para SPA, excepto prefijos `/_api, /v3, /socket.io` `faraday/server/app.py:457`. No tocar (ignorado en refactor).
- **WS**: `DispatcherNamespace /dispatcher` `faraday/server/websockets/dispatcher.py` + `socketio` `faraday/server/extensions.py:10`. `register_extensions` `faraday/server/app.py:693` usa `faraday/server/extensions.py:97` `init_extensions`. No cambiar evento `join_agent`, `run_status`.

## 8. Qué sí puede cambiar (YAGNI)

- Internos `faraday/services/`, `faraday/repo/`, `faraday/infra/*` (puertos `TaskQueue`, `EventPublisher`, `WebSocketGateway`) mientras pasen tests de contrato.
- Extracción `faraday/server/models.py:1` (4248L, 90 clases) a `faraday/domain/*` vía shim re-export — `faraday/server/models.py` debe seguir exportando `db`, `Workspace`, `Host`, etc. para compat.
- `faraday/server/api/base.py:548` mixins a `faraday/services/*` composición, manteniendo herencia para compat.

## 9. Tests de contrato (antes de cada PR)

```bash
python -m venv /tmp/faraday-venv --clear && /tmp/faraday-venv/bin/pip install -q ruff pytest
/tmp/faraday-venv/bin/python -m py_compile faraday/server/config.py faraday/server/extensions.py faraday/server/app.py
/tmp/faraday-venv/bin/ruff check faraday/server --select F401
pytest tests/test_api_hosts_workspaced.py tests/test_api_vulns_workspaced.py -k "test_list or test_create"  # wire
# + swagger diff: python -c "import json; json.load(open('faraday/openapi/faraday_swagger.json'))"
```

Todo PR ponytail debe pasar estos sin tocar `contracts.md` sin ADR.
