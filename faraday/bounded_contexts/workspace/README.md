# Workspace BC — cómo dejar de ser monolito (YAGNI)

Este directorio demuestra el patrón para extraer un bounded context sin romper `contracts.md`.

## Grafo actual
`faraday/server/models.py` 117n/345e/23c → `faraday/domain/workspace` 6 clases + `faraday/repo/workspace_repo` + `faraday/services` ya desacoplados.
`faraday/bounded_contexts/workspace/app.py` `create_workspace_app` es el factory que *podría* registrar solo `workspace_api` (`faraday/server/api/modules/workspaces.py`) sin cargar `vulns/hosts`.

## YAGNI hoy
Delega a `faraday/server/app.create_app` completo (monolito) para no duplicar `register_blueprints`/`register_extensions` manteniendo `/_api` + `SKIP_RULES` + `APPLICATION_PREFIX`.

## Próximo corte (1 arista)
Hacer `create_workspace_app` registrar solo:
```python
from faraday.server.api.modules.workspaces import workspace_api
app.register_blueprint(workspace_api, url_prefix=app.config['APPLICATION_PREFIX'])
```
y usar `faraday/repo/workspace_repo.WorkspaceRepository` + `faraday/domain/workspace/service.py` sin importar `Vulnerability`/`Host`. Ver `contracts.md` sección 4 `workspaces` para rutas a mantener.
