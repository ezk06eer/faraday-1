# Bounded Contexts — Modulith (E3)

Generado desde grafo determinístico `/tmp/faraday_graph.json` (117 nodos, 345 aristas, 23 ciclos).

## Contextos futuros (cuando E2 complete extracción services/repo)

- **core** — `faraday.server.config`, `faraday.server.extensions`, `faraday.server.models` shards workspace/user_auth, `faraday.server.app`
- **workspace** — `api/modules/workspaces.py` + `repo/workspace_repo.py` + `services/workspace_service.py`
- **vuln_mgmt** — `api/modules/vulns_*`, `hosts_*`, `services_*`, `domain/vulnerability`, `services/search_service.py`
- **agent** — `api/modules/agent*`, `domain/agent_workflow`, `threads/crontab.py`, `websockets/dispatcher.py`
- **reporting** — `api/modules/upload_reports.py`, `services/bulk_create`, `domain/command`, `infra/broker`, `server/tasks.py`

Cada contexto expone `api/`, `services/`, `repo/`, `schemas/`. `faraday/app_factory.py` compone vía `faraday_server.*` config.

PONyTAIL: cada contexto es una branch corta (`refactor/bc-workspace`), merge squash a trunk cuando tests verdes.
YAGNI: no crear microservicios físicos hasta que `rg "from faraday.server.models import" faraday/server/api` == 0.
