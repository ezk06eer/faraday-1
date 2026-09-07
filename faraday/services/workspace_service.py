"""
WorkspaceService — extracted from faraday/server/utils + debouncer (E2-A9)

Centralizes workspace stats logic. Import-safe: debouncer deferred.
"""
class WorkspaceService:
    @staticmethod
    def refresh_counts(workspace_id: int, workspace_name: str | None = None):
        from faraday.server.debouncer import (
            debounce_workspace_host_count,
            debounce_workspace_service_count,
            debounce_workspace_update,
            debounce_workspace_vulns_count_update,
        )
        if workspace_id:
            debounce_workspace_vulns_count_update(workspace_id=workspace_id)
            debounce_workspace_host_count(workspace_id=workspace_id)
            debounce_workspace_service_count(workspace_id=workspace_id)
            if workspace_name:
                debounce_workspace_update(workspace_name, workspace_id=workspace_id)
        elif workspace_name:
            debounce_workspace_vulns_count_update(workspace_name=workspace_name)
            debounce_workspace_host_count(workspace_name=workspace_name)
            debounce_workspace_service_count(workspace_name=workspace_name)
