"""VulnRepository — YAGNI shim. Import-safe, no text() injection."""
class VulnRepository:
    @staticmethod
    def get_by_cve(workspace_name, cve, session=None):
        if session is None:
            from faraday.server.models import db
            session = db.session
        from faraday.server.models import VulnerabilityGeneric, Workspace
        return (session.query(VulnerabilityGeneric)
                .join(Workspace, VulnerabilityGeneric.workspace_id == Workspace.id)
                .filter(Workspace.name == workspace_name,
                        VulnerabilityGeneric.cve == cve)
                .first())

    @staticmethod
    def get_by_id(vuln_id):
        from faraday.server.models import VulnerabilityGeneric
        return VulnerabilityGeneric.query.get(vuln_id)

    @staticmethod
    def count_by_host(host_id):
        from faraday.server.models import Host
        host = Host.query.get(host_id)
        return host.vulnerability_count if host else 0
