"""HostRepository — YAGNI shim para host_service (E2). Import-safe."""
class HostRepository:
    @staticmethod
    def get_by_ip(workspace_id, ip):
        from faraday.server.models import Host
        return Host.query.filter_by(workspace_id=workspace_id, ip=ip).first()

    @staticmethod
    def get_by_id(host_id):
        from faraday.server.models import Host
        return Host.query.get(host_id)
