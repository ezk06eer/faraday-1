"""CommandRepository — YAGNI shim para reporting."""
class CommandRepository:
    @staticmethod
    def get_by_id(command_id):
        from faraday.server.models import Command
        return Command.query.get(command_id)

    @staticmethod
    def get_by_workspace(workspace_id):
        from faraday.server.models import Command
        return Command.query.filter_by(workspace_id=workspace_id).all()
