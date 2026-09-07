"""ReportService — YAGNI shim, delega a utils/reports_processor. Import-safe."""
class ReportService:
    @staticmethod
    def process_report(*args, **kwargs):
        from faraday.server.utils.reports_processor import process_report
        return process_report(*args, **kwargs)
