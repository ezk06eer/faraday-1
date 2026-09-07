"""Host BC standalone factory — YAGNI."""
def create_host_app(db_connection_string=None, testing=None):
    from faraday.server.app import create_app as _create_app
    return _create_app(db_connection_string=db_connection_string, testing=testing, register_extensions_flag=False)
