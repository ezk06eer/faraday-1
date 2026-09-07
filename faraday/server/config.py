"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import errno
import logging
import os
import shutil
from configparser import ConfigParser
from logging import DEBUG, INFO
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Union


DEFAULT_INSTALLER_FARADAY_HOME_PATH = Path('/home/faraday')

_faraday_home = os.getenv('FARADAY_HOME', None)
if _faraday_home:
    _faraday_home = Path(_faraday_home)
else:
    if DEFAULT_INSTALLER_FARADAY_HOME_PATH.exists():
        _faraday_home = DEFAULT_INSTALLER_FARADAY_HOME_PATH
    else:
        _faraday_home = Path('~/').expanduser()

CONST_FARADAY_HOME_PATH = _faraday_home / '.faraday'

LOGGING_LEVEL = INFO

FARADAY_BASE = Path(__file__).parent.parent
FARADAY_SERVER_SESSIONS_DIR = CONST_FARADAY_HOME_PATH / 'session'
if not CONST_FARADAY_HOME_PATH.exists():
    CONST_FARADAY_HOME_PATH.mkdir()
if not FARADAY_SERVER_SESSIONS_DIR.exists():
    FARADAY_SERVER_SESSIONS_DIR.mkdir()
FARADAY_SERVER_PID_FILE = CONST_FARADAY_HOME_PATH / \
                          'faraday-server-port-{0}.pid'
REQUIREMENTS_FILE = FARADAY_BASE / 'requirements.txt'
DEFAULT_CONFIG_FILE = FARADAY_BASE / 'server' / 'default.ini'
REPORTS_VIEWS_DIR = FARADAY_BASE / 'views' / 'reports'
LOCAL_CONFIG_FILE = CONST_FARADAY_HOME_PATH / 'config' / 'server.ini'
LOCAL_REPORTS_FOLDER = CONST_FARADAY_HOME_PATH / 'uploaded_reports'
LOCAL_OPENAPI_FILE = CONST_FARADAY_HOME_PATH / 'openapi' / 'faraday_swagger.json'
CELERY_LOG_FILE = CONST_FARADAY_HOME_PATH / 'logs' / 'celery.log'
DEFAULT_MAX_QUEUE_MESSAGE_SIZE = 5 * 1024 * 1024  # 5MB

CONFIG_FILES = [DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE]

logger = logging.getLogger(__name__)

if not LOCAL_REPORTS_FOLDER.exists():
    try:
        LOCAL_REPORTS_FOLDER.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


# ---------------------------------------------------------------------------
# Optional typing helpers for DI documentation (pure typing, no runtime deps)
# ---------------------------------------------------------------------------
class DatabaseConfigDict(TypedDict, total=False):
    connection_string: Optional[str]


class FaradayServerConfigDict(TypedDict, total=False):
    bind_address: str
    port: int
    secret_key: Optional[str]
    session_timeout: float
    api_token_expiration: int
    agent_registration_secret: Optional[str]
    agent_token_expiration: int
    debug: bool
    delete_report_after_process: bool
    celery_enabled: bool
    celery_broker_url: str
    celery_backend_url: str
    max_task_message_size: int
    socketio_ping_interval: int
    socketio_ping_timeout: int
    socketio_logger: bool
    idle_session_timeout: int
    celery_queue_prefix: Optional[str]
    pipeline_running_timeout: int


class StorageConfigDict(TypedDict, total=False):
    path: Optional[str]


class LoggerConfigDict(TypedDict, total=False):
    use_rfc5424_formatter: bool


class LimiterConfigDict(TypedDict, total=False):
    enabled: bool
    login_limit: str


class AppConfigDict(TypedDict, total=False):
    database: DatabaseConfigDict
    faraday_server: FaradayServerConfigDict
    storage: StorageConfigDict
    logger: LoggerConfigDict
    limiter: LimiterConfigDict


def copy_default_config_to_local():
    if LOCAL_CONFIG_FILE.exists():
        return

    # Create directory if it doesn't exist
    try:
        LOCAL_CONFIG_FILE.parent.mkdir(parents=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # Copy default config file into faraday local config
    shutil.copyfile(DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE)
    logger.info(f"Local faraday-server configuration created at {LOCAL_CONFIG_FILE}")


def create_config_parser(config_files=None) -> ConfigParser:
    """Deterministic helper to create and load a ConfigParser.

    Pure function with no global side-effects. Preferred for DI and testing
    where explicit config file injection is needed.

    Args:
        config_files: Optional iterable of config file paths. If None, uses
            module-level CONFIG_FILES ([DEFAULT_CONFIG_FILE, LOCAL_CONFIG_FILE]).
            Elements may be str or Path.

    Returns:
        ConfigParser with files read. Deterministic: same inputs produce same
        parser state.
    """
    if config_files is None:
        config_files = CONFIG_FILES
    parser = ConfigParser()
    # Normalize Path objects to str for ConfigParser.read determinism
    parser.read([str(p) for p in config_files])
    return parser


def parse_and_bind_configuration(config_files=None):
    """Load configuration from files declared in this module and put them
    on this module's namespace for convenient access"""

    parser = create_config_parser(config_files=config_files)

    for section_name in parser.sections():
        ConfigSection.parse_section(section_name, parser[section_name])


def is_debug_mode():
    return LOGGING_LEVEL is DEBUG


class ConfigSection:
    def parse(self, __parser):
        for att in self.__dict__:  # pylint:disable=consider-using-dict-items
            value = __parser.get(att)
            if value is None:
                continue
            if isinstance(self.__dict__[att], bool):
                if value.lower() in ("yes", "true", "t", "1"):
                    setattr(self, att, True)
                else:
                    setattr(self, att, False)
            elif isinstance(self.__dict__[att], int):
                setattr(self, att, int(value))
            elif isinstance(self.__dict__[att], float):
                setattr(self, att, float(value))

            else:
                setattr(self, att, value)

    def set(self, option_name, value):
        return setattr(self, option_name, value)

    @staticmethod
    def parse_section(section_name, __parser):
        if section_name == 'database':
            section = database
        elif section_name == 'faraday_server':
            section = faraday_server
        elif section_name == 'storage':
            section = storage
        elif section_name == 'logger':
            section = logger_config
        elif section_name == 'limiter':
            section = limiter_config
        else:
            return
        section.parse(__parser)


class DatabaseConfigObject(ConfigSection):
    def __init__(self):
        self.connection_string = None


class LimiterConfigObject(ConfigSection):
    def __init__(self):
        self.enabled = False
        self.login_limit = "10/minutes"


class FaradayServerConfigObject(ConfigSection):
    def __init__(self):
        self.bind_address = "127.0.0.1"
        self.port = 5985
        self.secret_key = None
        self.session_timeout = 12.0
        self.api_token_expiration = 86400  # Default as 24 hs
        self.agent_registration_secret = None
        self.agent_token_expiration = 60  # Default as 1 min
        self.debug = False
        self.delete_report_after_process = True
        self.celery_enabled = True
        self.celery_broker_url = "redis://127.0.0.1:6379/0"
        self.celery_backend_url = "redis://127.0.0.1:6379/0"
        self.max_task_message_size = DEFAULT_MAX_QUEUE_MESSAGE_SIZE
        self.socketio_ping_interval = 60
        self.socketio_ping_timeout = 220
        self.socketio_logger = False
        self.idle_session_timeout = 0  # Default to 0 seconds (disabled)
        self.celery_queue_prefix = None
        self.pipeline_running_timeout = 21600  # 6 hours in seconds


class StorageConfigObject(ConfigSection):
    def __init__(self):
        self.path = None


class LoggerConfig(ConfigSection):
    def __init__(self):
        self.use_rfc5424_formatter = False


database = DatabaseConfigObject()
faraday_server = FaradayServerConfigObject()
storage = StorageConfigObject()
logger_config = LoggerConfig()
limiter_config = LimiterConfigObject()
parse_and_bind_configuration()


def get_config(config_files=None) -> AppConfigDict:
    """Return configuration as plain dict (DI future path).

    This is the preferred DI entry point for new code. Instead of importing
    module-level globals (database, faraday_server, storage, logger_config,
    limiter_config, CONST_FARADAY_HOME_PATH) directly, inject the result of
    get_config() or a parser from create_config_parser().

    Globals are kept for backwards compatibility and will continue to work,
    but new code should depend on get_config() for testability and explicit
    dependency injection.

    Args:
        config_files: Optional override for config files (deterministic testing).
            If None, returns snapshot of currently bound globals (post
            parse_and_bind_configuration). If provided, performs a fresh
            deterministic parse without mutating globals and returns typed dict.

    Returns:
        dict with keys 'database', 'faraday_server', 'storage', 'logger',
        'limiter' (and any extra sections found). Each value is a dict of
        option->value. Known sections have typed values (int/float/bool/str),
        unknown sections contain raw string values from the parser.
    """
    if config_files is not None:
        parser = create_config_parser(config_files=config_files)
        # Build typed dict from fresh instances without mutating globals
        fresh_db = DatabaseConfigObject()
        fresh_faraday = FaradayServerConfigObject()
        fresh_storage = StorageConfigObject()
        fresh_logger = LoggerConfig()
        fresh_limiter = LimiterConfigObject()
        section_map: Dict[str, Any] = {
            'database': fresh_db,
            'faraday_server': fresh_faraday,
            'storage': fresh_storage,
            'logger': fresh_logger,
            'limiter': fresh_limiter,
        }
        for sec in parser.sections():
            if sec in section_map:
                section_map[sec].parse(parser[sec])
        result: Dict[str, Any] = {k: dict(vars(v)) for k, v in section_map.items()}
        # Include any unknown sections as raw strings (DI completeness)
        for sec in parser.sections():
            if sec not in section_map:
                result[sec] = dict(parser[sec])
        return result  # type: ignore[return-value]
    # Default: snapshot of already-bound globals (backwards compatible)
    return {
        'database': dict(vars(database)),
        'faraday_server': dict(vars(faraday_server)),
        'storage': dict(vars(storage)),
        'logger': dict(vars(logger_config)),
        'limiter': dict(vars(limiter_config)),
    }  # type: ignore[return-value]
