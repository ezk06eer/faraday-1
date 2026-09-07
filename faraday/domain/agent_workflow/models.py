"""Domain agent_workflow — definiciones reales (shard desde faraday/server/models.py).

Mantiene las relaciones con Workspace/Command via string references de SQLAlchemy.
Sigue el patrón lazy-import de faraday/domain/host_service/models.py para evitar
ciclos: cuando es importado desde faraday.server.models (import parcial), todos
los nombres necesarios ya están definidos en ese módulo.
"""
import string
from datetime import datetime, timedelta
from random import SystemRandom

import dateutil
from croniter import croniter, CroniterError
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import backref, relationship

from faraday.server.fields import JSONType
from faraday.server.models import (  # noqa: F401  (import parcial: nombres ya definidos antes del shim)
    BlankColumn,
    Metadata,
    NonBlankColumn,
    db,
)


class Executor(Metadata):
    __tablename__ = 'executor'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    agent_id = Column(Integer, ForeignKey('agent.id', ondelete='CASCADE'), index=True, nullable=False)
    agent = relationship(
        'Agent',
        backref=backref('executors', cascade="all, delete-orphan"),
    )
    parameters_metadata = Column(JSONType, nullable=False, default={})
    parameters_data = Column(JSONType, nullable=False, default={})
    last_run = Column(DateTime)
    category = Column(JSONType, nullable=True)
    tool = Column(String(50), nullable=True)
    website = Column(Text, nullable=True)
    # workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    # workspace = relationship('Workspace', backref=backref('executors', cascade="all, delete-orphan"))

    __table_args__ = (
        UniqueConstraint('name', 'agent_id', name='uix_executor_table_agent_id_name'),
    )


agents_schedule_workspace_table = Table(
    "agents_schedule_workspace_table",
    db.Model.metadata,
    Column("workspace_id", Integer, ForeignKey("workspace.id", ondelete="CASCADE")),
    Column("agents_schedule_id", Integer, ForeignKey("agent_schedule.id")),
)


class SchedulerGeneric(Metadata):

    SCHEDULER_TYPES = ['cloud_agent', 'agent']
    SEVERITIES = ['UNCLASSIFIED', 'INFO', 'LOW', 'MED', 'HIGH', 'CRITICAL']

    __tablename__ = 'agent_schedule'
    id = Column(Integer, primary_key=True)
    description = NonBlankColumn(Text, nullable=False)
    crontab = NonBlankColumn(Text, nullable=False)
    timezone = NonBlankColumn(Text, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    last_run = Column(DateTime)
    ignore_info = Column(Boolean, default=False)
    resolve_hostname = Column(Boolean, default=True)
    vuln_tag = Column(String, default="")
    service_tag = Column(String, default="")
    host_tag = Column(String, default="")
    parameters = Column(JSONType, nullable=False, default={})
    type = Column(Enum(*SCHEDULER_TYPES, name='scheduler_types'), nullable=False)
    min_severity = Column(Enum(*SEVERITIES, name='scheduler_severities'), nullable=True)
    max_severity = Column(Enum(*SEVERITIES, name='scheduler_severities'), nullable=True)

    workspaces = relationship(
        'Workspace',
        secondary=agents_schedule_workspace_table,
        backref='agent_scheduler',
    )

    @declared_attr
    def executor_id(self):
        return Column(Integer, db.ForeignKey('executor.id'), index=True)

    @declared_attr
    def cloud_agent_id(self):
        return Column(Integer, db.ForeignKey('cloud_agent.id'), index=True)

    @property
    def next_run(self):
        try:
            return croniter(
                self.crontab,
                datetime.now(tz=dateutil.tz.gettz(self.timezone)),
                ret_type=datetime
            ).get_next(datetime)
        except (CroniterError, ValueError):
            # An unparseable crontab must not break serialization of the list
            return None

    __mapper_args__ = {
        'polymorphic_on': type
    }


class AgentsSchedule(SchedulerGeneric):
    __tablename__ = None

    executor = relationship(
        'Executor',
        backref=backref('schedules', cascade="all, delete-orphan"),
    )

    @declared_attr
    def executor_id(self):
        return SchedulerGeneric.__table__.c.get('executor_id',
                                                Column(Integer,
                                                       db.ForeignKey('executor.id'),
                                                       nullable=False,
                                                       index=True))

    @property
    def parent(self):
        return self.executor.agent

    __mapper_args__ = {
        'polymorphic_identity': SchedulerGeneric.SCHEDULER_TYPES[1]
    }


class CloudAgentsSchedule(SchedulerGeneric):
    __tablename__ = None
    cloud_agent = relationship(
        'CloudAgent',
        backref=backref('schedules', cascade="all, delete-orphan"),
    )

    @property
    def parent(self):
        return self.cloud_agent

    @declared_attr
    def cloud_agent_id(self):
        return SchedulerGeneric.__table__.c.get('cloud_agent_id',
                                                Column(Integer,
                                                       db.ForeignKey('cloud_agent.id'),
                                                       nullable=False,
                                                       index=True))

    __mapper_args__ = {
        'polymorphic_identity': SchedulerGeneric.SCHEDULER_TYPES[0]
    }


class Agent(Metadata):
    __tablename__ = 'agent'
    id = Column(Integer, primary_key=True)
    token = Column(Text, unique=True, nullable=False, default=lambda: "".
                   join([SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(64)]))

    name = NonBlankColumn(Text)
    description = BlankColumn(Text)
    active = Column(Boolean, default=True)
    sid = Column(Text)  # socketio sid

    @property
    def parent(self):
        return

    @property
    def is_online(self):
        return self.sid is not None

    @property
    def is_offline(self):
        return self.sid is None

    @property
    def status(self):
        if self.is_online:
            return 'online'
        else:
            return 'offline'

    @property
    def last_run(self):
        execs = db.session.query(Executor).filter_by(agent_id=self.id)
        if execs:
            _last_run = None
            for exe in execs:
                if _last_run is None or (exe.last_run is not None and _last_run - exe.last_run <= timedelta()):
                    _last_run = exe.last_run
            return _last_run
        return None

    def __repr__(self):
        return f"Agent {self.name}"


class AgentExecution(Metadata):
    __tablename__ = 'agent_execution'
    id = Column(Integer, primary_key=True)
    running = Column(Boolean, nullable=True)
    successful = Column(Boolean, nullable=True)
    message = Column(String, nullable=True)
    executor_id = Column(Integer, ForeignKey('executor.id', ondelete='CASCADE'), index=True, nullable=False)
    executor = relationship('Executor', foreign_keys=[executor_id],
                            backref=backref('executions', cascade="all, delete-orphan"))

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('agent_executions', cascade="all, delete-orphan")
    )
    parameters_data = Column(JSONType, nullable=False)
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)
    command = relationship(
        'Command',
        foreign_keys=[command_id],
        backref=backref('agent_execution_id', cascade="all, delete-orphan")
    )
    triggered_by = Column(String, nullable=True)
    run_uuid = Column(UUID(as_uuid=True), nullable=True, index=True)

    @property
    def parent(self):
        return

    def notification_message(self, _event, user=None):
        if self.command.end_date:
            return f"{self.executor.agent.name} finished"
        elif self.running:
            return f"{self.executor.agent.name} running"


class CloudAgent(Metadata):
    __tablename__ = "cloud_agent"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True)
    access_token = Column(Text, unique=True)
    params = Column(JSONType)
    parameters_data = Column(JSONType, nullable=False, default={})
    category = Column(JSONType, nullable=True)
    description = BlankColumn(Text)
    tools_count = Column(Integer, nullable=False, default=1)
    website = Column(Text, nullable=True)

    @property
    def last_run(self):
        execs = db.session.query(CloudAgentExecution).filter_by(cloud_agent_id=self.id)
        if execs:
            _last_run = None
            for exe in execs:
                if _last_run is None or (exe.last_run is not None and _last_run - exe.last_run <= timedelta()):
                    _last_run = exe.last_run
            return _last_run
        return None

    @property
    def parent(self):
        return


class CloudAgentExecution(Metadata):
    __tablename__ = 'cloud_agent_execution'
    id = Column(Integer, primary_key=True)
    running = Column(Boolean, nullable=True)
    successful = Column(Boolean, nullable=True)
    message = Column(String, nullable=True)

    cloud_agent_id = Column(Integer, ForeignKey('cloud_agent.id', ondelete='CASCADE'), index=True, nullable=False)
    cloud_agent = relationship(
        'CloudAgent',
        backref=backref('cloud_agent_executions', cascade="all, delete-orphan"),
    )

    workspace_id = Column(Integer, ForeignKey('workspace.id'), index=True, nullable=False)
    workspace = relationship(
        'Workspace',
        backref=backref('cloud_agent_executions', cascade="all, delete-orphan")
    )
    parameters_data = Column(JSONType, nullable=False)
    command_id = Column(Integer, ForeignKey('command.id', ondelete='SET NULL'), index=True)
    command = relationship(
        'Command',
        foreign_keys=[command_id],
        backref=backref('cloud_agent_execution_id', cascade="all, delete-orphan")
    )
    last_run = Column(DateTime)
    triggered_by = Column(String, nullable=True)
    run_uuid = Column(UUID(as_uuid=True), nullable=True, index=True)
    tasks_completed = Column(Integer, nullable=False, default=0)

    @property
    def parent(self):
        return
