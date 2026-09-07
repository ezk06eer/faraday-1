# Domain Shards - Faraday

Generado determinísticamente desde faraday/server/models.py:1 (4248L, grafo in-degree 71)

## Estrategia
Shim primero: `faraday/server/models.py` re-exporta desde `faraday/domain/*`. Luego extraer por agregado con tests verdes.

## Shards
- **workspace** (6 clases, first_line 361): DatabaseMetadata, SeveritiesHistogram, VulnerabilityHitCount, Workspace, Scope, WorkspacePermission
- **host_service** (5 clases, first_line 397): SourceCode, Hostname, Host, Service, Credential
- **command** (8 clases, first_line 477): CustomFieldsSchema, CommandObject, Command, File, Tag, TagObject, Comment, ObjectType
- **vulnerability** (19 clases, first_line 489): VulnerabilityABC, VulnerabilityTemplate, CVE, VulnerabilityGroup, VulnerabilityGeneric, Vulnerability, VulnerabilityWeb, VulnerabilityCode, ReferenceTemplate, Reference, VulnerabilityReference, OWASP, ReferenceVulnerabilityAssociation, PolicyViolationVulnerabilityAssociation, ReferenceTemplateVulnerabilityAssociation, PolicyViolationTemplateVulnerabilityAssociation, PolicyViolationTemplate, PolicyViolation, CWE
- **user_auth** (9 clases, first_line 2717): Role, UserToken, User, UserAvatar, MethodologyTemplate, Methodology, PlannerProject, ProjectTask, License
- **notification** (12 clases, first_line 3072): ExecutiveReport, EventType, NotificationSubscription, NotificationSubscriptionConfigBase, NotificationSubscriptionMailConfig, NotificationSubscriptionWebHookConfig, NotificationSubscriptionWebSocketConfig, NotificationEvent, NotificationBase, MailNotification, WebHookNotification, Notification
- **agent_workflow** (10 clases, first_line 3360): Pipeline, Workflow, Condition, Action, WorkflowExecution, Executor, SchedulerGeneric, Agent, AgentExecution, CloudAgent
- **other** (21 clases, first_line None): Metadata, CustomAssociationSet, WebsocketNotification, AgentsSchedule, CloudAgentsSchedule, CloudAgentExecution, SearchFilter, Configuration, Analytics, BaseNotification, UserNotification, UserNotificationSettings, EmailNotification, SlackNotification, VulnerabilityStatusHistory, PermissionsGroup, PermissionsUnit, PermissionsUnitAction, RolePermission, WorkspaceSummaryReport, WorkspaceSummaryReportRun
