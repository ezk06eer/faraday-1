"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
"""Schemas marshmallow de vulnerabilidades (P4b, extraído de vulns_base)."""
from base64 import b64encode
from depot.manager import DepotManager
from marshmallow import Schema, ValidationError, fields, post_load
from marshmallow.validate import OneOf
from sqlalchemy.orm.exc import NoResultFound
from faraday.server.api.base import (
    AutoSchema,
)
from faraday.server.api.modules.services_base import ServiceSchema
try:
    from faraday.domain.vulnerability.models import VulnerabilityGeneric  # noqa: F401  (ejecuta shard real)
except ImportError:
    pass
from faraday.server.models import (
    File,
    Host,
    REFERENCE_TYPES,
    Service,
    Vulnerability,
    VulnerabilityWeb,
    Workspace,
    db,
)
from faraday.server.schemas import (
    FaradayCustomField,
    MetadataSchema,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
    SeverityField,
)
from faraday.server.utils.vulns import (
    SCHEMA_FIELDS,
    WEB_SCHEMA_FIELDS,
)

class EvidenceSchema(AutoSchema):
    content_type = fields.Method('get_content_type')
    data = fields.Method('get_data')
    description = fields.String()

    class Meta:
        model = File
        fields = ('content_type', 'data', 'description')

    @staticmethod
    def get_content_type(file_obj):
        depot = DepotManager.get()
        return depot.get(file_obj.content.get('file_id')).content_type

    @staticmethod
    def get_data(file_obj):
        depot = DepotManager.get()
        return b64encode(depot.get(file_obj.content.get('file_id')).read()).decode()

class ImpactSchema(Schema):
    accountability = fields.Boolean(attribute='impact_accountability', default=False)
    availability = fields.Boolean(attribute='impact_availability', default=False)
    confidentiality = fields.Boolean(attribute='impact_confidentiality', default=False)
    integrity = fields.Boolean(attribute='impact_integrity', default=False)

class PatchAttachmentSchema(Schema):
    description = fields.String(required=True)

class CustomMetadataSchema(MetadataSchema):
    """
    Implements command_id and creator logic
    """
    command_id = fields.Integer(dump_only=True, attribute='creator_command_id')
    creator = fields.Method('get_creator', dump_only=True)

    @staticmethod
    def get_creator(obj):
        if obj.tool:
            return obj.tool
        else:
            return obj.creator_command_tool or 'Web UI'

class CVESchema(AutoSchema):
    name = fields.String()

class CVSS2Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss2_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss2_base_score", required=False, dump_only=True)
    exploitability_score = fields.Float(attribute="cvss2_exploitability_score", required=False, dump_only=True)
    impact_score = fields.Float(attribute="cvss2_impact_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss2_base_severity", dump_only=True, required=False)
    temporal_score = fields.Float(attribute="cvss2_temporal_score", required=False, dump_only=True)
    temporal_severity = fields.String(attribute="cvss2_temporal_severity", dump_only=True, required=False)
    environmental_score = fields.Float(attribute="cvss2_environmental_score", required=False, dump_only=True)
    environmental_severity = fields.String(attribute="cvss2_environmental_severity", dump_only=True, required=False)
    access_vector = fields.String(attribute="cvss2_access_vector", dump_only=True, required=False)
    access_complexity = fields.String(attribute="cvss2_access_complexity", dump_only=True, required=False)
    authentication = fields.String(attribute="cvss2_authentication", dump_only=True, required=False)
    confidentiality_impact = fields.String(attribute="cvss2_confidentiality_impact", dump_only=True, required=False)
    integrity_impact = fields.String(attribute="cvss2_integrity_impact", dump_only=True, required=False)
    availability_impact = fields.String(attribute="cvss2_availability_impact", dump_only=True, required=False)
    exploitability = fields.String(attribute="cvss2_exploitability", dump_only=True, required=False)
    remediation_level = fields.String(attribute="cvss2_remediation_level", dump_only=True, required=False)
    report_confidence = fields.String(attribute="cvss2_report_confidence", dump_only=True, required=False)
    collateral_damage_potential = fields.String(attribute="cvss2_collateral_damage_potential", dump_only=True, required=False)
    target_distribution = fields.String(attribute="cvss2_target_distribution", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss2_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss2_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss2_availability_requirement", dump_only=True, required=False)

class CVSS3Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss3_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss3_base_score", required=False, dump_only=True)
    exploitability_score = fields.Float(attribute="cvss3_exploitability_score", required=False, dump_only=True)
    impact_score = fields.Float(attribute="cvss3_impact_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss3_base_severity", dump_only=True, required=False)
    temporal_score = fields.Float(attribute="cvss3_temporal_score", required=False, dump_only=True)
    temporal_severity = fields.String(attribute="cvss3_temporal_severity", dump_only=True, required=False)
    environmental_score = fields.Float(attribute="cvss3_environmental_score", required=False, dump_only=True)
    environmental_severity = fields.String(attribute="cvss3_environmental_severity", dump_only=True, required=False)
    attack_vector = fields.String(attribute="cvss3_attack_vector", dump_only=True, required=False)
    attack_complexity = fields.String(attribute="cvss3_attack_complexity", dump_only=True, required=False)
    privileges_required = fields.String(attribute="cvss3_privileges_required", dump_only=True, required=False)
    user_interaction = fields.String(attribute="cvss3_user_interaction", dump_only=True, required=False)
    confidentiality_impact = fields.String(attribute="cvss3_confidentiality_impact", dump_only=True, required=False)
    integrity_impact = fields.String(attribute="cvss3_integrity_impact", dump_only=True, required=False)
    availability_impact = fields.String(attribute="cvss3_availability_impact", dump_only=True, required=False)
    exploit_code_maturity = fields.String(attribute="cvss3_exploit_code_maturity", dump_only=True, required=False)
    remediation_level = fields.String(attribute="cvss3_remediation_level", dump_only=True, required=False)
    report_confidence = fields.String(attribute="cvss3_report_confidence", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss3_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss3_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss3_availability_requirement", dump_only=True, required=False)
    modified_attack_vector = fields.String(attribute="cvss3_modified_attack_vector", dump_only=True, required=False)
    modified_attack_complexity = fields.String(attribute="cvss3_modified_attack_complexity", dump_only=True, required=False)
    modified_privileges_required = fields.String(attribute="cvss3_modified_privileges_required", dump_only=True, required=False)
    modified_user_interaction = fields.String(attribute="cvss3_modified_user_interaction", dump_only=True, required=False)
    modified_scope = fields.String(attribute="cvss3_modified_scope", dump_only=True, required=False)
    modified_confidentiality_impact = fields.String(attribute="cvss3_modified_confidentiality_impact", dump_only=True, required=False)
    modified_integrity_impact = fields.String(attribute="cvss3_modified_integrity_impact", dump_only=True, required=False)
    modified_availability_impact = fields.String(attribute="cvss3_modified_availability_impact", dump_only=True, required=False)
    scope = fields.String(attribute="cvss3_scope", dump_only=True, required=False)

class CVSS4Schema(AutoSchema):
    vector_string = fields.String(attribute="cvss4_vector_string", required=False, allow_none=True)
    base_score = fields.Float(attribute="cvss4_base_score", required=False, dump_only=True)
    base_severity = fields.String(attribute="cvss4_base_severity", dump_only=True, required=False)
    attack_vector = fields.String(attribute="cvss4_attack_vector", dump_only=True, required=False)
    attack_complexity = fields.String(attribute="cvss4_attack_complexity", dump_only=True, required=False)
    attack_requirements = fields.String(attribute="cvss4_attack_requirements", dump_only=True, required=False)
    privileges_required = fields.String(attribute="cvss4_privileges_required", dump_only=True, required=False)
    user_interaction = fields.String(attribute="cvss4_user_interaction", dump_only=True, required=False)
    vulnerable_system_confidentiality_impact = fields.String(attribute="cvss4_vulnerable_system_confidentiality_impact", dump_only=True, required=False)
    subsequent_system_confidentiality_impact = fields.String(attribute="cvss4_subsequent_system_confidentiality_impact", dump_only=True, required=False)
    vulnerable_system_integrity_impact = fields.String(attribute="cvss4_vulnerable_system_integrity_impact", dump_only=True, required=False)
    subsequent_system_integrity_impact = fields.String(attribute="cvss4_subsequent_system_integrity_impact", dump_only=True, required=False)
    vulnerable_system_availability_impact = fields.String(attribute="cvss4_vulnerable_system_availability_impact", dump_only=True, required=False)
    subsequent_system_availability_impact = fields.String(attribute="cvss4_subsequent_system_availability_impact", dump_only=True, required=False)
    safety = fields.String(attribute="cvss4_safety", dump_only=True, required=False)
    automatable = fields.String(attribute="cvss4_automatable", dump_only=True, required=False)
    recovery = fields.String(attribute="cvss4_recovery", dump_only=True, required=False)
    value_density = fields.String(attribute="cvss4_value_density", dump_only=True, required=False)
    vulnerability_response_effort = fields.String(attribute="cvss4_vulnerability_response_effort", dump_only=True, required=False)
    provider_urgency = fields.String(attribute="cvss4_provider_urgency", dump_only=True, required=False)
    modified_attack_vector = fields.String(attribute="cvss4_modified_attack_vector", dump_only=True, required=False)
    modified_attack_complexity = fields.String(attribute="cvss4_modified_attack_complexity", dump_only=True, required=False)
    modified_attack_requirements = fields.String(attribute="cvss4_modified_attack_requirements", dump_only=True, required=False)
    modified_privileges_required = fields.String(attribute="cvss4_modified_privileges_required", dump_only=True, required=False)
    modified_user_interaction = fields.String(attribute="cvss4_modified_user_interaction", dump_only=True, required=False)
    modified_vulnerable_system_confidentiality_impact = fields.String(attribute="cvss4_modified_vulnerable_system_confidentiality_impact", dump_only=True, required=False)
    modified_subsequent_system_confidentiality_impact = fields.String(attribute="cvss4_modified_subsequent_system_confidentiality_impact", dump_only=True, required=False)
    modified_vulnerable_system_integrity_impact = fields.String(attribute="cvss4_modified_vulnerable_system_integrity_impact", dump_only=True, required=False)
    modified_subsequent_system_integrity_impact = fields.String(attribute="cvss4_modified_subsequent_system_integrity_impact", dump_only=True, required=False)
    modified_vulnerable_system_availability_impact = fields.String(attribute="cvss4_modified_vulnerable_system_availability_impact", dump_only=True, required=False)
    modified_subsequent_system_availability_impact = fields.String(attribute="cvss4_modified_subsequent_system_availability_impact", dump_only=True, required=False)
    confidentiality_requirement = fields.String(attribute="cvss4_confidentiality_requirement", dump_only=True, required=False)
    integrity_requirement = fields.String(attribute="cvss4_integrity_requirement", dump_only=True, required=False)
    availability_requirement = fields.String(attribute="cvss4_availability_requirement", dump_only=True, required=False)
    exploit_maturity = fields.String(attribute="cvss4_exploit_maturity", dump_only=True, required=False)

class RiskSchema(AutoSchema):
    score = fields.Int(attribute='risk', dump_only=True)
    severity = fields.Method(serialize='get_risk_severity', dump_only=True)

    @staticmethod
    def get_risk_severity(obj):
        if not obj.risk:
            return None
        if 0 <= obj.risk < 40:
            return 'low'
        if 40 <= obj.risk < 70:
            return 'medium'
        if 70 <= obj.risk < 90:
            return 'high'
        if 90 <= obj.risk <= 100:
            return 'critical'

class CWESchema(AutoSchema):
    name = fields.String()

class OWASPSchema(AutoSchema):
    name = fields.String()

class ReferenceSchema(AutoSchema):
    name = fields.String()
    type = fields.String(validate=OneOf(REFERENCE_TYPES))

class VulnerabilitySchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    _rev = fields.String(dump_only=True, default='')
    _attachments = fields.Method(serialize='get_attachments', deserialize='load_attachments', default=[])
    owned = fields.Boolean(dump_only=True, default=False)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')
    impact = SelfNestedField(ImpactSchema())
    desc = fields.String(attribute='description')
    description = fields.String(dump_only=True)
    policyviolations = fields.List(fields.String, attribute='policy_violations')
    refs = fields.List(fields.Nested(ReferenceSchema), attribute='refs')
    issuetracker = fields.Method(serialize='get_issuetracker_json', deserialize='load_issuetracker', dump_only=True)
    cve = fields.List(fields.String(), attribute='cve')
    cvss2 = SelfNestedField(CVSS2Schema())
    cvss3 = SelfNestedField(CVSS3Schema())
    cvss4 = SelfNestedField(CVSS4Schema())
    tool = fields.String(attribute='tool')
    parent = fields.Method(serialize='get_parent', deserialize='load_parent', required=True)
    parent_type = MutableField(fields.Method('get_parent_type'), fields.String(), required=True)
    cwe = fields.List(fields.Pluck(CWESchema(), "name"))
    tags = PrimaryKeyRelatedField('name', dump_only=True, many=True)
    easeofresolution = fields.String(
        attribute='ease_of_resolution',
        validate=OneOf(Vulnerability.EASE_OF_RESOLUTIONS),
        allow_none=True,
    )
    hostnames = PrimaryKeyRelatedField('name', many=True, dump_only=True)
    service = fields.Nested(ServiceSchema(only=[
        '_id', 'ports', 'status', 'protocol', 'name', 'version', 'summary'
    ]), dump_only=True)
    host = fields.Integer(dump_only=True, attribute='host_id')
    severity = SeverityField(required=True)
    status = fields.Method(
        serialize='get_status',
        validate=OneOf(Vulnerability.STATUSES + ['opened']),
        deserialize='load_status',
    )
    type = fields.Method(serialize='get_type', deserialize='load_type', required=True)
    obj_id = fields.String(dump_only=True, attribute='id')
    target = fields.String(dump_only=True, attribute='target_host_ip')
    host_os = fields.String(dump_only=True, attribute='target_host_os')
    metadata = SelfNestedField(CustomMetadataSchema())
    date = fields.DateTime(attribute='create_date', dump_only=True)  # This is only used for sorting
    update_date = fields.DateTime(attribute='update_date', dump_only=True)
    custom_fields = FaradayCustomField(table_name='vulnerability', attribute='custom_fields')
    external_id = fields.String(allow_none=True)
    command_id = fields.Int(required=False, load_only=True)
    risk = SelfNestedField(RiskSchema(), dump_only=True)
    workspace_name = fields.String(attribute='workspace.name', dump_only=True)
    last_detected = fields.DateTime(dump_only=True)

    class Meta:
        model = Vulnerability
        fields = SCHEMA_FIELDS

    @staticmethod
    def get_type(obj):
        return obj.__class__.__name__

    @staticmethod
    def get_attachments(obj):
        res = {}

        for file_obj in obj.evidence:
            try:
                res[file_obj.filename] = EvidenceSchema().dump(file_obj)
            except OSError:
                logger.warning("File not found. Did you move your server?")

        return res

    @staticmethod
    def load_attachments(value):
        return value

    @staticmethod
    def get_parent(obj):
        return obj.service_id or obj.host_id

    @staticmethod
    def get_parent_type(obj):
        assert obj.service_id is not None or obj.host_id is not None
        return 'Service' if obj.service_id is not None else 'Host'

    @staticmethod
    def get_status(obj):
        return obj.status

    @staticmethod
    def get_issuetracker_json(obj):
        return {}

    @staticmethod
    def load_issuetracker(obj):
        return {}

    @staticmethod
    def load_status(value):
        if value == 'opened':
            return 'open'
        return value

    @staticmethod
    def load_type(value):
        if value == 'Vulnerability':
            return 'vulnerability'
        if value == 'VulnerabilityWeb':
            return 'vulnerability_web'
        else:
            raise ValidationError('Invalid vulnerability type.')

    @staticmethod
    def load_parent(value):
        try:
            # sometimes api requests send str or unicode.
            value = int(value)
        except ValueError as e:
            raise ValidationError("Invalid parent type") from e
        return value

    # @post_load
    # def post_load_owasp(self, data, **kwargs):
    #     owasp = data.pop('owasp', None)
    #     if owasp:
    #         data['owasp'] = [item['name'] for item in owasp]
    #     return data

    @post_load
    def post_load_impact(self, data, **kwargs):
        # Unflatten impact (move data[impact][*] to data[*])
        impact = data.pop('impact', None)
        if impact:
            data.update(impact)
        return data

    @post_load
    def post_load_parent(self, data, **kwargs):
        # schema guarantees that parent_type exists.
        parent_class = None
        parent_field = None
        parent_type = data.pop('parent_type', None)
        parent_id = data.pop('parent', None)

        if not parent_type and not parent_id:
            return data
        if parent_id and parent_type is None:
            raise ValidationError('Trying to modify parent with no parent_type')
        if parent_type and parent_id is None:
            raise ValidationError('Trying to modify parent_type but parent not sent')

        if parent_type == 'Host':
            parent_class = Host
            parent_field = 'host_id'
            data['service_id'] = None
        if parent_type == 'Service':
            parent_class = Service
            parent_field = 'service_id'
            data['host_id'] = None
        if not parent_class:
            raise ValidationError('Unknown parent type')
        if parent_type == 'Host':
            if 'type' in data:
                if data['type'] == 'vulnerability_web':
                    raise ValidationError('Trying to set a host for a vulnerability web')
            elif kwargs.get("partial", False):
                vulnerability = self.context.get("object", None)
                if vulnerability:
                    if vulnerability.type == 'vulnerability_web':
                        raise ValidationError('Trying to set a host for a vulnerability web')
        try:
            parent = db.session.query(parent_class).join(Workspace).filter(
                Workspace.name == self.context['workspace_name'],
                parent_class.id == parent_id
            ).one()
        except NoResultFound as e:
            raise ValidationError(f'Parent id not found: {parent_id}') from e
        data[parent_field] = parent.id
        # TODO migration: check what happens when updating the parent from
        # service to host or vice versa
        return data

    @post_load
    def post_load_cvss2(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss2')

    @post_load
    def post_load_cvss3(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss3')

    @post_load
    def post_load_cvss4(self, data, **kwargs):
        return self._get_vector_string(data, 'cvss4')

    @staticmethod
    def _get_vector_string(data, version):
        if version not in ['cvss2', 'cvss3', 'cvss4']:
            return data

        if version in data:
            vector_string = f'{version}_vector_string'
            cvss = data.pop(version)
            if vector_string in cvss:
                data[vector_string] = cvss[vector_string]
        return data

class VulnerabilityWebSchema(VulnerabilitySchema):
    method = fields.String(default='')
    params = fields.String(attribute='parameters', default='')
    pname = fields.String(attribute='parameter_name', default='')
    path = fields.String(default='')
    response = fields.String(default='')
    request = fields.String(default='')
    website = fields.String(default='')
    query = fields.String(attribute='query_string', default='')
    status_code = fields.Integer(allow_none=True)

    class Meta:
        model = VulnerabilityWeb
        fields = WEB_SCHEMA_FIELDS
