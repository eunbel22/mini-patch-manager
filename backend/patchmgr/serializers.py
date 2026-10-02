from django.db import transaction
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .models import (
    CVE,
    AffectedSoftware,
    Endpoint,
    EndpointGroup,
    InstalledSoftware,
    Patch,
    PatchStatus,
    Policy,
    PolicyStage,
)
from .services import assess_vulnerabilities


class EndpointGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndpointGroup
        fields = ['id', 'name']


class InstalledSoftwareSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='software.name')
    vendor = serializers.CharField(source='software.vendor')

    class Meta:
        model = InstalledSoftware
        fields = ['id', 'name', 'vendor', 'version']


class PatchStatusSerializer(serializers.ModelSerializer):
    kb_number = serializers.CharField(source='patch.kb_number')
    target_os = serializers.CharField(source='patch.target_os')

    class Meta:
        model = PatchStatus
        fields = ['id', 'patch', 'kb_number', 'target_os', 'status', 'error_code', 'reported_at']


class EndpointSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='group.name')

    class Meta:
        model = Endpoint
        fields = ['id', 'hostname', 'os_name', 'os_build', 'group', 'group_name', 'last_reported_at']


class VulnerabilitySerializer(serializers.Serializer):
    """PC에 설치된 소프트웨어 버전이 CVE의 영향 범위에 들어가는지에 대한 판단 결과"""

    cve_id = serializers.CharField()
    severity = serializers.CharField()
    cvss_score = serializers.DecimalField(max_digits=3, decimal_places=1, allow_null=True)
    software = serializers.CharField()
    installed_version = serializers.CharField()
    status = serializers.ChoiceField(choices=['vulnerable', 'unknown'])


class EndpointDetailSerializer(EndpointSerializer):
    installed_software = InstalledSoftwareSerializer(many=True)
    patch_statuses = PatchStatusSerializer(many=True)
    vulnerabilities = serializers.SerializerMethodField()

    class Meta(EndpointSerializer.Meta):
        fields = EndpointSerializer.Meta.fields + ['installed_software', 'patch_statuses', 'vulnerabilities']

    @extend_schema_field(VulnerabilitySerializer(many=True))
    def get_vulnerabilities(self, obj):
        findings = assess_vulnerabilities(endpoint=obj)
        order = {'vulnerable': 0, 'unknown': 1}
        findings.sort(key=lambda f: (order[f['status']], f['cve_id']))
        return VulnerabilitySerializer(findings, many=True).data


class AffectedSoftwareSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='software.name')
    vendor = serializers.CharField(source='software.vendor')

    class Meta:
        model = AffectedSoftware
        fields = [
            'id', 'name', 'vendor', 'version_start_including', 'version_start_excluding',
            'version_end_including', 'version_end_excluding', 'version_exact',
        ]


class PatchSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Patch
        fields = ['id', 'kb_number', 'target_os', 'fixed_build', 'download_url']


class CVESerializer(serializers.ModelSerializer):
    affected_software = AffectedSoftwareSerializer(many=True)
    patches = PatchSummarySerializer(many=True)

    class Meta:
        model = CVE
        fields = [
            'id', 'cve_id', 'description', 'cvss_score', 'severity', 'published_at',
            'affected_software', 'patches',
        ]


class CVESummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = ['id', 'cve_id', 'cvss_score', 'severity']


class PatchSerializer(serializers.ModelSerializer):
    cves = CVESummarySerializer(many=True)

    class Meta:
        model = Patch
        fields = [
            'id', 'kb_number', 'title', 'target_os', 'fixed_build', 'release_date',
            'download_url', 'is_error_reported', 'cves',
        ]


class SearchCVESerializer(serializers.ModelSerializer):
    description = serializers.SerializerMethodField()

    class Meta:
        model = CVE
        fields = ['id', 'cve_id', 'severity', 'cvss_score', 'published_at', 'description']

    def get_description(self, obj) -> str:
        # 목록에서는 앞부분만 보여 준다
        return obj.description[:200]


class SearchPatchSerializer(serializers.ModelSerializer):
    cve_count = serializers.IntegerField()

    class Meta:
        model = Patch
        fields = ['id', 'kb_number', 'target_os', 'fixed_build', 'release_date', 'cve_count']


class SearchResultSerializer(serializers.Serializer):
    cves = SearchCVESerializer(many=True)
    patches = SearchPatchSerializer(many=True)


class PolicyStageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PolicyStage
        fields = ['id', 'order', 'group', 'delay_minutes', 'rollback_error_rate']


class PolicySerializer(serializers.ModelSerializer):
    stages = PolicyStageSerializer(many=True, required=False)

    class Meta:
        model = Policy
        fields = ['id', 'name', 'min_severity', 'start_time', 'is_active', 'stages']

    def validate_stages(self, stages):
        orders = [stage['order'] for stage in stages]
        if len(orders) != len(set(orders)):
            raise serializers.ValidationError('단계 순서(order)가 겹칩니다.')
        return stages

    @transaction.atomic
    def create(self, validated_data):
        stages = validated_data.pop('stages', [])
        policy = Policy.objects.create(**validated_data)
        PolicyStage.objects.bulk_create(PolicyStage(policy=policy, **stage) for stage in stages)
        return policy

    @transaction.atomic
    def update(self, instance, validated_data):
        stages = validated_data.pop('stages', None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        instance.save()
        if stages is not None:
            # 단계를 통째로 바꾼다. 진행 중인 배포의 current_stage는 비워진다(SET_NULL).
            # 배포 로직을 만들 때(Day 8) 진행 중인 배포가 있으면 수정을 막을지 정한다.
            instance.stages.all().delete()
            PolicyStage.objects.bulk_create(PolicyStage(policy=instance, **stage) for stage in stages)
        return instance


class ReportedSoftwareSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    vendor = serializers.CharField(max_length=200, required=False, allow_blank=True, default='')
    version = serializers.CharField(max_length=100)


class ReportedErrorSerializer(serializers.Serializer):
    kb_number = serializers.CharField(max_length=20)
    error_code = serializers.CharField(max_length=50)


class AgentReportSerializer(serializers.Serializer):
    """에이전트(PC)가 보내는 보고. 설치된 SW 전체, 설치된 KB 전체, 설치에 실패한 KB와 오류 코드."""

    hostname = serializers.CharField(max_length=100)
    os_name = serializers.CharField(max_length=100)
    os_build = serializers.CharField(max_length=50)
    installed_software = ReportedSoftwareSerializer(many=True, required=False, default=list)
    installed_kbs = serializers.ListField(child=serializers.CharField(max_length=20), required=False, default=list)
    errors = ReportedErrorSerializer(many=True, required=False, default=list)
