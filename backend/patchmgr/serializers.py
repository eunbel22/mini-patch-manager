from django.db import transaction
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


class EndpointDetailSerializer(EndpointSerializer):
    installed_software = InstalledSoftwareSerializer(many=True)
    patch_statuses = PatchStatusSerializer(many=True)

    class Meta(EndpointSerializer.Meta):
        fields = EndpointSerializer.Meta.fields + ['installed_software', 'patch_statuses']


class AffectedSoftwareSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='software.name')
    vendor = serializers.CharField(source='software.vendor')

    class Meta:
        model = AffectedSoftware
        fields = ['id', 'name', 'vendor', 'version_start', 'version_end_excluding']


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
