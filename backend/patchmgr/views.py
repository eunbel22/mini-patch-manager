from rest_framework import mixins, viewsets

from .models import CVE, Endpoint, EndpointGroup, Patch, Policy
from .serializers import (
    CVESerializer,
    EndpointDetailSerializer,
    EndpointGroupSerializer,
    EndpointSerializer,
    PatchSerializer,
    PolicySerializer,
)


class EndpointGroupViewSet(viewsets.ReadOnlyModelViewSet):
    """그룹 목록 (PC 목록의 필터와 정책 편집에서 그룹을 고르는 데 쓴다)"""

    queryset = EndpointGroup.objects.order_by('id')
    serializer_class = EndpointGroupSerializer


class EndpointViewSet(viewsets.ReadOnlyModelViewSet):
    """PC 목록과 상세. 목록은 ?group=<그룹 id>, ?status=<패치 상태>로 거를 수 있다."""

    def get_queryset(self):
        queryset = Endpoint.objects.select_related('group').order_by('id')
        if self.action == 'retrieve':
            return queryset.prefetch_related('installed_software__software', 'patch_statuses__patch')
        group = self.request.query_params.get('group')
        status = self.request.query_params.get('status')
        if group:
            queryset = queryset.filter(group_id=group)
        if status:
            queryset = queryset.filter(patch_statuses__status=status).distinct()
        return queryset

    def get_serializer_class(self):
        return EndpointDetailSerializer if self.action == 'retrieve' else EndpointSerializer


class CVEViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """CVE 상세 (CVSS, 영향받는 소프트웨어, 해결하는 KB)"""

    queryset = CVE.objects.prefetch_related('affected_software__software', 'patches')
    serializer_class = CVESerializer


class PatchViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """패치(KB) 상세"""

    queryset = Patch.objects.prefetch_related('cves')
    serializer_class = PatchSerializer


class PolicyViewSet(viewsets.ModelViewSet):
    """패치 정책 목록, 상세, 생성, 수정, 삭제 (배포 단계 포함)"""

    queryset = Policy.objects.prefetch_related('stages').order_by('id')
    serializer_class = PolicySerializer
