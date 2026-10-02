from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CVE, Endpoint, EndpointGroup, Patch, Policy
from .services import dashboard_summary
from .tasks import process_agent_report
from .serializers import (
    AgentReportSerializer,
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


class AgentReportView(APIView):
    """에이전트 상태 보고. 형식만 확인하고 바로 202로 응답하며, 패치 상태 갱신은 Celery 작업이 처리한다."""

    @extend_schema(
        request=AgentReportSerializer,
        responses={
            202: OpenApiResponse(description='접수됨. 처리는 비동기로 진행된다.'),
            404: OpenApiResponse(description='등록되지 않은 PC'),
        },
    )
    def post(self, request):
        serializer = AgentReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        if not Endpoint.objects.filter(hostname=payload['hostname']).exists():
            return Response({'detail': '등록되지 않은 PC입니다.'}, status=status.HTTP_404_NOT_FOUND)
        process_agent_report.delay(payload)
        return Response({'status': 'accepted'}, status=status.HTTP_202_ACCEPTED)


class DashboardSummaryView(APIView):
    """패치율과 상태별 건수 (대시보드 화면에서 위험도별 미적용 PC 등은 이후에 더한다)"""

    @extend_schema(responses={200: OpenApiResponse(description='패치 적용 현황 요약')})
    def get(self, request):
        return Response(dashboard_summary())
