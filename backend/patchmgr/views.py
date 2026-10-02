from django.db.models import Count, F, Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
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
    SearchResultSerializer,
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


class SearchView(APIView):
    """CVE · KB 통합 검색. CVE 번호, KB 번호, CVE 설명의 일부로 찾는다."""

    LIMIT = 20  # 종류별로 최대 몇 건까지 보여 줄지

    @extend_schema(
        parameters=[OpenApiParameter('q', str, required=True, description='CVE 번호, KB 번호(숫자만도 가능) 또는 설명의 일부. 2글자 이상')],
        responses={200: SearchResultSerializer, 400: OpenApiResponse(description='검색어가 없거나 너무 짧음')},
    )
    def get(self, request):
        q = request.query_params.get('q', '').strip()
        if len(q) < 2:
            return Response({'detail': '검색어(q)는 2글자 이상이어야 합니다.'}, status=status.HTTP_400_BAD_REQUEST)

        cves = (
            CVE.objects.filter(Q(cve_id__icontains=q) | Q(description__icontains=q))
            .order_by(F('cvss_score').desc(nulls_last=True), '-published_at')[:self.LIMIT]
        )
        # KB 번호는 숫자만 입력해도 찾는다 (5044273 -> KB5044273). CVE 번호로 그 CVE를 고치는 KB도 찾는다.
        kb = f'KB{q}' if q.isdigit() else q
        patches = (
            Patch.objects.filter(Q(kb_number__icontains=kb) | Q(cves__cve_id__icontains=q))
            .distinct()
            .annotate(cve_count=Count('cves', distinct=True))
            .order_by(F('release_date').desc(nulls_last=True), 'kb_number')[:self.LIMIT]
        )
        return Response(SearchResultSerializer({'cves': cves, 'patches': patches}).data)


class DashboardSummaryView(APIView):
    """패치율과 상태별 건수 (대시보드 화면에서 위험도별 미적용 PC 등은 이후에 더한다)"""

    @extend_schema(responses={200: OpenApiResponse(description='패치 적용 현황 요약')})
    def get(self, request):
        return Response(dashboard_summary())
