from django.db.models import Count, F, Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from .deployment import DeploymentError, deployment_status, is_eligible, start_deployment, tasks_for_endpoint
from .models import CVE, Deployment, Endpoint, EndpointGroup, Patch, Policy
from .services import dashboard_summary, endpoint_stats
from .tasks import process_agent_report
from .serializers import (
    AgentReportSerializer,
    AgentTasksSerializer,
    CVESerializer,
    DeployRequestSerializer,
    DeploymentStatusSerializer,
    PatchListSerializer,
    EndpointDetailSerializer,
    EndpointGroupSerializer,
    EndpointListSerializer,
    PatchSerializer,
    PolicySerializer,
    SearchResultSerializer,
)


class EndpointGroupViewSet(viewsets.ReadOnlyModelViewSet):
    """그룹 목록 (PC 목록의 필터와 정책 편집에서 그룹을 고르는 데 쓴다)"""

    queryset = EndpointGroup.objects.order_by('id')
    serializer_class = EndpointGroupSerializer


@extend_schema_view(
    list=extend_schema(parameters=[
        OpenApiParameter('group', int, description='그룹 id'),
        OpenApiParameter('status', str, description='패치 상태(pending, applied, error, rolled_back). 그 상태인 패치가 하나라도 있는 PC'),
        OpenApiParameter('search', str, description='호스트 이름의 일부 (대소문자 구분 없음)'),
    ]),
)
class EndpointViewSet(viewsets.ReadOnlyModelViewSet):
    """PC 목록과 상세. 목록은 ?group=, ?status=, ?search=(호스트 이름)로 거를 수 있고 줄마다 미적용 · 오류 · 취약 건수가 붙는다."""

    def get_queryset(self):
        queryset = Endpoint.objects.select_related('group').order_by('id')
        if self.action == 'retrieve':
            return queryset.prefetch_related('installed_software__software', 'patch_statuses__patch')
        params = self.request.query_params
        if params.get('group'):
            queryset = queryset.filter(group_id=params['group'])
        if params.get('status'):
            queryset = queryset.filter(patch_statuses__status=params['status']).distinct()
        search = params.get('search', '').strip()
        if search:
            queryset = queryset.filter(hostname__icontains=search)
        return queryset

    def get_serializer_class(self):
        return EndpointDetailSerializer if self.action == 'retrieve' else EndpointListSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        items = page if page is not None else list(queryset)
        stats = endpoint_stats([endpoint.id for endpoint in items])  # 이 쪽에 보이는 PC만 계산한다
        serializer = self.get_serializer(items, many=True, context={**self.get_serializer_context(), 'stats': stats})
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)


class CVEViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """CVE 상세 (CVSS, 영향받는 소프트웨어, 해결하는 KB)"""

    queryset = CVE.objects.prefetch_related('affected_software__software', 'patches')
    serializer_class = CVESerializer


@extend_schema_view(
    list=extend_schema(parameters=[
        OpenApiParameter('policy', int, description='정책 id. 주면 그 정책으로 배포할 수 있는 패치만(최소 위험도 이상이고 진행 중인 배포가 없는 것)'),
    ]),
)
class PatchViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """패치(KB) 목록과 상세"""

    def get_serializer_class(self):
        return PatchListSerializer if self.action == 'list' else PatchSerializer

    def get_queryset(self):
        queryset = Patch.objects.prefetch_related('cves').order_by('kb_number', 'target_os')
        policy_id = self.request.query_params.get('policy') if self.action == 'list' else None
        if policy_id:
            policy = Policy.objects.filter(pk=policy_id).first() if policy_id.isdigit() else None
            if policy is None:
                return queryset.none()
            busy = set(Deployment.objects.filter(state=Deployment.State.RUNNING).values_list('patch_id', flat=True))
            ids = [patch.id for patch in queryset if is_eligible(policy, patch) and patch.id not in busy]
            queryset = queryset.filter(id__in=ids)
        return queryset


class PolicyViewSet(viewsets.ModelViewSet):
    """패치 정책 목록, 상세, 생성, 수정, 삭제 (배포 단계 포함)"""

    queryset = Policy.objects.prefetch_related('stages').order_by('id')
    serializer_class = PolicySerializer

    def destroy(self, request, *args, **kwargs):
        policy = self.get_object()
        if policy.deployments.filter(state=Deployment.State.RUNNING).exists():
            return Response({'detail': '진행 중인 배포가 있는 정책은 삭제할 수 없습니다.'}, status=status.HTTP_409_CONFLICT)
        return super().destroy(request, *args, **kwargs)

    @extend_schema(
        request=DeployRequestSerializer,
        responses={
            201: DeploymentStatusSerializer,
            400: OpenApiResponse(description='꺼 둔 정책, 단계 없음, 정책의 대상이 아닌 패치 등'),
            409: OpenApiResponse(description='그 패치는 이미 배포가 진행 중'),
        },
    )
    @action(detail=True, methods=['post'], url_path='deploy')
    def deploy(self, request, pk=None):
        """정책을 지정한 패치 하나에 실행하기 시작한다. 1단계(보통 테스트 그룹)부터 시작한다."""
        policy = self.get_object()
        serializer = DeployRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            deployment = start_deployment(policy, serializer.validated_data['patch'])
        except DeploymentError as error:
            return Response({'detail': error.message}, status=error.status_code)
        return Response(DeploymentStatusSerializer(deployment_status(deployment)).data, status=status.HTTP_201_CREATED)

    @extend_schema(responses=DeploymentStatusSerializer(many=True))
    @action(detail=True, methods=['get'], url_path='status')
    def deployment_progress(self, request, pk=None):
        """이 정책의 배포 진행 상태 (최근 20건). 단계마다 대상 PC 수, 상태별 수, 오류율을 준다."""
        policy = self.get_object()
        deployments = policy.deployments.select_related('policy', 'patch', 'current_stage').order_by('-id')[:20]
        return Response(DeploymentStatusSerializer([deployment_status(item) for item in deployments], many=True).data)


class AgentTasksView(APIView):
    """에이전트가 서버에 "나한테 할 일이 있나?"를 묻는 API. 설치해도 되는 KB(install)와 제거할 KB(uninstall)를 준다."""

    @extend_schema(
        responses={200: AgentTasksSerializer, 404: OpenApiResponse(description='등록되지 않은 PC')},
    )
    def get(self, request, hostname):
        endpoint = Endpoint.objects.filter(hostname=hostname).first()
        if endpoint is None:
            return Response({'detail': '등록되지 않은 PC입니다.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(AgentTasksSerializer(tasks_for_endpoint(endpoint)).data)


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
