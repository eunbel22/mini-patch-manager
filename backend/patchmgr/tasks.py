from celery import shared_task

from .deployment import advance_all
from .nvd import collect_recent
from .services import apply_agent_report


@shared_task
def ping():
    """Celery와 RabbitMQ 연결 확인용 작업"""
    return 'pong'


@shared_task
def fetch_recent_cves(hours=24):
    """NVD에서 최근 hours시간 안에 바뀐 CVE를 가져와 저장한다. Celery Beat가 주기적으로 실행한다."""
    return collect_recent(hours=hours)


@shared_task
def process_agent_report(payload):
    """에이전트 보고를 처리한다 (패치 상태 갱신). API는 보고를 큐에 넣고 바로 응답하고, 이 작업이 처리한다."""
    apply_agent_report(payload)
    # 보고가 들어왔으니 진행 중인 배포를 바로 점검한다 (1분 주기 점검을 기다리지 않고 단계를 넘기거나 롤백한다)
    advance_all()


@shared_task
def advance_deployments():
    """진행 중인 배포를 점검해서 단계를 넘기거나 롤백한다. Celery Beat가 주기적으로 실행한다."""
    return {'changed': advance_all()}
