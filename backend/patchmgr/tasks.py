from celery import shared_task

from .nvd import collect_recent
from .services import apply_agent_report


@shared_task
def ping():
    """Celery와 RabbitMQ 연결 확인용 작업"""
    return 'pong'


@shared_task
def fetch_recent_cves(hours=24):
    """NVD에서 최근 hours시간 안에 바뀐 CVE를 가져와 저장한다. Celery Beat가 주기적으로 실행한다."""
    created, updated, skipped = collect_recent(hours=hours)
    return {'created': created, 'updated': updated, 'skipped': skipped}


@shared_task
def process_agent_report(payload):
    """에이전트 보고를 처리한다 (패치 상태 갱신). API는 보고를 큐에 넣고 바로 응답하고, 이 작업이 처리한다."""
    apply_agent_report(payload)
