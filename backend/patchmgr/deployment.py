"""정책에 따른 단계적 배포와 롤백.

흐름:
  1. start_deployment: 정책을 패치 하나에 실행하기 시작한다 (1단계에 들어간다).
  2. 에이전트가 tasks_for_endpoint로 "내가 설치해도 되는 KB"를 물어서 가져간다.
     지금 단계의 그룹에 속한 PC에게만, 그 단계의 대기 시간이 지난 뒤에만 지시가 나간다.
  3. advance_all이 진행 중인 배포를 점검한다 (Celery Beat 1분마다 + 에이전트 보고를 처리한 직후).
       - 단계의 오류율이 롤백 기준을 넘으면 롤백한다.
       - 단계의 대상 PC가 모두 결과(적용 · 오류)를 냈으면 다음 단계로 넘긴다. 마지막 단계면 완료한다.
  오류율 = 오류인 PC 수 ÷ 그 단계 그룹의 대상 PC 전체(패치의 대상 Windows와 같은 PC). 오류율이 기준을 "넘으면" 롤백한다.
"""
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Count
from django.utils import timezone

from .models import Deployment, Endpoint, PatchStatus

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
SEVERITY_LABEL = {'low': '낮음', 'medium': '보통', 'high': '높음', 'critical': '매우 높음'}


class DeploymentError(Exception):
    """배포를 시작할 수 없을 때. status_code는 API가 그대로 돌려준다."""

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def patch_severity_rank(patch):
    """패치가 해결하는 CVE 중 가장 높은 위험도의 순위 (CVE가 없거나 점수가 없으면 0)"""
    return max((SEVERITY_RANK.get(cve.severity, 0) for cve in patch.cves.all()), default=0)


def is_eligible(policy, patch):
    return patch_severity_rank(patch) >= SEVERITY_RANK[policy.min_severity]


def _percent(rate):
    return f'{rate * 100:.1f}'.rstrip('0').rstrip('.')


def stage_ready_at(deployment):
    """현재 단계의 PC들에게 설치 지시가 나가기 시작하는 시각 (단계에 들어간 시각 + 대기 시간)"""
    stage = deployment.current_stage
    if stage is None or deployment.stage_started_at is None:
        return None
    return deployment.stage_started_at + timedelta(minutes=stage.delay_minutes)


def stage_counts(stage, patch):
    """단계 그룹의 대상 PC 수와 상태별 수. 상태 줄이 아직 없는 PC는 '대기'로 센다."""
    target_ids = list(
        Endpoint.objects.filter(group_id=stage.group_id, os_name=patch.target_os).values_list('id', flat=True)
    )
    counts = {status.value: 0 for status in PatchStatus.Status}
    rows = (
        PatchStatus.objects.filter(patch=patch, endpoint_id__in=target_ids)
        .values('status').annotate(total=Count('id'))
    )
    for row in rows:
        counts[row['status']] = row['total']
    counts['pending'] += len(target_ids) - sum(counts.values())
    return len(target_ids), counts


def start_deployment(policy, patch, now=None):
    now = now or timezone.now()
    if not policy.is_active:
        raise DeploymentError('꺼 둔 정책은 배포할 수 없습니다.')
    first = policy.stages.order_by('order').first()
    if first is None:
        raise DeploymentError('배포 단계가 없는 정책은 배포할 수 없습니다.')
    if not is_eligible(policy, patch):
        raise DeploymentError(
            f'이 패치가 해결하는 CVE 중 정책의 최소 위험도({SEVERITY_LABEL[policy.min_severity]}) 이상인 것이 없어 '
            '이 정책의 대상이 아닙니다.'
        )
    if Deployment.objects.filter(patch=patch, state=Deployment.State.RUNNING).exists():
        raise DeploymentError('이 패치는 이미 배포가 진행 중입니다.', 409)

    try:
        with transaction.atomic():
            # 이전 배포에서 롤백됐거나 설치에 실패한 PC는 다시 처음 상태(미적용)로 되돌린다.
            # 원인을 고친 뒤 다시 시도하는 것이 재배포의 목적이고, 오류 상태를 남겨 두면 시작하자마자 오류율이
            # 기준을 넘어 또 롤백되기 때문이다. 이미 적용된 PC는 그대로 둔다.
            PatchStatus.objects.filter(
                patch=patch, status__in=[PatchStatus.Status.ROLLED_BACK, PatchStatus.Status.ERROR],
            ).update(status=PatchStatus.Status.PENDING, error_code='')
            deployment = Deployment.objects.create(
                policy=policy, patch=patch, current_stage=first, state=Deployment.State.RUNNING, stage_started_at=now,
            )
    except IntegrityError:  # 거의 동시에 같은 패치의 배포가 시작된 경우
        raise DeploymentError('이 패치는 이미 배포가 진행 중입니다.', 409) from None

    advance_deployment(deployment, now)  # 대상 PC가 없는 단계는 바로 넘어간다
    return deployment


def _roll_back(deployment, stage, error_rate, now):
    patch = deployment.patch
    # 지금까지 설치 지시가 나간 단계(현재 단계까지)에서 적용된 PC는 "롤백" 상태로 바꾼다.
    # 에이전트는 tasks API의 uninstall 목록을 보고 제거한다. 설치에 실패한 PC는 되돌릴 것이 없어 그대로 둔다.
    for done_stage in deployment.policy.stages.filter(order__lte=stage.order):
        PatchStatus.objects.filter(
            patch=patch, status=PatchStatus.Status.APPLIED,
            endpoint__group_id=done_stage.group_id, endpoint__os_name=patch.target_os,
        ).update(status=PatchStatus.Status.ROLLED_BACK)

    deployment.state = Deployment.State.ROLLED_BACK
    deployment.finished_at = now
    deployment.note = (
        f'{stage.order}단계 오류율 {_percent(error_rate)}%가 롤백 기준 {_percent(stage.rollback_error_rate)}%를 넘어 롤백했습니다.'
    )
    deployment.save(update_fields=['state', 'finished_at', 'note'])

    # 오류가 난 패치로 분류한다 (오류 PC가 남아 있는 한 유지되고, 롤백된 배포가 있으면 계속 유지된다)
    patch.is_error_reported = True
    patch.save(update_fields=['is_error_reported'])


def advance_deployment(deployment, now=None):
    """배포 하나를 점검해서 롤백하거나 다음 단계로 넘긴다. 바뀐 것이 있으면 True."""
    now = now or timezone.now()
    changed = False
    for _ in range(deployment.policy.stages.count() + 1):  # 대상 없는 단계가 이어져도 끝난다
        if deployment.state != Deployment.State.RUNNING or deployment.current_stage is None:
            break
        stage = deployment.current_stage
        ready_at = stage_ready_at(deployment)
        if ready_at is not None and now < ready_at:
            break  # 이 단계는 대기 시간이 아직 안 지났다

        total, counts = stage_counts(stage, deployment.patch)
        error_rate = counts['error'] / total if total else 0
        if total and error_rate > stage.rollback_error_rate:
            _roll_back(deployment, stage, error_rate, now)
            return True
        if counts['pending'] > 0:
            break  # 아직 결과를 내지 않은 PC가 있다

        next_stage = deployment.policy.stages.filter(order__gt=stage.order).order_by('order').first()
        if next_stage is None:
            deployment.state = Deployment.State.COMPLETED
            deployment.finished_at = now
            deployment.save(update_fields=['state', 'finished_at'])
            return True
        deployment.current_stage = next_stage
        deployment.stage_started_at = now
        deployment.save(update_fields=['current_stage', 'stage_started_at'])
        changed = True
    return changed


def advance_all(now=None):
    """진행 중인 배포를 모두 점검한다. 바뀐 배포의 수를 돌려준다."""
    now = now or timezone.now()
    changed = 0
    running = Deployment.objects.filter(state=Deployment.State.RUNNING).select_related(
        'policy', 'patch', 'current_stage',
    )
    for deployment in running:
        changed += advance_deployment(deployment, now)
    return changed


def tasks_for_endpoint(endpoint, now=None):
    """에이전트(PC)가 서버에 물어서 가져가는 일 목록.

    install: 설치해도 되는 KB. 진행 중인 배포 중 이 PC의 그룹이 현재 단계이고, 그 단계의 대기 시간이 지났고,
             패치의 대상 Windows가 이 PC와 같고, 아직 설치 전(상태 줄이 없거나 미적용)인 것만 나간다.
             설치에 실패한 PC(오류)에게는 다시 지시하지 않는다.
    uninstall: 롤백된 패치. 에이전트가 설치돼 있다면 제거한다.
    """
    now = now or timezone.now()
    status_by_patch = dict(PatchStatus.objects.filter(endpoint=endpoint).values_list('patch_id', 'status'))

    install = []
    running = Deployment.objects.filter(state=Deployment.State.RUNNING).select_related('patch', 'current_stage')
    for deployment in running:
        stage = deployment.current_stage
        if stage is None or stage.group_id != endpoint.group_id or deployment.patch.target_os != endpoint.os_name:
            continue
        ready_at = stage_ready_at(deployment)
        if ready_at is not None and now < ready_at:
            continue
        if status_by_patch.get(deployment.patch_id) in (None, PatchStatus.Status.PENDING):
            install.append({
                'deployment': deployment.id, 'patch': deployment.patch_id, 'kb_number': deployment.patch.kb_number,
            })

    rolled_back = PatchStatus.objects.filter(endpoint=endpoint, status=PatchStatus.Status.ROLLED_BACK).select_related('patch')
    uninstall = [{'patch': row.patch_id, 'kb_number': row.patch.kb_number} for row in rolled_back]
    return {'install': install, 'uninstall': uninstall}


def deployment_status(deployment, now=None):
    """배포 하나의 진행 상태 (정책 화면에 보여 줄 값). 단계마다 대상 · 상태별 PC 수와 오류율을 준다."""
    now = now or timezone.now()
    current = deployment.current_stage
    ready_at = stage_ready_at(deployment) if deployment.state == Deployment.State.RUNNING else None

    stages = []
    for stage in deployment.policy.stages.select_related('group').order_by('order'):
        total, counts = stage_counts(stage, deployment.patch)
        if deployment.state == Deployment.State.COMPLETED:
            state = 'done'
        elif current is None:
            state = 'upcoming'
        elif stage.order < current.order:
            state = 'done'
        elif stage.id == current.id:
            if deployment.state == Deployment.State.ROLLED_BACK:
                state = 'failed'
            else:
                state = 'waiting' if ready_at is not None and now < ready_at else 'active'
        else:
            state = 'upcoming'
        stages.append({
            'order': stage.order,
            'group': stage.group_id,
            'group_name': stage.group.name,
            'delay_minutes': stage.delay_minutes,
            'rollback_error_rate': stage.rollback_error_rate,
            'state': state,
            'target_count': total,
            'applied': counts['applied'],
            'error': counts['error'],
            'pending': counts['pending'],
            'rolled_back': counts['rolled_back'],
            'error_rate': round(counts['error'] / total, 4) if total else 0,
        })

    return {
        'id': deployment.id,
        'policy': deployment.policy_id,
        'patch': {
            'id': deployment.patch_id,
            'kb_number': deployment.patch.kb_number,
            'target_os': deployment.patch.target_os,
        },
        'state': deployment.state,
        'current_stage_order': current.order if current else None,
        'stage_ready_at': ready_at,
        'started_at': deployment.started_at,
        'finished_at': deployment.finished_at,
        'note': deployment.note,
        'stages': stages,
    }
