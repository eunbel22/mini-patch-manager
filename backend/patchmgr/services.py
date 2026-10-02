from django.db.models import Count
from django.utils import timezone

from .models import Endpoint, InstalledSoftware, Patch, PatchStatus, Software


def apply_agent_report(payload):
    """PC가 보낸 보고를 DB에 반영한다. Celery 작업이 호출한다.

    PC는 자기 상태(설치 SW, 설치된 KB, 오류)만 알리고, 각 패치가 적용인지 미적용인지 오류인지는
    여기서 서버가 정한다.
    """
    now = timezone.now()
    endpoint = Endpoint.objects.get(hostname=payload['hostname'])
    endpoint.os_name = payload['os_name']
    endpoint.os_build = payload['os_build']
    endpoint.last_reported_at = now
    endpoint.save(update_fields=['os_name', 'os_build', 'last_reported_at'])

    # 설치된 소프트웨어: 보고는 전체 목록이므로 목록에 없는 것은 지운다
    seen_software_ids = []
    for item in payload['installed_software']:
        software, _ = Software.objects.get_or_create(name=item['name'], vendor=item.get('vendor', ''))
        InstalledSoftware.objects.update_or_create(
            endpoint=endpoint, software=software, defaults={'version': item['version']},
        )
        seen_software_ids.append(software.id)
    endpoint.installed_software.exclude(software_id__in=seen_software_ids).delete()

    # 패치 상태: 이 PC의 Windows 종류에 해당하는 패치만 본다
    installed_kbs = {kb.upper() for kb in payload['installed_kbs']}
    error_codes = {item['kb_number'].upper(): item['error_code'] for item in payload['errors']}
    existing = {status.patch_id: status for status in PatchStatus.objects.filter(endpoint=endpoint)}

    touched_patch_ids = []
    for patch in Patch.objects.filter(target_os=endpoint.os_name):
        kb = patch.kb_number.upper()
        if kb in error_codes:
            new_status, error_code = PatchStatus.Status.ERROR, error_codes[kb]
        elif kb in installed_kbs:
            new_status, error_code = PatchStatus.Status.APPLIED, ''
        else:
            new_status, error_code = PatchStatus.Status.PENDING, ''
            # 롤백된 패치는 PC가 아직 안 깔았다고 보고해도 롤백 상태를 유지한다
            previous = existing.get(patch.id)
            if previous and previous.status == PatchStatus.Status.ROLLED_BACK:
                new_status = PatchStatus.Status.ROLLED_BACK
        PatchStatus.objects.update_or_create(
            endpoint=endpoint, patch=patch,
            defaults={'status': new_status, 'error_code': error_code, 'reported_at': now},
        )
        touched_patch_ids.append(patch.id)

    # 오류 보고 패치 표시: 오류 상태인 PC가 하나라도 있으면 True, 모두 사라지면 False
    for patch in Patch.objects.filter(id__in=touched_patch_ids):
        has_error = PatchStatus.objects.filter(patch=patch, status=PatchStatus.Status.ERROR).exists()
        if patch.is_error_reported != has_error:
            patch.is_error_reported = has_error
            patch.save(update_fields=['is_error_reported'])


def dashboard_summary():
    """패치 적용 현황 요약. 패치율 = 적용된 수 / 전체 (PC와 패치 한 쌍이 한 건)"""
    counts = {status.value: 0 for status in PatchStatus.Status}
    for row in PatchStatus.objects.values('status').annotate(total=Count('id')):
        counts[row['status']] = row['total']
    total = sum(counts.values())
    return {
        'patch_rate': round(counts[PatchStatus.Status.APPLIED] / total, 4) if total else None,
        'total': total,
        'status_counts': counts,
        'endpoint_count': Endpoint.objects.count(),
        'reported_endpoint_count': Endpoint.objects.filter(last_reported_at__isnull=False).count(),
    }
