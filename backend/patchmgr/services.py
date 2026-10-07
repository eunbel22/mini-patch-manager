from collections import defaultdict

from django.db.models import Count
from django.utils import timezone

from .models import (
    AffectedSoftware,
    Deployment,
    Endpoint,
    InstalledSoftware,
    Patch,
    PatchStatus,
    Severity,
    Software,
)
from .versions import is_affected

UNSCORED = 'unscored'  # 아직 위험도 점수가 없는 CVE


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
        previous = existing.get(patch.id)
        if previous and previous.status == PatchStatus.Status.ROLLED_BACK:
            # 롤백된 PC는 새 배포가 시작되어 되돌려지기 전까지 롤백 상태를 유지한다
            # (에이전트가 아직 제거하지 않아 KB가 남아 있다고 보고해도 마찬가지다)
            new_status, error_code = PatchStatus.Status.ROLLED_BACK, ''
        elif kb in error_codes:
            new_status, error_code = PatchStatus.Status.ERROR, error_codes[kb]
        elif kb in installed_kbs:
            new_status, error_code = PatchStatus.Status.APPLIED, ''
        else:
            new_status, error_code = PatchStatus.Status.PENDING, ''
        PatchStatus.objects.update_or_create(
            endpoint=endpoint, patch=patch,
            defaults={'status': new_status, 'error_code': error_code, 'reported_at': now},
        )
        touched_patch_ids.append(patch.id)

    # 오류 보고 패치 표시: 오류 상태인 PC가 하나라도 있거나 가장 최근 배포가 롤백됐으면 True, 둘 다 아니면 False
    for patch in Patch.objects.filter(id__in=touched_patch_ids):
        latest = Deployment.objects.filter(patch=patch).order_by('-id').first()
        has_error = (
            PatchStatus.objects.filter(patch=patch, status=PatchStatus.Status.ERROR).exists()
            or (latest is not None and latest.state == Deployment.State.ROLLED_BACK)
        )
        if patch.is_error_reported != has_error:
            patch.is_error_reported = has_error
            patch.save(update_fields=['is_error_reported'])


def assess_vulnerabilities(endpoint=None, endpoint_ids=None):
    """설치된 소프트웨어 버전이 CVE의 영향 범위에 들어가는지 판단한다. endpoint나 endpoint_ids를 주면 그 PC만 본다.

    (PC, CVE, 소프트웨어)마다 한 건을 돌려준다.
      - status 'vulnerable': 영향 범위에 들어감
      - status 'unknown': 버전을 읽지 못해 판단 불가 (취약으로 세지 않고 따로 센다)
    같은 CVE에 범위가 여러 줄이면 하나라도 해당되면 vulnerable이다. 해당되지 않는 것은 돌려주지 않는다.
    """
    rows_by_software = defaultdict(list)
    for row in AffectedSoftware.objects.select_related('cve'):
        rows_by_software[row.software_id].append(row)

    installed = InstalledSoftware.objects.select_related('software')
    if endpoint is not None:
        installed = installed.filter(endpoint=endpoint)
    if endpoint_ids is not None:
        installed = installed.filter(endpoint_id__in=endpoint_ids)

    findings = {}
    for item in installed:
        for row in rows_by_software.get(item.software_id, []):
            result = is_affected(item.version, row)
            if result is False:
                continue
            key = (item.endpoint_id, row.cve_id, item.software_id)
            status = 'vulnerable' if result else 'unknown'
            if key in findings and findings[key]['status'] == 'vulnerable':
                continue
            findings[key] = {
                'endpoint_id': item.endpoint_id,
                'cve_id': row.cve.cve_id,
                'severity': row.cve.severity or UNSCORED,
                'cvss_score': row.cve.cvss_score,
                'software': item.software.name,
                'installed_version': item.version,
                'status': status,
            }
    return list(findings.values())


def endpoint_stats(endpoint_ids):
    """PC 목록의 각 줄에 보여 줄 숫자를 PC id별로 돌려준다. (목록 한 쪽에 있는 PC만 계산한다)

      - unapplied: 적용되지 않은 패치 수 (미적용 + 오류 + 롤백)
      - error: 오류 상태인 패치 수
      - vulnerable: 설치된 버전이 영향 범위에 들어가는 CVE 수 (판단 불가는 세지 않는다)
    """
    stats = {pk: {'unapplied': 0, 'error': 0, 'vulnerable': 0} for pk in endpoint_ids}

    rows = (
        PatchStatus.objects.filter(endpoint_id__in=endpoint_ids)
        .values('endpoint_id', 'status')
        .annotate(total=Count('id'))
    )
    for row in rows:
        if row['status'] != PatchStatus.Status.APPLIED:
            stats[row['endpoint_id']]['unapplied'] += row['total']
        if row['status'] == PatchStatus.Status.ERROR:
            stats[row['endpoint_id']]['error'] += row['total']

    cves = defaultdict(set)
    for finding in assess_vulnerabilities(endpoint_ids=endpoint_ids):
        if finding['status'] == 'vulnerable':
            cves[finding['endpoint_id']].add(finding['cve_id'])
    for pk, found in cves.items():
        stats[pk]['vulnerable'] = len(found)
    return stats


def dashboard_summary():
    """패치 적용 현황 요약. 패치율 = 적용된 수 / 전체 (PC와 패치 한 쌍이 한 건)"""
    counts = {status.value: 0 for status in PatchStatus.Status}
    for row in PatchStatus.objects.values('status').annotate(total=Count('id')):
        counts[row['status']] = row['total']
    total = sum(counts.values())

    # 설치된 소프트웨어 버전 기준으로 취약한 PC 수 (위험도별). 한 PC가 여러 등급에 걸리면 각각 센다.
    affected_endpoints = {severity: set() for severity in [*reversed(Severity.values), UNSCORED]}
    unknown = 0
    for finding in assess_vulnerabilities():
        if finding['status'] == 'vulnerable':
            affected_endpoints[finding['severity']].add(finding['endpoint_id'])
        else:
            unknown += 1

    return {
        'patch_rate': round(counts[PatchStatus.Status.APPLIED] / total, 4) if total else None,
        'total': total,
        'status_counts': counts,
        'endpoint_count': Endpoint.objects.count(),
        'reported_endpoint_count': Endpoint.objects.filter(last_reported_at__isnull=False).count(),
        'software_vulnerable_endpoints_by_severity': {
            severity: len(ids) for severity, ids in affected_endpoints.items()
        },
        'unknown_assessments': unknown,
        'running_deployments': Deployment.objects.filter(state=Deployment.State.RUNNING).count(),
    }
