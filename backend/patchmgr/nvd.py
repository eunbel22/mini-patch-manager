"""NVD(미국 국립 취약점 데이터베이스) API 2.0에서 CVE를 가져와 저장한다."""
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib import error, parse, request

from django.db import transaction

from .models import CVE, AffectedSoftware, Severity, SoftwareCpe

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
PAGE_SIZE = 2000
MAX_ATTEMPTS = 3

# 위험도 점수는 CVSS 3.1을 먼저 쓰고, 없으면 4.0, 3.0 순서로 쓴다
METRIC_KEYS = ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30')
VALID_SEVERITIES = set(Severity.values)


class NvdError(Exception):
    pass


def parse_cve(item):
    """NVD 응답의 vulnerabilities 항목 하나를 우리 CVE 칸에 맞는 dict로 바꾼다."""
    cve = item['cve']

    description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')

    score, severity = None, ''
    for key in METRIC_KEYS:
        metrics = cve.get('metrics', {}).get(key)
        if not metrics:
            continue
        # NVD가 직접 매긴 점수(Primary)를 우선한다
        chosen = next((m for m in metrics if m.get('type') == 'Primary'), metrics[0])
        data = chosen['cvssData']
        score = data.get('baseScore')
        severity = (data.get('baseSeverity') or '').lower()
        break
    if severity not in VALID_SEVERITIES:
        severity = ''

    published = cve.get('published')
    published_at = datetime.fromisoformat(published).replace(tzinfo=timezone.utc) if published else None

    return {
        'cve_id': cve['id'],
        'description': description,
        'cvss_score': score,
        'severity': severity,
        'published_at': published_at,
    }


def _split_cpe(criteria):
    """CPE 2.3 문자열을 칸으로 나눈다. 역슬래시로 이스케이프된 콜론은 나누지 않고, 역슬래시는 뺀다."""
    return [re.sub(r'\\(.)', r'\1', part) for part in re.split(r'(?<!\\):', criteria)]


def parse_affected(item):
    """CVE 하나에서 영향받는 응용 프로그램(vulnerable이 true인 CPE)의 제조사 · 제품 · 버전 범위를 뽑는다.

    "다른 소프트웨어 위에서 실행될 때만 해당"하는 조건(vulnerable=false)과 응용 프로그램이 아닌 것(운영체제, 하드웨어)은 뺀다.
    """
    found, seen = [], set()
    for config in item['cve'].get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if not match.get('vulnerable'):
                    continue
                parts = _split_cpe(match['criteria'])
                if len(parts) < 6 or parts[2] != 'a':
                    continue
                version = parts[5]
                entry = {
                    'vendor': parts[3].lower(),
                    'product': parts[4].lower(),
                    'version_start_including': match.get('versionStartIncluding', ''),
                    'version_start_excluding': match.get('versionStartExcluding', ''),
                    'version_end_including': match.get('versionEndIncluding', ''),
                    'version_end_excluding': match.get('versionEndExcluding', ''),
                    # 버전 칸이 *(전체) 또는 -(해당 없음)이 아니면 특정 버전 하나를 가리킨다
                    'version_exact': '' if version in ('*', '-') else version,
                }
                key = tuple(entry.values())
                if key not in seen:
                    seen.add(key)
                    found.append(entry)
    return found


def _get(url, api_key):
    headers = {'User-Agent': 'mini-patch-manager'}
    if api_key:
        headers['apiKey'] = api_key
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with request.urlopen(request.Request(url, headers=headers), timeout=60) as response:
                return json.load(response)
        except error.HTTPError as exc:
            # 429(요청이 너무 많음), 403/503(일시적 제한)이면 잠깐 쉬고 다시 시도한다. 키는 오류 메시지에 넣지 않는다.
            if exc.code in (403, 429, 503) and attempt < MAX_ATTEMPTS:
                time.sleep(6 * attempt)
                continue
            raise NvdError(f'NVD 요청 실패: HTTP {exc.code}') from None
        except error.URLError as exc:
            if attempt < MAX_ATTEMPTS:
                time.sleep(3 * attempt)
                continue
            raise NvdError(f'NVD에 연결하지 못했습니다: {exc.reason}') from None


def fetch_modified_since(start, end, api_key=None):
    """start~end 사이에 바뀐 CVE를 페이지별로 가져온다. (NVD는 한 번에 최대 120일까지만 조회된다)"""
    pause = 0.7 if api_key else 6.5  # NVD 요청 한도(키가 있으면 30초에 50번, 없으면 5번)를 지킨다
    index = 0
    while True:
        query = parse.urlencode({
            'lastModStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000+00:00'),
            'lastModEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.000+00:00'),
            'resultsPerPage': PAGE_SIZE,
            'startIndex': index,
        })
        body = _get(f'{NVD_URL}?{query}', api_key)
        yield from body.get('vulnerabilities', [])
        index += body.get('resultsPerPage', 0)
        if index >= body.get('totalResults', 0) or not body.get('resultsPerPage'):
            return
        time.sleep(pause)


def fetch_by_ids(cve_ids, api_key=None):
    """CVE 번호를 지정해서 가져온다. 확인과 문제 추적에 쓴다."""
    pause = 0.7 if api_key else 6.5
    for position, cve_id in enumerate(cve_ids):
        if position:
            time.sleep(pause)
        body = _get(f'{NVD_URL}?{parse.urlencode({"cveId": cve_id})}', api_key)
        yield from body.get('vulnerabilities', [])


@transaction.atomic
def save_cves(parsed):
    """파싱된 CVE 목록을 저장한다. 이미 있으면 갱신한다. (새로 만든 수, 갱신한 수)를 돌려준다."""
    created = updated = 0
    for values in parsed:
        values = dict(values)
        cve_id = values.pop('cve_id')
        _, was_created = CVE.objects.update_or_create(cve_id=cve_id, defaults=values)
        created += was_created
        updated += not was_created
    return created, updated


@transaction.atomic
def save_affected(affected_by_cve):
    """CVE별 영향 소프트웨어를 저장한다. SoftwareCpe로 우리 소프트웨어와 이어지는 것만 저장하고,
    CVE마다 이전에 저장한 것은 지우고 새로 넣는다. 저장한 줄 수를 돌려준다."""
    mapping = {}
    for link in SoftwareCpe.objects.select_related('software'):
        mapping.setdefault((link.vendor.lower(), link.product.lower()), []).append(link.software)

    cves = {cve.cve_id: cve for cve in CVE.objects.filter(cve_id__in=affected_by_cve)}
    AffectedSoftware.objects.filter(cve__in=cves.values()).delete()

    rows, seen = [], set()
    for cve_id, entries in affected_by_cve.items():
        for entry in entries:
            range_fields = {k: v for k, v in entry.items() if k not in ('vendor', 'product')}
            for software in mapping.get((entry['vendor'], entry['product']), []):
                # 같은 소프트웨어에 이어진 이름 둘이 같은 범위로 나열되면(예: acrobat_reader와 acrobat_reader_dc) 한 줄만 둔다
                key = (cve_id, software.id, tuple(range_fields.values()))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(AffectedSoftware(cve=cves[cve_id], software=software, **range_fields))
    AffectedSoftware.objects.bulk_create(rows)
    return len(rows)


def _ingest(items):
    parsed, affected, skipped = [], {}, 0
    for item in items:
        try:
            values = parse_cve(item)
            affected[values['cve_id']] = parse_affected(item)
        except (KeyError, ValueError):
            skipped += 1
            continue
        parsed.append(values)
    created, updated = save_cves(parsed)
    return {
        'created': created,
        'updated': updated,
        'skipped': skipped,
        'affected': save_affected(affected),
    }


def collect_recent(hours=24, now=None):
    """최근 hours시간 안에 바뀐 CVE를 NVD에서 가져와 저장한다."""
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    api_key = os.environ.get('NVD_API_KEY') or None
    return _ingest(fetch_modified_since(start, end, api_key))


def collect_ids(cve_ids):
    """CVE 번호를 지정해서 NVD에서 가져와 저장한다."""
    api_key = os.environ.get('NVD_API_KEY') or None
    return _ingest(fetch_by_ids(cve_ids, api_key))
