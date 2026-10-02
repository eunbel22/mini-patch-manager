"""NVD(미국 국립 취약점 데이터베이스) API 2.0에서 CVE를 가져와 저장한다."""
import json
import os
import time
from datetime import datetime, timedelta, timezone
from urllib import error, parse, request

from django.db import transaction

from .models import CVE, Severity

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


@transaction.atomic
def save_cves(parsed):
    """파싱된 CVE 목록을 저장한다. 이미 있으면 갱신한다. (새로 만든 수, 갱신한 수)를 돌려준다."""
    created = updated = 0
    for values in parsed:
        cve_id = values.pop('cve_id')
        _, was_created = CVE.objects.update_or_create(cve_id=cve_id, defaults=values)
        created += was_created
        updated += not was_created
    return created, updated


def collect_recent(hours=24, now=None):
    """최근 hours시간 안에 바뀐 CVE를 NVD에서 가져와 저장한다. (새로, 갱신, 건너뜀)을 돌려준다."""
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    api_key = os.environ.get('NVD_API_KEY') or None

    parsed, skipped = [], 0
    for item in fetch_modified_since(start, end, api_key):
        try:
            parsed.append(parse_cve(item))
        except (KeyError, ValueError):
            skipped += 1
    created, updated = save_cves(parsed)
    return created, updated, skipped
