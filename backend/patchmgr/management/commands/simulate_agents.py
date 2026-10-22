import hashlib
import json
import os
import random
import time
from collections import Counter
from urllib import error, request

from django.core.management.base import BaseCommand

from patchmgr.models import Endpoint, Patch, PatchStatus

# 파일 검증(sha256)에 실패했을 때 에이전트가 보고하는 오류 코드 (Windows의 TRUST_E_BAD_DIGEST와 같은 값)
ERROR_BAD_DIGEST = '0x80096010'


class DownloadUnavailable(Exception):
    """서버가 바쁘거나(429 · 503) 연결에 실패해 파일을 받지 못했다. 설치하지 않고 다음 접속에서 다시 시도한다."""


class DigestMismatch(Exception):
    """받은 파일의 크기나 sha256이 서버가 알려 준 값과 다르다. 중간에 바뀌었거나 깨진 파일이라 설치하지 않는다."""


def download_package(base, package, corrupt=False):
    """패치 파일을 내려받으면서 sha256을 계산하고, 서버가 알려 준 크기·sha256과 같은지 확인한다.

    corrupt=True면 받은 첫 바이트를 바꿔서 중간에 파일이 변조된 상황을 흉내 낸다.
    반환값은 (받은 바이트 수, 걸린 시간 초). 느린 속도 제한이 걸려 있으면 그만큼 오래 걸린다.
    """
    digest = hashlib.sha256()
    total = 0
    started = time.monotonic()
    try:
        with request.urlopen(base + package['url'], timeout=60) as response:
            while chunk := response.read(64 * 1024):
                if corrupt and total == 0:
                    chunk = bytes([chunk[0] ^ 0xFF]) + chunk[1:]
                digest.update(chunk)
                total += len(chunk)
    except (error.HTTPError, error.URLError, TimeoutError, ConnectionError) as exc:
        raise DownloadUnavailable(str(exc)) from exc
    elapsed = time.monotonic() - started
    if total != package['size'] or digest.hexdigest() != package['sha256']:
        raise DigestMismatch(f'{total}바이트, sha256 {digest.hexdigest()[:12]}...')
    return total, elapsed


class Command(BaseCommand):
    help = (
        '가상 PC들이 서버에 한 번씩 접속하는 것을 흉내 낸다. 서버가 허락한 설치만 하고(단계적 배포를 따른다), 결과를 보고한다. '
        '서버(runserver)와 Celery 워커가 켜져 있어야 한다.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--base', default=os.environ.get('SIMULATOR_BASE', 'http://127.0.0.1:8000'),
                            help='서버 주소. localhost 대신 127.0.0.1: 윈도우에서는 localhost가 먼저 IPv6로 시도하다 거절당해 요청마다 약 2초가 걸린다. '
                                 '패치 파일(/patches/)은 Nginx가 내려주므로, 파일을 받으려면 Nginx를 거치는 주소여야 한다(compose의 backend 컨테이너는 환경변수 SIMULATOR_BASE=http://frontend가 기본값)')
        parser.add_argument('--apply-rate', type=float, default=0.6,
                            help='설치 지시를 받은 PC가 이번 접속에서 실제로 설치를 시도할 확률 (기본 0.6, PC마다 접속 시점이 다른 것을 흉내)')
        parser.add_argument('--error-rate', type=float, default=0.1,
                            help='설치를 시도했을 때 실패할 확률 (기본 0.1)')
        parser.add_argument('--seed', type=int, default=None, help='같은 결과를 다시 얻고 싶을 때 고정하는 값')
        parser.add_argument('--no-download', action='store_true',
                            help='패치 파일을 내려받지 않고 지시만 따른다 (파일이 없는 예전 방식)')
        parser.add_argument('--corrupt-rate', type=float, default=0.0,
                            help='파일을 받는 도중 변조될 확률 (기본 0). 변조되면 sha256 검증에 실패해 설치하지 않고 오류를 보고한다')
        parser.add_argument('--unmanaged', action='store_true',
                            help='서버의 지시와 상관없이 미적용 패치를 마음대로 적용한다 (예전 방식. 부하 시험용)')

    def handle(self, *args, **options):
        rng = random.Random(options['seed'])
        base = options['base'].rstrip('/')
        results, actions = Counter(), Counter()
        downloaded, download_seconds = 0, 0.0

        for endpoint in Endpoint.objects.prefetch_related('installed_software__software'):
            statuses = {
                row.patch.kb_number: row
                for row in PatchStatus.objects.filter(endpoint=endpoint).select_related('patch')
            }
            # PC가 가지고 있는 상태: 설치된 KB와 이전에 실패한 KB(에이전트는 실패를 기억해서 보고마다 다시 알린다)
            installed = {kb for kb, row in statuses.items() if row.status == PatchStatus.Status.APPLIED}
            errors = {kb: row.error_code for kb, row in statuses.items() if row.status == PatchStatus.Status.ERROR}

            if options['unmanaged']:
                self._act_unmanaged(rng, endpoint, installed, errors, options, actions)
            else:
                tasks = self._get(f"{base}/api/agents/{endpoint.hostname}/tasks/")
                if tasks is None:
                    results['지시 조회 실패'] += 1
                    continue
                for item in tasks['uninstall']:
                    if item['kb_number'] in installed:
                        installed.discard(item['kb_number'])
                        actions['제거'] += 1
                for item in tasks['install']:
                    kb = item['kb_number']
                    if rng.random() > options['apply_rate']:
                        continue  # 이번 접속에서는 설치하지 않았다
                    package = item.get('package')
                    if package and not options['no_download']:
                        corrupt = options['corrupt_rate'] > 0 and rng.random() < options['corrupt_rate']
                        try:
                            nbytes, seconds = download_package(base, package, corrupt=corrupt)
                        except DownloadUnavailable:
                            actions['내려받기 미룸'] += 1  # 서버가 바쁘면 설치하지 않고 다음 접속에서 다시 시도
                            continue
                        except DigestMismatch:
                            errors[kb] = ERROR_BAD_DIGEST
                            actions['파일 검증 실패'] += 1
                            continue
                        downloaded += nbytes
                        download_seconds += seconds
                        actions['내려받기'] += 1
                    if rng.random() < options['error_rate']:
                        errors[kb] = '0x80070643'
                        actions['설치 실패'] += 1
                    else:
                        installed.add(kb)
                        errors.pop(kb, None)
                        actions['설치 성공'] += 1

            payload = {
                'hostname': endpoint.hostname,
                'os_name': endpoint.os_name,
                'os_build': endpoint.os_build,
                'installed_software': [
                    {'name': item.software.name, 'vendor': item.software.vendor, 'version': item.version}
                    for item in endpoint.installed_software.all()
                ],
                'installed_kbs': sorted(installed),
                'errors': [{'kb_number': kb, 'error_code': code} for kb, code in sorted(errors.items())],
            }
            results[self._post(f'{base}/api/agents/report/', payload)] += 1

        summary = ', '.join(f'{code}: {count}건' for code, count in sorted(results.items(), key=str))
        did = ', '.join(f'{name} {count}건' for name, count in actions.items()) or '없음'
        self.stdout.write(self.style.SUCCESS(f'보고 {sum(results.values())}건 전송 ({summary}) / 이번에 한 일: {did}'))
        if downloaded:
            mb = downloaded / 1024 / 1024
            self.stdout.write(f'내려받은 양 {mb:.1f}MB, 파일 하나당 평균 속도 {mb / download_seconds:.2f}MB/초')

    def _act_unmanaged(self, rng, endpoint, installed, errors, options, actions):
        """예전 방식: 서버의 지시와 상관없이 이 PC의 Windows에 해당하는 미적용 패치를 확률로 적용한다."""
        for patch in Patch.objects.filter(target_os=endpoint.os_name):
            if patch.kb_number in installed or patch.kb_number in errors:
                continue
            roll = rng.random()
            if roll < options['error_rate']:
                errors[patch.kb_number] = '0x80070643'
                actions['설치 실패'] += 1
            elif roll < options['error_rate'] + options['apply_rate']:
                installed.add(patch.kb_number)
                actions['설치 성공'] += 1

    def _get(self, url):
        try:
            with request.urlopen(url, timeout=10) as response:
                return json.load(response)
        except (error.HTTPError, error.URLError):
            return None

    def _post(self, url, payload):
        req = request.Request(
            url, data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST',
        )
        try:
            with request.urlopen(req, timeout=10) as response:
                return response.status
        except error.HTTPError as exc:
            return exc.code
        except error.URLError:
            return '연결 실패'
