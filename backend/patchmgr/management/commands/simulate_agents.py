import json
import random
from collections import Counter
from urllib import error, request

from django.core.management.base import BaseCommand

from patchmgr.models import Endpoint, Patch, PatchStatus


class Command(BaseCommand):
    help = (
        '가상 PC들이 서버에 한 번씩 접속하는 것을 흉내 낸다. 서버가 허락한 설치만 하고(단계적 배포를 따른다), 결과를 보고한다. '
        '서버(runserver)와 Celery 워커가 켜져 있어야 한다.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--base', default='http://127.0.0.1:8000',
                            help='서버 주소. localhost 대신 127.0.0.1: 윈도우에서는 localhost가 먼저 IPv6로 시도하다 거절당해 요청마다 약 2초가 걸린다')
        parser.add_argument('--apply-rate', type=float, default=0.6,
                            help='설치 지시를 받은 PC가 이번 접속에서 실제로 설치를 시도할 확률 (기본 0.6, PC마다 접속 시점이 다른 것을 흉내)')
        parser.add_argument('--error-rate', type=float, default=0.1,
                            help='설치를 시도했을 때 실패할 확률 (기본 0.1)')
        parser.add_argument('--seed', type=int, default=None, help='같은 결과를 다시 얻고 싶을 때 고정하는 값')
        parser.add_argument('--unmanaged', action='store_true',
                            help='서버의 지시와 상관없이 미적용 패치를 마음대로 적용한다 (예전 방식. 부하 시험용)')

    def handle(self, *args, **options):
        rng = random.Random(options['seed'])
        base = options['base'].rstrip('/')
        results, actions = Counter(), Counter()

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
