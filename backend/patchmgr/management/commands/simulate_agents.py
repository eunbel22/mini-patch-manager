import json
import random
from collections import Counter
from urllib import error, request

from django.core.management.base import BaseCommand

from patchmgr.models import Endpoint, Patch, PatchStatus


class Command(BaseCommand):
    help = (
        '가상 PC들이 서버에 상태를 보고하는 것을 흉내 낸다. 실행할 때마다 아직 적용 안 한 패치 일부가 적용되어 '
        '패치율이 올라간다. 서버(runserver)와 Celery 워커가 켜져 있어야 한다.'
    )

    def add_arguments(self, parser):
        # localhost 대신 127.0.0.1: 윈도우에서는 localhost가 먼저 IPv6로 시도하다 거절당해 요청마다 약 2초가 걸린다
        parser.add_argument('--url', default='http://127.0.0.1:8000/api/agents/report/')
        parser.add_argument('--apply-rate', type=float, default=0.3,
                            help='아직 적용 안 한 패치를 이번에 적용할 확률 (기본 0.3)')
        parser.add_argument('--error-rate', type=float, default=0.05,
                            help='이번에 설치를 시도하다 오류가 날 확률 (기본 0.05)')
        parser.add_argument('--seed', type=int, default=None, help='같은 결과를 다시 얻고 싶을 때 고정하는 값')

    def handle(self, *args, **options):
        rng = random.Random(options['seed'])
        apply_rate, error_rate = options['apply_rate'], options['error_rate']
        results = Counter()

        for endpoint in Endpoint.objects.prefetch_related('installed_software__software'):
            patches = Patch.objects.filter(target_os=endpoint.os_name)
            applied = set(
                PatchStatus.objects.filter(endpoint=endpoint, status=PatchStatus.Status.APPLIED)
                .values_list('patch__kb_number', flat=True)
            )
            installed_kbs = set(applied)
            errors = []
            for patch in patches:
                if patch.kb_number in applied:
                    continue
                roll = rng.random()
                if roll < error_rate:
                    errors.append({'kb_number': patch.kb_number, 'error_code': '0x80070643'})
                elif roll < error_rate + apply_rate:
                    installed_kbs.add(patch.kb_number)

            payload = {
                'hostname': endpoint.hostname,
                'os_name': endpoint.os_name,
                'os_build': endpoint.os_build,
                'installed_software': [
                    {'name': item.software.name, 'vendor': item.software.vendor, 'version': item.version}
                    for item in endpoint.installed_software.all()
                ],
                'installed_kbs': sorted(installed_kbs),
                'errors': errors,
            }
            results[self._post(options['url'], payload)] += 1

        summary = ', '.join(f'{code}: {count}건' for code, count in sorted(results.items(), key=str))
        self.stdout.write(self.style.SUCCESS(f'보고 {sum(results.values())}건 전송 ({summary})'))

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
