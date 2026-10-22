from django.core.management.base import BaseCommand
from django.db import transaction

from patchmgr.models import Endpoint, EndpointGroup

# 부하 테스트용 가상 PC. seed_demo의 PC 4종 Windows와 같은 이름을 쓴다(패치의 대상 Windows와 맞아야 패치 상태가 만들어진다).
OS_CHOICES = [
    ('Windows 10 22H2', '10.0.19045.4000'),
    ('Windows 11 23H2', '10.0.22631.4000'),
    ('Windows Server 2019', '10.0.17763.6000'),
    ('Windows Server 2022', '10.0.20348.2600'),
]


class Command(BaseCommand):
    help = (
        '부하 테스트용 가상 PC를 만든다(load-0001, load-0002, ...). 이미 있으면 건드리지 않아 여러 번 실행해도 같은 결과가 된다. '
        '지우려면 --delete.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=1000, help='만들 PC 수 (기본 1000)')
        parser.add_argument('--delete', action='store_true', help='부하 테스트용 PC(load-로 시작)를 모두 지운다')

    @transaction.atomic
    def handle(self, *args, **options):
        if options['delete']:
            deleted, _ = Endpoint.objects.filter(hostname__startswith='load-').delete()
            self.stdout.write(self.style.SUCCESS(f'부하 테스트용 PC와 딸린 기록 {deleted}건을 지웠습니다.'))
            return

        group, _ = EndpointGroup.objects.get_or_create(name='일반')
        existing = set(Endpoint.objects.filter(hostname__startswith='load-').values_list('hostname', flat=True))
        new = []
        for number in range(1, options['count'] + 1):
            hostname = f'load-{number:04d}'
            if hostname in existing:
                continue
            os_name, os_build = OS_CHOICES[(number - 1) % len(OS_CHOICES)]
            new.append(Endpoint(hostname=hostname, os_name=os_name, os_build=os_build, group=group))
        Endpoint.objects.bulk_create(new)
        total = Endpoint.objects.filter(hostname__startswith='load-').count()
        self.stdout.write(self.style.SUCCESS(f'부하 테스트용 PC {total}대 (새로 {len(new)}대)'))
