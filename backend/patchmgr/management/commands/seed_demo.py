import random

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction

from patchmgr.models import Endpoint, EndpointGroup, InstalledSoftware, Policy, PolicyStage, Software

# 모두 개발 · 시연용 가상 데이터다. 실제 PC나 실제 버전 현황이 아니다.

GROUPS = [
    # (이름, PC 수)
    ('테스트', 5),
    ('일반', 40),
    ('예외', 5),
]

# (OS 이름, 가상 빌드 번호). 일부러 낮은 번호를 써서, 나중에 패치의 fixed_build와 비교하면 미적용으로 나온다.
OS_CHOICES = [
    ('Windows 10 22H2', '10.0.19045.4000'),
    ('Windows 11 23H2', '10.0.22631.4000'),
    ('Windows Server 2019', '10.0.17763.6000'),
    ('Windows Server 2022', '10.0.20348.2600'),
]

# (이름, 제조사, 가상 버전 3개: 낮은 것 → 높은 것)
SOFTWARE = [
    ('Google Chrome', 'Google', ['118.0', '124.0', '130.0']),
    ('Mozilla Firefox', 'Mozilla', ['115.0', '121.0', '128.0']),
    ('Microsoft Edge', 'Microsoft', ['118.0', '124.0', '130.0']),
    ('Adobe Acrobat Reader', 'Adobe', ['23.1', '24.1', '24.4']),
    ('한컴오피스', 'Hancom', ['2018', '2020', '2022']),
    ('7-Zip', 'Igor Pavlov', ['22.01', '23.01', '24.05']),
    ('Notepad++', 'Notepad++ Team', ['8.4', '8.5', '8.6']),
    ('VLC media player', 'VideoLAN', ['3.0.16', '3.0.18', '3.0.20']),
    ('Zoom', 'Zoom', ['5.14', '5.16', '5.17']),
    ('Slack', 'Slack', ['4.30', '4.35', '4.38']),
    ('Microsoft Teams', 'Microsoft', ['1.5', '1.6', '1.7']),
    ('Oracle Java Runtime', 'Oracle', ['8u341', '8u381', '8u421']),
    ('Apache Log4j', 'Apache', ['2.14.0', '2.17.1', '2.20.0']),
    ('Python', 'Python Software Foundation', ['3.9.13', '3.11.5', '3.12.4']),
    ('Git', 'Git', ['2.39', '2.42', '2.45']),
    ('Visual Studio Code', 'Microsoft', ['1.80', '1.85', '1.90']),
    ('WinRAR', 'win.rar GmbH', ['6.11', '6.24', '7.01']),
    ('Node.js', 'OpenJS Foundation', ['16.20', '18.18', '20.14']),
    ('PuTTY', 'Simon Tatham', ['0.78', '0.79', '0.81']),
    ('AhnLab V3', 'AhnLab', ['9.0', '9.1', '9.2']),
]


class Command(BaseCommand):
    help = '시연용 가상 데이터(그룹 3개, 소프트웨어 20종, PC 50대와 설치 목록)를 넣는다. 여러 번 실행해도 같은 결과가 된다.'

    @transaction.atomic
    def handle(self, *args, **options):
        rng = random.Random(42)  # 항상 같은 데이터가 나오게 고정한다

        groups = [EndpointGroup.objects.get_or_create(name=name)[0] for name, _ in GROUPS]
        software = []
        for name, vendor, _ in SOFTWARE:
            software.append(Software.objects.get_or_create(name=name, vendor=vendor)[0])
        versions = {name: versions for name, _, versions in SOFTWARE}

        number = 0
        for group, (_, count) in zip(groups, GROUPS):
            for _ in range(count):
                number += 1
                os_name, os_build = OS_CHOICES[(number - 1) % len(OS_CHOICES)]
                endpoint, _ = Endpoint.objects.update_or_create(
                    hostname=f'pc-{number:03d}',
                    defaults={'os_name': os_name, 'os_build': os_build, 'group': group},
                )
                for item in rng.sample(software, rng.randint(6, 12)):
                    InstalledSoftware.objects.update_or_create(
                        endpoint=endpoint,
                        software=item,
                        defaults={'version': rng.choice(versions[item.name])},
                    )

        # 시연용 정책 하나: 높음 이상 패치를 테스트 그룹에 먼저 배포하고, 1시간 뒤 일반 그룹에 배포한다
        policy, created = Policy.objects.get_or_create(
            name='높음 이상 단계 배포', defaults={'min_severity': 'high', 'is_active': True},
        )
        if created:
            by_name = {group.name: group for group in groups}
            PolicyStage.objects.create(policy=policy, order=1, group=by_name['테스트'],
                                       delay_minutes=0, rollback_error_rate=0.1)
            PolicyStage.objects.create(policy=policy, order=2, group=by_name['일반'],
                                       delay_minutes=60, rollback_error_rate=0.05)

        # 소프트웨어를 NVD 이름과 잇는 매핑도 함께 넣는다
        call_command('seed_cpe_mappings', stdout=self.stdout)

        self.stdout.write(self.style.SUCCESS(
            f'그룹 {EndpointGroup.objects.count()}개, 소프트웨어 {Software.objects.count()}종, '
            f'PC {Endpoint.objects.count()}대, 설치 기록 {InstalledSoftware.objects.count()}건'
        ))
