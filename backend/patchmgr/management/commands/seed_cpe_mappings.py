from django.core.management.base import BaseCommand
from django.db import transaction

from patchmgr.models import Software, SoftwareCpe

# 소프트웨어 이름 -> NVD의 (제조사, 제품) 목록.
# 2026-10-02에 NVD CPE API(services.nvd.nist.gov/rest/json/cpes/2.0)에서 직접 조회해 존재를 확인한 이름이다.
# 하나의 소프트웨어에 이름이 여러 개인 경우가 있다 (Adobe 2개, Notepad++ 제조사 3개, 한컴은 버전마다 제품이 따로).
MAPPINGS = {
    'Google Chrome': [('google', 'chrome')],
    'Mozilla Firefox': [('mozilla', 'firefox')],
    'Microsoft Edge': [('microsoft', 'edge_chromium')],  # 옛 Edge(microsoft:edge)는 다른 제품이라 제외
    'Adobe Acrobat Reader': [('adobe', 'acrobat_reader'), ('adobe', 'acrobat_reader_dc')],
    '한컴오피스': [
        ('hancom', 'hancom_office_2010'), ('hancom', 'hancom_office_2010_se'), ('hancom', 'hancom_office_2014'),
        ('hancom', 'hancom_office_2018'), ('hancom', 'hancom_office_2020'), ('hancom', 'hancom_office_neo'),
    ],
    '7-Zip': [('7-zip', '7-zip')],
    'Notepad++': [('notepad-plus-plus', 'notepad++'), ('don_ho', 'notepad++'), ('notepad_plus_plus', 'notepad++')],
    'VLC media player': [('videolan', 'vlc_media_player')],
    'Zoom': [('zoom', 'zoom'), ('zoom', 'meetings'), ('zoom', 'workplace_desktop')],  # 클라이언트에 해당하는 것을 판단해 묶음
    'Microsoft Teams': [('microsoft', 'teams')],
    'Oracle Java Runtime': [('oracle', 'jre')],
    'Apache Log4j': [('apache', 'log4j')],
    'Python': [('python', 'python')],
    'Git': [('git-scm', 'git')],
    'Visual Studio Code': [('microsoft', 'visual_studio_code')],
    'WinRAR': [('rarlab', 'winrar')],
    'Node.js': [('nodejs', 'node.js')],
    'PuTTY': [('putty', 'putty')],
}

# 매핑하지 못한 소프트웨어와 까닭
UNMAPPED = {
    'Slack': 'NVD CPE 사전에서 Slack 데스크톱 제품을 찾지 못함',
    'AhnLab V3': 'NVD에 ahnlab:v3_internet_security, v3_lite가 1건씩 있으나 우리 V3 9.x와 같은 제품인지 확인하지 못함',
}


class Command(BaseCommand):
    help = '소프트웨어와 NVD 제조사:제품 이름(CPE)의 매핑을 넣는다. 여러 번 실행해도 같은 결과가 된다.'

    @transaction.atomic
    def handle(self, *args, **options):
        missing = []
        for name, pairs in MAPPINGS.items():
            software = Software.objects.filter(name=name).first()
            if software is None:
                missing.append(name)
                continue
            for vendor, product in pairs:
                SoftwareCpe.objects.get_or_create(software=software, vendor=vendor, product=product)

        self.stdout.write(self.style.SUCCESS(
            f'매핑 {SoftwareCpe.objects.count()}줄 (소프트웨어 {SoftwareCpe.objects.values("software").distinct().count()}종)'
        ))
        if missing:
            self.stdout.write(f'DB에 없어 건너뜀: {", ".join(missing)} (seed_demo를 먼저 실행하세요)')
        for name, reason in UNMAPPED.items():
            self.stdout.write(f'매핑 없음: {name} — {reason}')
