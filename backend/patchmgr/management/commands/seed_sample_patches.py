from datetime import datetime, timezone

from django.core.management.base import BaseCommand
from django.db import transaction

from patchmgr.models import CVE, Patch

# 2026-10-02에 MS 보안 업데이트 안내(api.msrc.microsoft.com/sug/v2.0)에서 직접 확인한 실제 데이터다.
# CVE-2024-43572: Microsoft Management Console Remote Code Execution Vulnerability, 2024-10-08 공개, 기본 점수 7.8
CVE_ID = 'CVE-2024-43572'
CVE_TITLE = 'Microsoft Management Console Remote Code Execution Vulnerability'

# (대상 OS 이름은 seed_demo의 PC와 같게 맞춘다, KB 번호, 고쳐진 빌드)
PATCHES = [
    ('Windows 10 22H2', 'KB5044273', '10.0.19045.5011'),
    ('Windows 11 23H2', 'KB5044285', '10.0.22631.4317'),
    ('Windows Server 2019', 'KB5044277', '10.0.17763.6414'),
    ('Windows Server 2022', 'KB5044281', '10.0.20348.2762'),
]


class Command(BaseCommand):
    help = '실제 CVE 1개(CVE-2024-43572)와 해결하는 KB 4개를 넣는다. 여러 번 실행해도 같은 결과가 된다.'

    @transaction.atomic
    def handle(self, *args, **options):
        cve, _ = CVE.objects.update_or_create(
            cve_id=CVE_ID,
            defaults={
                'description': CVE_TITLE,
                'cvss_score': '7.8',
                'severity': 'high',
                'published_at': datetime(2024, 10, 8, tzinfo=timezone.utc),
            },
        )
        for target_os, kb_number, fixed_build in PATCHES:
            patch, _ = Patch.objects.update_or_create(
                kb_number=kb_number,
                target_os=target_os,
                defaults={
                    'fixed_build': fixed_build,
                    'download_url': f'https://catalog.update.microsoft.com/v7/site/Search.aspx?q={kb_number}',
                },
            )
            patch.cves.add(cve)

        self.stdout.write(self.style.SUCCESS(
            f'CVE {CVE.objects.count()}개, 패치(KB) {Patch.objects.count()}개'
        ))
