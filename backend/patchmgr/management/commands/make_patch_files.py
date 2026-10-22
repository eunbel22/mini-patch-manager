import hashlib
import random

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from patchmgr.models import Patch

CHUNK = 1024 * 1024


def package_name(patch):
    return f'patch-{patch.id}.bin'


def build_package(patch, size):
    """패치 하나의 시연용 파일 내용. 같은 패치와 크기면 항상 같은 내용이라 다시 만들어도 sha256이 같다."""
    rng = random.Random(f'patch-{patch.id}')
    remaining = size
    while remaining > 0:
        n = min(CHUNK, remaining)
        yield rng.randbytes(n)
        remaining -= n


class Command(BaseCommand):
    help = (
        '패치마다 시연용 파일(실제 패치가 아닌 무작위 바이트)을 만들고, 크기와 sha256을 DB에 적는다. '
        '에이전트는 이 파일을 Nginx(/patches/)에서 내려받아 sha256을 확인한다. 여러 번 실행해도 같은 결과가 된다.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--size-mb', type=float, default=2.0, help='파일 하나의 크기(MB). 기본 2')

    def handle(self, *args, **options):
        size = int(options['size_mb'] * 1024 * 1024)
        if size <= 0:
            raise CommandError('--size-mb는 0보다 커야 합니다.')
        directory = settings.PATCH_FILE_DIR
        directory.mkdir(parents=True, exist_ok=True)

        count = 0
        for patch in Patch.objects.order_by('id'):
            digest = hashlib.sha256()
            path = directory / package_name(patch)
            with open(path, 'wb') as handle:
                for chunk in build_package(patch, size):
                    handle.write(chunk)
                    digest.update(chunk)
            patch.package_size = size
            patch.package_sha256 = digest.hexdigest()
            patch.save(update_fields=['package_size', 'package_sha256'])
            count += 1

        self.stdout.write(self.style.SUCCESS(f'패치 파일 {count}개를 {directory}에 만들었습니다 (개당 {size / 1024 / 1024:.1f}MB).'))
