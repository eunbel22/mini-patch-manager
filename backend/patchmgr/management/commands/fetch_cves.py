from django.core.management.base import BaseCommand, CommandError

from patchmgr.nvd import NvdError, collect_recent


class Command(BaseCommand):
    help = 'NVD에서 최근에 바뀐 CVE를 가져와 저장한다. Celery Beat가 주기적으로 하는 일을 손으로 한 번 실행한다.'

    def add_arguments(self, parser):
        parser.add_argument('--hours', type=int, default=24, help='최근 몇 시간 안에 바뀐 CVE를 가져올지 (기본 24)')

    def handle(self, *args, **options):
        try:
            created, updated, skipped = collect_recent(hours=options['hours'])
        except NvdError as exc:
            raise CommandError(str(exc))
        self.stdout.write(self.style.SUCCESS(
            f'CVE 새로 {created}건, 갱신 {updated}건 (읽지 못해 건너뜀 {skipped}건)'
        ))
