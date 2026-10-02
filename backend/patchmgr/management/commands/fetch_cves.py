from django.core.management.base import BaseCommand, CommandError

from patchmgr.nvd import NvdError, collect_ids, collect_recent


class Command(BaseCommand):
    help = (
        'NVD에서 CVE를 가져와 저장한다. 기본은 최근에 바뀐 CVE이고(Celery Beat가 주기적으로 하는 일을 손으로 한 번 실행), '
        '--cve-id로 번호를 지정할 수도 있다.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--hours', type=int, default=24, help='최근 몇 시간 안에 바뀐 CVE를 가져올지 (기본 24)')
        parser.add_argument('--cve-id', nargs='+', help='가져올 CVE 번호 (여러 개 가능). 지정하면 --hours는 무시한다')

    def handle(self, *args, **options):
        try:
            if options['cve_id']:
                result = collect_ids(options['cve_id'])
            else:
                result = collect_recent(hours=options['hours'])
        except NvdError as exc:
            raise CommandError(str(exc))
        self.stdout.write(self.style.SUCCESS(
            f"CVE 새로 {result['created']}건, 갱신 {result['updated']}건, 읽지 못해 건너뜀 {result['skipped']}건, "
            f"우리 소프트웨어와 이어진 영향 항목 {result['affected']}줄"
        ))
