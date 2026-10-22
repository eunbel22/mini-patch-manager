"""에이전트 1,000대 보고 부하 테스트 실행기.

docker compose(별도 프로젝트 이름 mpmbench, 화면 포트 18080)로 전체를 켜고, Celery 워커 수를 바꿔 가며
"1,000대가 한꺼번에 보고했을 때" 다음 두 가지를 잰다.
  1. API가 보고를 받아 202를 돌려주기까지의 응답 시간과 실패 수 (Locust)
  2. 큐에 쌓인 1,000건을 워커가 모두 처리하는 데 걸린 시간과 초당 처리 건수 (워커 로그의 시각)

사용:
  python benchmark.py up                       전체를 켜고 부하 테스트용 PC 1,000대를 만든다
  python benchmark.py bench --workers 1 2 4 8  워커 수별로 측정 (--repeat 3, --sync 로 "Celery 없이"도 비교)
  python benchmark.py down                     끄고 데이터까지 지운다

이 스크립트는 Locust가 설치된 파이썬으로 실행한다: loadtest/.venv/Scripts/python benchmark.py ...
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = 'mpmbench'
BASE = 'http://127.0.0.1:18080'
WORKER = f'{PROJECT}-worker-1'
COMPOSE = [
    'docker', 'compose', '-p', PROJECT,
    '-f', str(ROOT / 'docker-compose.yml'), '-f', str(HERE / 'compose.bench.yml'),
]
TASK = 'process_agent_report'


def run(command, env=None, check=True, cwd=ROOT):
    merged = {**os.environ, **(env or {}), 'PYTHONIOENCODING': 'utf-8'}
    result = subprocess.run(command, cwd=cwd, env=merged, capture_output=True, text=True, encoding='utf-8')
    if check and result.returncode != 0:
        raise SystemExit(f'명령 실패: {" ".join(command)}\n{result.stdout}\n{result.stderr}')
    return result


def compose(*args, env=None, check=True):
    return run([*COMPOSE, *args], env=env, check=check)


def wait_until(check, seconds, what):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if check():
            return
        time.sleep(1)
    raise SystemExit(f'{seconds}초 안에 끝나지 않았습니다: {what}')


def backend_ready():
    try:
        with urllib.request.urlopen(f'{BASE}/api/groups/', timeout=5):
            return True
    except (urllib.error.URLError, OSError):
        return False


def worker_ready():
    result = run(['docker', 'logs', WORKER], check=False)
    return 'ready.' in result.stdout + result.stderr


def docker_now():
    """Docker(WSL) 쪽 시계의 지금 시각. 워커 로그의 시각과 같은 시계라서 --since에 쓸 수 있다."""
    out = run(['docker', 'exec', WORKER, 'date', '-u', '+%Y-%m-%dT%H:%M:%S.%NZ']).stdout.strip()
    return out


def parse_docker_time(text):
    # 2026-10-07T05:20:22.123456789Z -> 마이크로초까지만 쓴다
    return datetime.fromisoformat(text[:26] + '+00:00')


def worker_events(since):
    """since 이후 워커가 보고 작업을 받은/끝낸 시각들"""
    result = run(['docker', 'logs', '-t', '--since', since, WORKER], check=False)
    received, succeeded = [], []
    for line in (result.stdout + result.stderr).splitlines():
        if TASK not in line:
            continue
        stamp = parse_docker_time(line.split(' ', 1)[0])
        if line.rstrip().endswith('received'):
            received.append(stamp)
        elif ' succeeded in ' in line:
            succeeded.append(stamp)
    return received, succeeded


def run_locust(users, mode='burst', seconds=60):
    """Locust를 실행하고 보고 API의 통계와 요청이 오간 시간(이 PC의 시계)을 돌려준다."""
    with tempfile.TemporaryDirectory() as folder:
        result_file = Path(folder) / 'result.json'
        command = [
            sys.executable, '-m', 'locust', '-f', str(HERE / 'locustfile.py'), '--headless',
            '-u', str(users), '-r', str(users), '--host', BASE, '--only-summary', '--stop-timeout', '30',
        ]
        command += ['-t', f'{seconds}s'] if mode == 'steady' else ['-t', '300s']
        env = {'LOAD_MODE': mode, 'LOAD_WINDOW_FILE': str(result_file)}
        result = run(command, env=env, check=False, cwd=HERE)
        if not result_file.exists():
            raise SystemExit(f'Locust 결과가 없습니다.\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}')
        data = json.loads(result_file.read_text(encoding='utf-8'))
    api_seconds = data['last_end'] - data['first_start']
    return {
        'requests': data['requests'],
        'failures': data['failures'],
        'api_seconds': round(api_seconds, 2),
        'api_per_sec': round(data['requests'] / api_seconds, 1) if api_seconds else None,
        'p50_ms': int(data['p50_ms']),
        'p95_ms': int(data['p95_ms']),
        'p99_ms': int(data['p99_ms']),
        'max_ms': int(data['max_ms']),
        'avg_ms': int(data['avg_ms']),
    }


def one_run(users, mode, sync):
    """보고 users건을 한꺼번에 보내고, 워커가 모두 처리할 때까지 기다려서 측정값을 돌려준다."""
    since = docker_now()
    api = run_locust(users, mode)
    result = {'users': users, **api}
    if sync:
        # Celery 없이: 응답이 처리가 끝난 뒤에 나간다. 처리가 끝난 시점 = API가 마지막 응답을 준 시점
        result['processed'] = api['requests'] - api['failures']
        result['process_seconds'] = api['api_seconds']
        result['process_per_sec'] = api['api_per_sec']
        return result

    expected = api['requests'] - api['failures']

    def done():
        return len(worker_events(since)[1]) >= expected

    wait_until(done, 600, f'워커가 보고 {expected}건을 모두 처리')
    received, succeeded = worker_events(since)
    seconds = (max(succeeded) - min(received)).total_seconds()
    result.update({
        'processed': len(succeeded),
        'process_seconds': round(seconds, 2),
        'process_per_sec': round(len(succeeded) / seconds, 1) if seconds else None,
    })
    return result


def summarize(runs):
    """같은 설정의 여러 번 측정을 중앙값으로 줄인다."""
    keys = ['p50_ms', 'p95_ms', 'p99_ms', 'max_ms', 'api_seconds', 'process_seconds', 'process_per_sec']
    summary = {key: statistics.median(r[key] for r in runs if r.get(key) is not None) for key in keys}
    summary['failures'] = sum(r['failures'] for r in runs)
    summary['requests'] = sum(r['requests'] for r in runs)
    return summary


def cmd_up(args):
    compose('up', '-d', '--build', env={'GUNICORN_WORKERS': str(args.gunicorn)})
    wait_until(backend_ready, 180, '백엔드가 뜨기')
    out = compose('exec', '-T', 'backend', 'python3.12', 'manage.py', 'seed_load', '--count', str(args.users)).stdout
    print(out.strip().splitlines()[-1])
    print(f'준비 끝: {BASE}')


def cmd_down(args):
    compose('down', '-v')
    print('끄고 데이터를 지웠습니다.')


def cmd_bench(args):
    configs = []
    if args.sync:
        configs.append({'label': 'Celery 없이(요청 안에서 직접 처리)', 'sync': True, 'celery': None})
    configs += [{'label': f'Celery 워커 {n}개', 'sync': False, 'celery': n} for n in args.workers]

    all_results = []
    for config in configs:
        env = {
            'GUNICORN_WORKERS': str(args.gunicorn),
            'AGENT_REPORT_SYNC': '1' if config['sync'] else '0',
            'CELERY_CONCURRENCY': str(config['celery'] or 4),
        }
        compose('up', '-d', '--force-recreate', 'backend', 'worker', env=env)
        wait_until(backend_ready, 180, '백엔드가 다시 뜨기')
        wait_until(worker_ready, 120, '워커가 뜨기')
        time.sleep(2)
        if not config['sync']:
            one_run(args.warmup, 'burst', False)  # 연결을 데우는 준비 운동(기록하지 않는다)
        else:
            run_locust(args.warmup, 'burst')

        runs = []
        for index in range(args.repeat):
            outcome = one_run(args.users, 'burst', config['sync'])
            runs.append(outcome)
            print(f"  {config['label']} #{index + 1}: 응답 p95 {outcome['p95_ms']}ms, 실패 {outcome['failures']}, "
                  f"전부 처리까지 {outcome['process_seconds']}초 ({outcome['process_per_sec']}건/초)", flush=True)
        all_results.append({**config, 'runs': runs, 'summary': summarize(runs)})

    environment = {
        'measured_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'users': args.users,
        'repeat': args.repeat,
        'gunicorn_workers': args.gunicorn,
        'cpu': run(['docker', 'info', '--format', '{{.NCPU}}']).stdout.strip(),
        'memory_gb': round(int(run(['docker', 'info', '--format', '{{.MemTotal}}']).stdout.strip()) / 1024 ** 3, 1),
    }
    out = HERE / 'results' / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({'environment': environment, 'configs': all_results}, ensure_ascii=False, indent=2),
                   encoding='utf-8')
    print(f'\n결과 파일: {out}\n')
    print(markdown_table(environment, all_results))


def markdown_table(environment, configs):
    lines = [
        f"측정 {environment['measured_at']}, 보고 {environment['users']}건을 한꺼번에, 설정마다 {environment['repeat']}회 "
        f"(표의 값은 중앙값), gunicorn 워커 {environment['gunicorn_workers']}개, CPU {environment['cpu']}개 · 메모리 {environment['memory_gb']}GB",
        '',
        '| 설정 | 응답 p50 | 응답 p95 | 응답 p99 | 응답 최대 | 실패 | 전부 처리까지 | 초당 처리 |',
        '| --- | --- | --- | --- | --- | --- | --- | --- |',
    ]
    for config in configs:
        s = config['summary']
        lines.append(
            f"| {config['label']} | {s['p50_ms']}ms | {s['p95_ms']}ms | {s['p99_ms']}ms | {s['max_ms']}ms | {s['failures']} | "
            f"{s['process_seconds']}초 | {s['process_per_sec']}건 |"
        )
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    up = sub.add_parser('up')
    up.add_argument('--users', type=int, default=1000)
    up.add_argument('--gunicorn', type=int, default=3, help='gunicorn 워커 수')
    sub.add_parser('down')
    bench = sub.add_parser('bench')
    bench.add_argument('--workers', type=int, nargs='*', default=[1, 2, 4, 8], help='비교할 Celery 워커(동시 처리) 수')
    bench.add_argument('--sync', action='store_true', help='"Celery 없이" 요청 안에서 직접 처리하는 경우도 비교')
    bench.add_argument('--users', type=int, default=1000)
    bench.add_argument('--repeat', type=int, default=3)
    bench.add_argument('--warmup', type=int, default=200)
    bench.add_argument('--gunicorn', type=int, default=3)
    args = parser.parse_args()
    {'up': cmd_up, 'down': cmd_down, 'bench': cmd_bench}[args.command](args)


if __name__ == '__main__':
    main()
