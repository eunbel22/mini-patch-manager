"""에이전트(PC) 보고 부하 테스트.

가상 에이전트(load-0001, load-0002, ...)가 POST /api/agents/report/로 보고한다.
이 PC들은 `manage.py seed_load`로 먼저 만들어 둬야 한다(등록되지 않은 PC는 404를 받는다).

LOAD_MODE
  burst  (기본) 에이전트마다 한 번씩만 보고하고 끝낸다. "1,000대가 한꺼번에 보고"를 흉내 낸다. 모두 끝나면 자동으로 종료한다.
  steady 에이전트마다 5~10초 간격으로 계속 보고한다. LOAD_SECONDS 동안 실행한다.
"""
import itertools
import os

import gevent
from locust import HttpUser, between, constant, events, task
from locust.exception import StopUser

MODE = os.environ.get('LOAD_MODE', 'burst')

# 실제 PC의 보고와 비슷한 크기의 내용: 설치된 소프트웨어 10개(seed_demo의 소프트웨어 이름과 같다), KB는 짝수 번호 PC만 설치
CATALOG = [
    ('Google Chrome', 'Google', ['118.0', '124.0', '130.0']),
    ('Mozilla Firefox', 'Mozilla', ['115.0', '121.0', '128.0']),
    ('Microsoft Edge', 'Microsoft', ['118.0', '124.0', '130.0']),
    ('Adobe Acrobat Reader', 'Adobe', ['23.1', '24.1', '24.4']),
    ('7-Zip', 'Igor Pavlov', ['22.01', '23.01', '24.05']),
    ('Notepad++', 'Notepad++ Team', ['8.4', '8.5', '8.6']),
    ('VLC media player', 'VideoLAN', ['3.0.16', '3.0.18', '3.0.20']),
    ('Zoom', 'Zoom', ['5.14', '5.16', '5.17']),
    ('Apache Log4j', 'Apache', ['2.14.0', '2.17.1', '2.20.0']),
    ('Git', 'Git', ['2.39', '2.42', '2.45']),
]
OS_CHOICES = [
    ('Windows 10 22H2', '10.0.19045.4000', 'KB5044273'),
    ('Windows 11 23H2', '10.0.22631.4000', 'KB5044285'),
    ('Windows Server 2019', '10.0.17763.6000', 'KB5044277'),
    ('Windows Server 2022', '10.0.20348.2600', 'KB5044281'),
]

_counter = itertools.count(1)


def build_payload(number):
    """seed_load가 만든 load-NNNN 번째 PC의 보고 내용 (같은 번호는 항상 같은 내용)"""
    os_name, os_build, kb = OS_CHOICES[(number - 1) % len(OS_CHOICES)]
    return {
        'hostname': f'load-{number:04d}',
        'os_name': os_name,
        'os_build': os_build,
        'installed_software': [
            {'name': name, 'vendor': vendor, 'version': versions[(number + index) % len(versions)]}
            for index, (name, vendor, versions) in enumerate(CATALOG)
        ],
        'installed_kbs': [kb] if number % 2 == 0 else [],
        'errors': [],
    }


class Agent(HttpUser):
    wait_time = between(5, 10) if MODE == 'steady' else constant(0)

    def on_start(self):
        self.payload = build_payload(next(_counter))

    @task
    def report(self):
        with self.client.post(
            '/api/agents/report/', json=self.payload, name='POST /api/agents/report/', catch_response=True,
        ) as response:
            if response.status_code != 202:
                response.failure(f'HTTP {response.status_code}')
        if MODE == 'burst':
            raise StopUser()


_window = {'first_start': None, 'last_end': None}


@events.request.add_listener
def track_window(response_time=0, start_time=None, **kwargs):
    """첫 요청이 시작된 시각과 마지막 응답이 끝난 시각(이 PC의 시계). API가 보고를 다 받는 데 걸린 시간을 구한다."""
    import time

    end = (start_time + response_time / 1000) if start_time else time.time()
    begin = start_time if start_time else end - response_time / 1000
    if _window['first_start'] is None or begin < _window['first_start']:
        _window['first_start'] = begin
    if _window['last_end'] is None or end > _window['last_end']:
        _window['last_end'] = end


@events.quitting.add_listener
def write_result(environment, **kwargs):
    """종료 직전에 통계를 파일로 남긴다. (burst는 1초도 안 돼 끝나서 Locust의 CSV 파일은 비어 있기 때문에 CSV를 쓰지 않는다.)"""
    path = os.environ.get('LOAD_WINDOW_FILE')
    entry = environment.stats.get('POST /api/agents/report/', 'POST')
    if not path or entry.num_requests == 0:
        return
    import json

    result = {
        **_window,
        'requests': entry.num_requests,
        'failures': entry.num_failures,
        'avg_ms': entry.avg_response_time,
        'p50_ms': entry.get_response_time_percentile(0.50),
        'p95_ms': entry.get_response_time_percentile(0.95),
        'p99_ms': entry.get_response_time_percentile(0.99),
        'max_ms': entry.max_response_time,
    }
    with open(path, 'w', encoding='utf-8') as file:
        json.dump(result, file)


@events.test_start.add_listener
def quit_when_all_agents_are_done(environment, **kwargs):
    """burst 모드는 에이전트가 모두 보고를 마치면 Locust를 바로 끝낸다(정해진 시간을 기다리지 않는다)."""
    if MODE != 'burst':
        return

    def watch():
        while True:
            gevent.sleep(0.25)
            runner = environment.runner
            if runner is not None and runner.state == 'running' and runner.user_count == 0:
                runner.quit()
                return

    gevent.spawn(watch)
