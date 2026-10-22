"""패치 파일 내려받기의 속도 제한(limit_rate)과 동시 연결 제한(limit_conn)이 실제로 걸리는지 잰다.

  1) 연결 하나로 순서대로 내려받아 초당 속도를 잰다 (--runs회, 중앙값).
  2) 한꺼번에 --parallel개를 내려받아 성공(200)과 거절(429)이 몇 건인지, 성공한 연결의 속도는 어땠는지 센다.

표준 라이브러리만 쓴다. 대상 서버는 이미 켜져 있고 패치 파일이 만들어져 있어야 한다(make_patch_files).
예: python loadtest/patch_download_check.py --base http://127.0.0.1:18080 --path /patches/patch-1.bin
"""
import argparse
import statistics
import threading
import time
from urllib import error, request

MB = 1024 * 1024


def fetch(url):
    """파일 하나를 끝까지 받는다. (HTTP 상태, 받은 바이트, 걸린 초)"""
    started = time.monotonic()
    total = 0
    try:
        with request.urlopen(url, timeout=120) as response:
            while chunk := response.read(64 * 1024):
                total += len(chunk)
            status = response.status
    except error.HTTPError as exc:
        status = exc.code
    return status, total, time.monotonic() - started


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', default='http://127.0.0.1:18080', help='서버 주소 (윈도우에서는 localhost 대신 127.0.0.1)')
    parser.add_argument('--path', default='/patches/patch-1.bin', help='내려받을 파일 경로')
    parser.add_argument('--runs', type=int, default=3, help='연결 하나로 받는 횟수')
    parser.add_argument('--parallel', type=int, default=5, help='동시에 받는 연결 수')
    args = parser.parse_args()
    url = args.base.rstrip('/') + args.path

    speeds = []
    for _ in range(args.runs):
        status, total, seconds = fetch(url)
        if status != 200:
            raise SystemExit(f'내려받기 실패: HTTP {status}. 서버가 켜져 있고 파일이 있는지 확인하세요.')
        speeds.append(total / MB / seconds)
    size_mb = total / MB
    print(f'연결 1개: 파일 {size_mb:.1f}MB, 속도 중앙값 {statistics.median(speeds):.2f}MB/초 (최소 {min(speeds):.2f}, 최대 {max(speeds):.2f}, {args.runs}회)')

    results = []
    lock = threading.Lock()
    start_line = threading.Barrier(args.parallel)

    def worker():
        start_line.wait()  # 모두 같은 순간에 시작한다
        row = fetch(url)
        with lock:
            results.append(row)

    threads = [threading.Thread(target=worker) for _ in range(args.parallel)]
    wall = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.monotonic() - wall

    ok = [row for row in results if row[0] == 200]
    refused = [row for row in results if row[0] == 429]
    other = [row for row in results if row[0] not in (200, 429)]
    per_connection = statistics.median(total / MB / seconds for _, total, seconds in ok) if ok else 0
    print(
        f'동시 {args.parallel}개: 성공(200) {len(ok)}건, 거절(429) {len(refused)}건, 그 밖 {len(other)}건 / '
        f'성공한 연결의 속도 중앙값 {per_connection:.2f}MB/초, 성공한 연결의 합계 {per_connection * len(ok):.2f}MB/초, 전체 {wall:.1f}초'
    )


if __name__ == '__main__':
    main()
