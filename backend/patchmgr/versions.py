"""소프트웨어 버전을 크기로 비교하고, 설치된 버전이 NVD의 영향 범위에 들어가는지 판단한다."""
import operator
import re

from packaging.version import InvalidVersion, Version

# Java식 버전(8u421)을 8.0.421로 바꿔서 읽는다
_JAVA_STYLE = re.compile(r'^(\d+)u(\d+)$', re.IGNORECASE)


def parse_version(text):
    """버전 문자열을 비교할 수 있는 값으로 바꾼다. 읽을 수 없으면 None을 돌려준다."""
    if text is None:
        return None
    cleaned = re.sub(r'^[vV](?=\d)', '', str(text).strip())
    if not cleaned:
        return None
    java = _JAVA_STYLE.match(cleaned)
    if java:
        cleaned = f'{java.group(1)}.0.{java.group(2)}'
    try:
        return Version(cleaned)
    except InvalidVersion:
        return None


def is_affected(installed_text, row):
    """설치된 버전이 AffectedSoftware 한 줄의 범위에 들어가는지 판단한다.

    True: 해당됨, False: 해당되지 않음, None: 판단 불가(버전을 읽지 못해서).
    범위 칸이 모두 비어 있으면 모든 버전이 해당된다. 읽을 수 있는 조건 중 하나라도 어긋나면
    나머지를 읽지 못해도 해당되지 않는 것으로 본다.
    """
    conditions = [
        (row.version_start_including, operator.ge),
        (row.version_start_excluding, operator.gt),
        (row.version_end_including, operator.le),
        (row.version_end_excluding, operator.lt),
        (row.version_exact, operator.eq),
    ]
    conditions = [(text, compare) for text, compare in conditions if text]
    if not conditions:
        return True

    installed = parse_version(installed_text)
    if installed is None:
        return None

    unreadable = False
    for text, compare in conditions:
        limit = parse_version(text)
        if limit is None:
            unreadable = True
        elif not compare(installed, limit):
            return False
    return None if unreadable else True
