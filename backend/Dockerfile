# 백엔드 이미지: Rocky Linux 9 + Python 3.12 (Django는 3.12 이상이 필요하고, Rocky 9 기본 저장소에 python3.12가 있다)
# 같은 이미지를 gunicorn(API), Celery 워커, Celery Beat, 초기화 작업(init)이 명령만 바꿔서 쓴다.
FROM rockylinux:9

RUN dnf -y install python3.12 python3.12-pip \
    && dnf clean all \
    && rm -rf /var/cache/dnf

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# root가 아닌 일반 사용자로 서버를 실행한다
RUN useradd --system --create-home --uid 10001 --shell /sbin/nologin app
WORKDIR /app

# 요구 목록을 먼저 설치한다. 코드만 바뀌면 이 층은 다시 만들지 않는다(캐시).
COPY requirements.txt .
RUN python3.12 -m pip install -r requirements.txt

COPY . .
# 관리자 화면의 정적 파일을 모아 둔다 (whitenoise가 서비스한다). 이 단계는 DB를 쓰지 않는다.
RUN python3.12 manage.py collectstatic --noinput \
    && chown -R app:app /app
USER app

EXPOSE 8000
CMD ["sh", "-c", "exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} --access-logfile -"]
