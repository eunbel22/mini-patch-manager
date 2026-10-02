import os

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('config')
# 설정은 settings.py의 CELERY_ 로 시작하는 값을 읽는다
app.config_from_object('django.conf:settings', namespace='CELERY')
# 각 앱의 tasks.py를 자동으로 찾는다
app.autodiscover_tasks()
