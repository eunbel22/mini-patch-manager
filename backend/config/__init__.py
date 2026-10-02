# Django가 시작될 때 Celery 앱도 같이 불러온다 (@shared_task가 이 앱을 쓴다)
from .celery import app as celery_app

__all__ = ('celery_app',)
