from celery import shared_task
from celery.decorators import task

from .models import UserProfile


@shared_task(max_retires=3, soft_time_limit=60)
def add(x, y):
    a = x + y
    u = UserProfile.objects.filter(id=2).update(is_deleted=True)
    return a


@shared_task(max_retires=3, soft_time_limit=60)
def test():
    u = UserProfile.objects.filter(id=2).update(is_deleted=True)
    return u
