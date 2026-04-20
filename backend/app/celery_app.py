import os

from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "samurai",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_max_tasks_per_child=50,
    task_time_limit=3600,
    task_soft_time_limit=3000,
    beat_schedule={
        "dispatch-due-schedules": {
            "task": "app.tasks.dispatch_due_schedules",
            "schedule": 30.0,  # seconds
        },
    },
)
