from celery import Celery
from src.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "socluma",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["src.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_always_eager=settings.SOAR_TASK_ALWAYS_EAGER or settings.USE_REDIS_MOCK,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT_SECONDS,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS,
    beat_schedule={
        "due-scheduled-searches": {
            "task": "run_due_scheduled_searches",
            "schedule": 60.0,
        },
        "due-threat-syncs": {
            "task": "run_due_threat_syncs",
            "schedule": 60.0,
        },
        "ioc-artifact-retention": {
            "task": "cleanup_ioc_commercial_jobs",
            "schedule": 3600.0,
        },
    },
)
