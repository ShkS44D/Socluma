import logging
import sys
from contextvars import ContextVar
from pythonjsonlogger import jsonlogger


request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_ctx: ContextVar[str | None] = ContextVar("tenant_id", default=None)
user_id_ctx: ContextVar[str | None] = ContextVar("user_id", default=None)
collector_id_ctx: ContextVar[str | None] = ContextVar("collector_id", default=None)
endpoint_ctx: ContextVar[str | None] = ContextVar("endpoint", default=None)
execution_time_ms_ctx: ContextVar[float | None] = ContextVar("execution_time_ms", default=None)


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        record.tenant_id = tenant_id_ctx.get()
        record.user_id = user_id_ctx.get()
        record.collector_id = collector_id_ctx.get()
        record.endpoint = endpoint_ctx.get()
        record.execution_time_ms = execution_time_ms_ctx.get()
        record.service = "backend"
        return True


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        (
            "%(asctime)s %(levelname)s %(name)s %(service)s %(request_id)s "
            "%(tenant_id)s %(user_id)s %(collector_id)s %(endpoint)s "
            "%(execution_time_ms)s %(message)s"
        ),
        rename_fields={"asctime": "timestamp", "levelname": "severity"},
    )
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())
    logger.addHandler(handler)
    
    return logger


logger = setup_logging()
