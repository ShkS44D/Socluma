import logging
import os
import threading
import json
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

_LOG_LOCK = threading.RLock()
_SHARED_FILE_HANDLER: logging.Handler | None = None
_SHARED_CONSOLE_HANDLER: logging.Handler | None = None
request_id_ctx: ContextVar[str | None] = ContextVar("collector_request_id", default=None)
collector_id_ctx: ContextVar[str | None] = ContextVar("collector_id", default=os.getenv("COLLECTOR_ID"))
backend_url_ctx: ContextVar[str | None] = ContextVar("backend_url", default=os.getenv("BACKEND_URL", "http://localhost:8001"))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "severity": record.levelname,
            "service": "collector",
            "logger": record.name,
            "request_id": getattr(record, "request_id", None) or request_id_ctx.get(),
            "collector_id": getattr(record, "collector_id", None) or collector_id_ctx.get(),
            "backend_url": getattr(record, "backend_url", None) or backend_url_ctx.get(),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def set_request_id(request_id: str | None):
    return request_id_ctx.set(request_id)


def reset_request_id(token) -> None:
    request_id_ctx.reset(token)


def set_collector_context(collector_id: str | None, backend_url: str | None) -> None:
    collector_id_ctx.set(collector_id)
    backend_url_ctx.set(backend_url)


class WindowsSafeRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        try:
            super().doRollover()
        except PermissionError:
            # On Windows another logger/thread may briefly hold the file. Keep
            # file logging alive and skip this rollover attempt without a noisy traceback.
            if self.stream:
                self.stream.close()
                self.stream = None
            self.stream = self._open()


def _get_handlers(formatter: logging.Formatter) -> tuple[logging.Handler, logging.Handler]:
    global _SHARED_CONSOLE_HANDLER, _SHARED_FILE_HANDLER

    with _LOG_LOCK:
        if _SHARED_CONSOLE_HANDLER is None:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            _SHARED_CONSOLE_HANDLER = console_handler

        if _SHARED_FILE_HANDLER is None:
            log_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "collector.log")
            file_handler = WindowsSafeRotatingFileHandler(
                log_file,
                maxBytes=1024 * 1024,
                backupCount=5,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            _SHARED_FILE_HANDLER = file_handler

        return _SHARED_CONSOLE_HANDLER, _SHARED_FILE_HANDLER


def setup_logger(name: str = "socluma_collector") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    
    # Create formatter
    formatter = JsonFormatter()
    
    console_handler, file_handler = _get_handlers(formatter)

    # Add handlers
    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
    
    return logger
