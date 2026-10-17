from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Request, status


DEFAULT_DOCS_URL = "https://docs.socluma.local/api/errors"

ERROR_CODE_BY_STATUS = {
    status.HTTP_400_BAD_REQUEST: "bad_request",
    status.HTTP_401_UNAUTHORIZED: "authentication_required",
    status.HTTP_403_FORBIDDEN: "forbidden",
    status.HTTP_404_NOT_FOUND: "not_found",
    status.HTTP_409_CONFLICT: "conflict",
    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE: "request_body_too_large",
    status.HTTP_422_UNPROCESSABLE_ENTITY: "validation_error",
    status.HTTP_423_LOCKED: "account_locked",
    status.HTTP_429_TOO_MANY_REQUESTS: "rate_limit_exceeded",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "internal_error",
}


def build_error_response(
    request: Request,
    *,
    status_code: int,
    message: str,
    details: Any = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request_id": getattr(request.state, "request_id", None),
        "status": status_code,
        "error_code": error_code or ERROR_CODE_BY_STATUS.get(status_code, "api_error"),
        "message": message,
        "detail": message,
        "details": details,
        "documentation_url": f"{DEFAULT_DOCS_URL}#{error_code or ERROR_CODE_BY_STATUS.get(status_code, 'api_error')}",
    }
