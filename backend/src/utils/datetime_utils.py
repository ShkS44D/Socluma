from datetime import datetime, timezone


def get_utc_now() -> datetime:
    """Get current time in UTC with timezone awareness."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime object is timezone-aware and in UTC."""
    if dt.tzinfo is None:
        # If naive, assume UTC
        return dt.replace(tzinfo=timezone.utc)
    # If timezone-aware, convert to UTC
    return dt.astimezone(timezone.utc)


def utc_isoformat(dt: datetime) -> str:
    """Serialize a datetime as ISO-8601 UTC with a Z suffix."""
    return ensure_utc(dt).isoformat().replace("+00:00", "Z")
