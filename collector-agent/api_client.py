import requests
import json
import time
import uuid
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.logger import reset_request_id, set_collector_context, set_request_id, setup_logger
from config import Config

logger = setup_logger("api_client")

# Backend EventType enum values (must match backend/src/models/sqlalchemy.py)
class BackendEventType:
    LOGIN = "login"
    LOGOUT = "logout"
    FILE = "file"
    NETWORK = "network"
    PROCESS = "process"
    ALERT = "alert"

# Backend Severity enum values
class BackendSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TriageOpsAPIClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = self._build_session()
        self.base_url = config.BACKEND_URL.rstrip("/")
        self.timeout = (5, 15)
        self.max_attempts = 3
        set_collector_context(config.COLLECTOR_ID, self.base_url)

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=1,
            backoff_factor=0.5,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["POST", "GET"]),
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "Authorization": f"Bearer {self.config.COLLECTOR_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "triageops-collector/1.0",
            "Connection": "close",
        })
        return session

    def _reset_session(self) -> None:
        self.session.close()
        self.session = self._build_session()

    def close(self) -> None:
        self.session.close()

    def _post(self, url: str, json_payload: Optional[Dict[str, Any]] = None) -> requests.Response:
        last_error: Optional[requests.exceptions.RequestException] = None
        request_id = str(uuid.uuid4())
        request_token = set_request_id(request_id)
        try:
            for attempt in range(1, self.max_attempts + 1):
                try:
                    headers = dict(self.session.headers)
                    headers["X-Request-ID"] = request_id
                    response = self.session.post(
                        url,
                        json=json_payload,
                        timeout=self.timeout,
                        headers=headers,
                    )
                    return response
                except requests.exceptions.RequestException as e:
                    last_error = e
                    if attempt == self.max_attempts:
                        break
                    logger.warning(
                        "POST request failed on attempt %s/%s; retrying: %s",
                        attempt,
                        self.max_attempts,
                        e,
                    )
                    self._reset_session()
                    time.sleep(0.5 * attempt)
            assert last_error is not None
            raise last_error
        finally:
            reset_request_id(request_token)
    
    def send_heartbeat(self, diagnostics: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/collectors/{self.config.COLLECTOR_ID}/heartbeat"
        try:
            response = self._post(url, diagnostics or {})
            response.raise_for_status()
            logger.info("Heartbeat sent successfully")
            return response.json()
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "unknown"
            response_text = e.response.text if e.response is not None else ""
            if status_code == 401:
                logger.error("Collector authentication failed; rotate or re-enroll this collector and replace COLLECTOR_TOKEN")
            elif status_code == 403:
                logger.error("Collector token is valid but is not authorized for this collector ID")
            else:
                logger.error("Heartbeat failed with HTTP %s: %s", status_code, response_text)
            return None

    def send_batch(self, events: list[Dict[str, Any]], batch_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/events/ingest/batch"
        payload = {"batch_id": batch_id or str(uuid.uuid4()), "events": events}
        try:
            timestamp = str(int(time.time()))
            nonce = str(uuid.uuid4())
            # Sign the same canonical representation produced by the backend's
            # validated request model. Pydantic serializes UTC as ``Z`` while
            # Windows events commonly arrive with a ``+00:00`` suffix.
            canonical_payload = self._canonical_batch_payload(payload)
            body_hash = hashlib.sha256(
                json.dumps(
                    canonical_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode()
            ).hexdigest()
            material = f"{timestamp}.{nonce}.{payload['batch_id']}.{body_hash}".encode()
            signature = hmac.new(self.config.COLLECTOR_TOKEN.encode(), material, hashlib.sha256).hexdigest()
            original = dict(self.session.headers)
            self.session.headers.update({
                "X-Ingestion-Timestamp": timestamp,
                "X-Ingestion-Nonce": nonce,
                "X-Ingestion-Signature": signature,
            })
            try:
                response = self._post(url, payload)
            finally:
                self.session.headers.clear()
                self.session.headers.update(original)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            error_code = ""
            if exc.response is not None:
                try:
                    detail = exc.response.json().get("detail", {})
                    error_code = detail.get("error_code", "") if isinstance(detail, dict) else ""
                except (ValueError, AttributeError):
                    error_code = ""
            if status_code == 401:
                if error_code in {
                    "INVALID_SIGNATURE",
                    "INCOMPLETE_SIGNATURE",
                    "INVALID_SIGNATURE_TIME",
                    "SIGNATURE_EXPIRED",
                }:
                    logger.error("Batch signature was rejected (%s); verify collector/backend clock and signing versions", error_code)
                else:
                    logger.error("Batch authentication failed; rotate or re-enroll this collector and replace COLLECTOR_TOKEN")
            elif status_code == 403:
                logger.error("Collector token is not authorized for configured COLLECTOR_ID")
            else:
                logger.error("Batch failed with HTTP %s", status_code)
            return None
        except requests.exceptions.RequestException as exc:
            logger.error("Batch request failed: %s", exc)
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Heartbeat request failed: %s", e)
            return None

    @staticmethod
    def _canonical_batch_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        canonical = json.loads(json.dumps(payload, default=str))
        for event in canonical.get("events", []):
            timestamp = event.get("timestamp")
            if isinstance(timestamp, str) and timestamp.endswith("+00:00"):
                event["timestamp"] = f"{timestamp[:-6]}Z"
        return canonical
    
    def send_event(self, source: str, event_type: str, raw_event: Dict[str, Any], 
                   normalized_event: Optional[Dict[str, Any]] = None, 
                   severity: Optional[str] = None, 
                   timestamp: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/api/v1/events/ingest"
        
        payload = {
            "source": source,
            "event_type": event_type,
            "raw_event": raw_event,
            "severity": severity or BackendSeverity.MEDIUM
        }
        
        if normalized_event:
            payload["normalized_event"] = normalized_event
        
        if timestamp:
            payload["timestamp"] = timestamp.isoformat()
        else:
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        logger.debug(
            "About to send event",
            extra={
                "event_source": source,
                "event_type": event_type,
                "event_timestamp": payload["timestamp"],
            },
        )
        
        try:
            response = self._post(url, payload)
            response.raise_for_status()
            logger.info(f"Event sent successfully: {event_type}")
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error("Failed to send event with HTTP %s", e.response.status_code if e.response is not None else "unknown")
            try:
                error_detail = e.response.json() if e.response is not None else {}
                logger.error(f"Backend error details: {json.dumps(error_detail)}")
            except Exception:
                logger.error("Backend error response: %s", e.response.text if e.response is not None else "")
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Event request failed: %s", e)
            return None
