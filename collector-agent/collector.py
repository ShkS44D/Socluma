import platform
import time
from typing import List, Dict, Any
from api_client import SoclumaAPIClient
from event_collector import WindowsEventCollector, LinuxEventCollector
from heartbeat import HeartbeatService
from utils.logger import setup_logger
from spool import DurableEventSpool
from state import AtomicCheckpointStore

logger = setup_logger("collector")

class SoclumaCollector:
    def __init__(self, api_client: SoclumaAPIClient, heartbeat_interval: int = 60, event_poll_interval: float = 2.0):
        self.api_client = api_client
        self.spool = DurableEventSpool(api_client.config.SPOOL_PATH, api_client.config.SPOOL_MAX_BYTES)
        self.checkpoints = AtomicCheckpointStore(api_client.config.CHECKPOINT_PATH)
        self.counters = {"events_collected": 0, "events_submitted": 0, "retry_count": 0, "dropped_event_count": 0}
        self.heartbeat_service = HeartbeatService(api_client, heartbeat_interval, self._diagnostics)
        self.event_poll_interval = max(0.5, float(event_poll_interval))
        
        # Initialize platform-specific collector
        system = platform.system().lower()
        if system == "windows":
            self.event_collector = WindowsEventCollector(api_client.config.WINDOWS_EVENT_CHANNELS)
        elif system == "linux":
            self.event_collector = LinuxEventCollector()
        else:
            logger.warning(f"Unsupported platform: {system}, using simulator")
            self.event_collector = WindowsEventCollector()  # Use Windows simulator for any platform
    
    def start(self):
        logger.info(
            "Starting Socluma collector (backend=%s collector_id=%s channels=%s)",
            self.api_client.base_url,
            self.api_client.config.COLLECTOR_ID,
            ",".join(getattr(self.event_collector, "channels", [])) or "platform-default",
        )
        self.heartbeat_service.start()
        
        try:
            self._event_collection_loop()
        except KeyboardInterrupt:
            logger.info("Received stop signal")
        finally:
            self.stop()
    
    def stop(self):
        logger.info("Stopping Socluma collector...")
        self.heartbeat_service.stop()
        self.api_client.close()
        self.spool.close()
    
    def _event_collection_loop(self):
        logger.info("Starting event collection loop...")
        while True:
            try:
                # Collect events
                events = self.event_collector.collect_events()
                accepted = 0
                duplicates = 0
                rejected = 0
                submitted = 0
                # Persist before attempting delivery. Checkpoints only advance
                # after this transaction has made the events durable.
                for event in events:
                    payload = dict(event)
                    timestamp = payload.get("timestamp")
                    if hasattr(timestamp, "isoformat"):
                        payload["timestamp"] = timestamp.isoformat()
                    if not payload.get("source_event_id"):
                        payload["source_event_id"] = self._derive_source_event_id(payload)
                    self.spool.append(payload)
                if events:
                    self.counters["events_collected"] += len(events)
                    state = self.checkpoints.load()
                    state["last_spooled_at"] = time.time()
                    state["events_collected"] = self.counters["events_collected"]
                    self.checkpoints.save(state)
                queued = self.spool.peek(self.api_client.config.BATCH_SIZE)
                if queued:
                    submitted = len(queued)
                    batch_id = str(__import__("uuid").uuid4())
                    response = self.api_client.send_batch([payload for _, payload in queued], batch_id)
                    self.counters["events_submitted"] += submitted
                    if response is None:
                        rejected = submitted
                        self.counters["retry_count"] += 1
                    else:
                        # Accepted and deterministic duplicates are acknowledged;
                        # permanent per-item rejects are also removed and visible in
                        # the server DLQ, avoiding a poison-event loop.
                        self.spool.ack([event_id for event_id, _ in queued])
                        accepted = int(response.get("accepted", 0))
                        duplicates = int(response.get("duplicates", 0))
                        rejected = int(response.get("rejected", 0))
                if events or submitted:
                    logger.info(
                        "Collection cycle completed (read=%s submitted=%s accepted=%s duplicates=%s rejected=%s)",
                        len(events),
                        submitted,
                        accepted,
                        duplicates,
                        rejected,
                    )
                    
            except Exception as e:
                logger.error(f"Event collection loop error: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying
            
            # Wait before next collection
            time.sleep(self.event_poll_interval)

    @staticmethod
    def _derive_source_event_id(payload: Dict[str, Any]) -> str | None:
        """Return a stable per-host Windows record identity.

        Windows EventID describes the event kind and is intentionally repeated.
        EventRecordID/RecordNumber is the unique cursor within a channel. Host
        and channel are included because record numbers can overlap across
        machines and log channels.
        """
        raw_event = payload.get("raw_event") or {}
        normalized_event = payload.get("normalized_event") or {}
        record_number = (
            raw_event.get("EventRecordID")
            if raw_event.get("EventRecordID") is not None
            else raw_event.get("record_number")
            if raw_event.get("record_number") is not None
            else raw_event.get("RecordNumber")
        )
        if record_number is None:
            return None
        host = (
            raw_event.get("Computer")
            or normalized_event.get("hostname")
            or raw_event.get("hostname")
            or "unknown-host"
        )
        channel = (
            raw_event.get("Channel")
            or raw_event.get("channel")
            or raw_event.get("log_name")
            or normalized_event.get("channel")
            or "unknown-channel"
        )
        return f"windows:{host}:{channel}:{record_number}"

    def _diagnostics(self):
        return {**self.spool.stats(), **self.counters, "checkpoint_status": "healthy"}
