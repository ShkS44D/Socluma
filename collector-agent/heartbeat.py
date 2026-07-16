import threading
import time
from utils.logger import setup_logger

logger = setup_logger("heartbeat")

class HeartbeatService:
    def __init__(self, api_client, interval_seconds: int):
        self.api_client = api_client
        self.interval_seconds = interval_seconds
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        if self._running:
            logger.warning("Heartbeat service already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"Heartbeat service started, interval: {self.interval_seconds}s")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Heartbeat service stopped")

    def _run_loop(self):
        while self._running:
            try:
                self.api_client.send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}", exc_info=True)
            
            # Wait for the interval, checking if we should stop every second
            for _ in range(self.interval_seconds):
                if not self._running:
                    break
                time.sleep(1)
