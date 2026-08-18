import threading
import time
import platform
import shutil
from utils.logger import setup_logger

logger = setup_logger("heartbeat")

class HeartbeatService:
    def __init__(self, api_client, interval_seconds: int, diagnostics_provider=None):
        self.api_client = api_client
        self.interval_seconds = interval_seconds
        self._running = False
        self._thread: threading.Thread | None = None
        self.diagnostics_provider = diagnostics_provider

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
                diagnostics = {
                    "collector_version": "1.0.0",
                    "platform": platform.system().lower(),
                    "os_version": platform.version(),
                    "architecture": platform.machine(),
                    "service_status": "running",
                }
                if self.diagnostics_provider:
                    diagnostics.update(self.diagnostics_provider())
                usage = shutil.disk_usage(".")
                diagnostics["disk_percent"] = round((usage.used / usage.total) * 100, 2) if usage.total else 0
                self.api_client.send_heartbeat(diagnostics)
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}", exc_info=True)
            
            # Wait for the interval, checking if we should stop every second
            for _ in range(self.interval_seconds):
                if not self._running:
                    break
                time.sleep(1)
