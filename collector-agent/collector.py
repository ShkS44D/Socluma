import platform
import time
from typing import List, Dict, Any
from api_client import TriageOpsAPIClient
from event_collector import WindowsEventCollector, LinuxEventCollector
from heartbeat import HeartbeatService
from utils.logger import setup_logger

logger = setup_logger("collector")

class TriageOpsCollector:
    def __init__(self, api_client: TriageOpsAPIClient, heartbeat_interval: int = 60, event_poll_interval: float = 2.0):
        self.api_client = api_client
        self.heartbeat_service = HeartbeatService(api_client, heartbeat_interval)
        self.event_poll_interval = max(0.5, float(event_poll_interval))
        
        # Initialize platform-specific collector
        system = platform.system().lower()
        if system == "windows":
            self.event_collector = WindowsEventCollector()
        elif system == "linux":
            self.event_collector = LinuxEventCollector()
        else:
            logger.warning(f"Unsupported platform: {system}, using simulator")
            self.event_collector = WindowsEventCollector()  # Use Windows simulator for any platform
    
    def start(self):
        logger.info("Starting TriageOps collector...")
        self.heartbeat_service.start()
        
        try:
            self._event_collection_loop()
        except KeyboardInterrupt:
            logger.info("Received stop signal")
        finally:
            self.stop()
    
    def stop(self):
        logger.info("Stopping TriageOps collector...")
        self.heartbeat_service.stop()
        self.api_client.close()
    
    def _event_collection_loop(self):
        logger.info("Starting event collection loop...")
        while True:
            try:
                # Collect events
                events = self.event_collector.collect_events()
                
                # Send events
                for event in events:
                    self.api_client.send_event(
                        source=event["source"],
                        event_type=event["event_type"],
                        raw_event=event["raw_event"],
                        normalized_event=event.get("normalized_event"),
                        severity=event.get("severity"),
                        timestamp=event.get("timestamp")
                    )
                    time.sleep(0.1)  # Small delay to avoid overwhelming the backend
                    
            except Exception as e:
                logger.error(f"Event collection loop error: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying
            
            # Wait before next collection
            time.sleep(self.event_poll_interval)
