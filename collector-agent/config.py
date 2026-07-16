import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Collector credentials
    COLLECTOR_ID: str = os.getenv("COLLECTOR_ID", "")
    COLLECTOR_TOKEN: str = os.getenv("COLLECTOR_TOKEN", "")
    
    # Backend configuration
    BACKEND_URL: str = os.getenv("BACKEND_URL", "http://localhost:8001")
    
    # Timing
    HEARTBEAT_INTERVAL_SECONDS: int = 60
    EVENT_POLL_INTERVAL_SECONDS: float = 2.0
    
    @classmethod
    def validate_config(cls) -> bool:
        if not cls.COLLECTOR_ID or not cls.COLLECTOR_TOKEN:
            return False
        if not cls.BACKEND_URL:
            return False
        if cls.HEARTBEAT_INTERVAL_SECONDS < 5:
            return False
        if cls.EVENT_POLL_INTERVAL_SECONDS < 0.5:
            return False
        return True
