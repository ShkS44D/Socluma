import sys
from config import Config
from api_client import SoclumaAPIClient
from collector import SoclumaCollector
from utils.logger import setup_logger

logger = setup_logger("main")

def main():
    # Validate config
    if not Config.validate_config():
        logger.critical("Invalid configuration. Please set COLLECTOR_ID, COLLECTOR_TOKEN, and BACKEND_URL")
        sys.exit(1)
    
    logger.info("Configuration loaded successfully")
    
    # Initialize API client
    api_client = SoclumaAPIClient(Config)
    
    # Initialize and start collector
    collector = SoclumaCollector(api_client, Config.HEARTBEAT_INTERVAL_SECONDS, Config.EVENT_POLL_INTERVAL_SECONDS)
    
    try:
        collector.start()
    except Exception as e:
        logger.critical(f"Collector failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
