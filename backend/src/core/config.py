import secrets
import json
from urllib.parse import urlparse
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    # Ignore unrelated keys in a colocated dotenv file.  The collector imports
    # shared request models during its own tests and has a separate .env schema;
    # rejecting those collector-only keys makes an otherwise valid test/runtime
    # environment fail while constructing backend settings.
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "Socluma"
    APP_VERSION: str = "1.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    DOCS_ENABLED: bool = True
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "::1", "testserver"]
    
    # Database
    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "socluma"
    POSTGRES_PASSWORD: str = "socluma_secret"
    POSTGRES_DB: str = "socluma"
    USE_SQLITE: bool = True
    DATABASE_URL_OVERRIDE: Optional[str] = None
    
    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE
        if self.USE_SQLITE:
            return "sqlite:///./socluma.db"
        return f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:5432/{self.POSTGRES_DB}"
    
    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    USE_REDIS_MOCK: bool = True
    
    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"
    
    # Security
    SECRET_KEY: Optional[str] = None
    JWT_SECRET_KEY: Optional[str] = None
    REFRESH_TOKEN_SECRET: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    JWT_ISSUER: str = "socluma"
    AI_IDEMPOTENCY_NAMESPACE: str = "socluma:ai:idempotency:"
    COLLECTOR_TOKEN_SECRET: Optional[str] = None
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_BCRYPT_ROUNDS: int = 12
    MFA_ISSUER: str = "Socluma"
    MFA_CHALLENGE_MINUTES: int = 5
    MFA_ENROLLMENT_MINUTES: int = 10
    MFA_FAILURE_LIMIT: int = 5
    MFA_LOCKOUT_MINUTES: int = 15
    EMAIL_VERIFICATION_REQUIRED: bool = False
    EMAIL_VERIFICATION_TOKEN_MINUTES: int = 1440
    EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS: int = 60
    PASSWORD_RESET_TOKEN_MINUTES: int = 30
    SESSION_INACTIVITY_DAYS: int = 7
    SESSION_MAX_LIFETIME_DAYS: int = 30
    AUTH_RATE_LIMIT_MFA: str = "5/minute"
    AUTH_RATE_LIMIT_RECOVERY: str = "5/minute"
    AUTH_RATE_LIMIT_PASSWORD_RESET: str = "3/hour"
    AUTH_RATE_LIMIT_VERIFICATION: str = "3/hour"
    SECURE_COOKIE: bool = False
    COOKIE_SAMESITE: str = "lax"
    FRONTEND_PUBLIC_URL: str = "http://localhost:3000"
    AUTH_EMAIL_FROM: str = "security@socluma.local"
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    AUTH_EMAIL_CAPTURE: bool = True
    AUTH_DEV_EXPOSE_TOKENS: bool = False
    RATE_LIMIT_STORAGE_URL: Optional[str] = None
    RATE_LIMIT_DEFAULT: str = "200/minute"
    METRICS_ENABLED: bool = True
    METRICS_PATH: str = "/metrics"
    WEBSOCKET_HEARTBEAT_SECONDS: int = 30
    WEBSOCKET_SEND_TIMEOUT_SECONDS: int = 5
    MAX_REQUEST_BODY_BYTES: int = 2_000_000
    COLLECTOR_OFFLINE_AFTER_SECONDS: int = 180
    INGESTION_MAX_BATCH_EVENTS: int = 500
    INGESTION_MAX_EVENT_BYTES: int = 262_144
    INGESTION_MAX_REQUEST_BYTES: int = 10_485_760
    INGESTION_DEDUP_WINDOW_HOURS: int = 24
    INGESTION_REPLAY_WINDOW_SECONDS: int = 300
    INGESTION_MAX_RETRY_ATTEMPTS: int = 5
    INGESTION_RETRY_BASE_SECONDS: int = 15
    INGESTION_DEAD_LETTER_RETENTION_DAYS: int = 30
    INGESTION_RATE_LIMIT: str = "120/minute"
    COLLECTOR_CREDENTIAL_LIFETIME_DAYS: int = 365
    COLLECTOR_CREDENTIAL_OVERLAP_MINUTES: int = 15
    COLLECTOR_ENROLLMENT_TOKEN_MINUTES: int = 30
    COLLECTOR_HEALTH_DELAYED_SECONDS: int = 120
    COLLECTOR_HEALTH_OFFLINE_SECONDS: int = 300
    COLLECTOR_LATEST_VERSION: str = "1.0.0"
    COLLECTOR_SUPPORTED_VERSIONS: List[str] = ["1.0.0"]
    COLLECTOR_BLOCKED_VERSIONS: List[str] = []
    TELEMETRY_IMPORT_MAX_BYTES: int = 25_000_000
    TELEMETRY_IMPORT_DIRECTORY: str = "./data/telemetry-imports"
    TELEMETRY_IMPORT_EXPIRE_HOURS: int = 24
    SYSLOG_UDP_ENABLED: bool = False
    SYSLOG_TCP_ENABLED: bool = False
    SYSLOG_TLS_ENABLED: bool = False
    SEARCH_DEFAULT_RANGE_HOURS: int = 24
    SEARCH_MAX_INTERACTIVE_DAYS: int = 30
    SEARCH_MAX_BACKGROUND_DAYS: int = 365
    SEARCH_MAX_QUERY_LENGTH: int = 4000
    SEARCH_MAX_CLAUSES: int = 50
    SEARCH_MAX_NESTING_DEPTH: int = 8
    SEARCH_MAX_WILDCARDS: int = 5
    SEARCH_MAX_LIST_SIZE: int = 50
    SEARCH_MAX_PAGE_SIZE: int = 200
    SEARCH_MAX_EXPORT_ROWS: int = 100_000
    SEARCH_EXPORT_EXPIRE_HOURS: int = 24
    SEARCH_HISTORY_RETENTION_DAYS: int = 90
    SEARCH_MAX_SCHEDULES_PER_TENANT: int = 100
    ENTITY_GRAPH_MAX_DEPTH: int = 3
    ENTITY_GRAPH_MAX_NODES: int = 200
    ENTITY_GRAPH_MAX_EDGES: int = 500
    INVESTIGATION_ATTACHMENT_MAX_BYTES: int = 10_000_000
    INVESTIGATION_ALLOWED_ATTACHMENT_TYPES: List[str] = ["image/png", "image/jpeg", "application/pdf", "text/plain", "text/csv"]
    SEARCH_AUTOCOMPLETE_LIMIT: int = 20
    DETECTION_MAX_RULE_BYTES: int = 262_144
    DETECTION_MAX_COMPLEXITY: int = 100
    DETECTION_MAX_BOOLEAN_CLAUSES: int = 50
    DETECTION_MAX_SEQUENCE_STEPS: int = 10
    DETECTION_MAX_GROUP_BY_FIELDS: int = 5
    DETECTION_MAX_AGGREGATION_CARDINALITY: int = 10_000
    DETECTION_MIN_WINDOW_SECONDS: int = 10
    DETECTION_MAX_WINDOW_SECONDS: int = 86_400
    DETECTION_MAX_REGEX_LENGTH: int = 512
    DETECTION_REGEX_TIMEOUT_MS: int = 25
    DETECTION_REGEX_MAX_INPUT_BYTES: int = 8192
    DETECTION_TEST_DATASET_MAX_EVENTS: int = 1_000
    DETECTION_SIMULATION_MAX_DAYS: int = 30
    DETECTION_SIMULATION_MAX_EVENTS: int = 100_000
    DETECTION_SIMULATION_MAX_RUNTIME_SECONDS: int = 300
    DETECTION_SIMULATION_EXPIRE_HOURS: int = 24
    DETECTION_REVIEW_EXPIRE_HOURS: int = 72
    DETECTION_REQUIRE_TWO_PERSON_APPROVAL: bool = True
    DETECTION_MAINTENANCE_MAX_HOURS: int = 168
    DETECTION_EXCEPTION_MAX_DAYS: int = 365
    DETECTION_STATE_RETENTION_HOURS: int = 48
    DETECTION_EXECUTION_TIMEOUT_MS: int = 250
    DETECTION_NOISE_ALERTS_PER_HOUR: int = 100
    DETECTION_CONTENT_PACK_MAX_BYTES: int = 5_000_000
    DETECTION_IMPORT_MAX_RULES: int = 100
    ORGANIZATION_DELETION_COOLING_OFF_DAYS: int = 30
    SOAR_TASK_ALWAYS_EAGER: bool = False
    CELERY_TASK_TIME_LIMIT_SECONDS: int = 300
    CELERY_TASK_SOFT_TIME_LIMIT_SECONDS: int = 240
    AUDIT_INTEGRITY_KEY: Optional[str] = None
    AUDIT_INTEGRITY_KEY_VERSION: int = 1
    AUDIT_INTEGRITY_KEYS_JSON: Optional[str] = None
    AUDIT_ARCHIVE_DIRECTORY: str = "./data/audit-archives"
    AUDIT_EXPORT_DIRECTORY: str = "./data/audit-exports"
    AUDIT_EXPORT_EXPIRE_HOURS: int = 24
    AUDIT_ARTIFACT_ENCRYPTION_ENABLED: bool = False
    AUDIT_RETENTION_MINIMUM_DAYS: int = 90
    AUDIT_RETENTION_MAXIMUM_DAYS: int = 3650
    ENCRYPTION_CURRENT_KEY_VERSION: int = 1
    ENCRYPTION_KEYS_JSON: Optional[str] = None
    
    # AI
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-5.6-luna"
    OPENAI_TIMEOUT_SECONDS: int = 60
    OPENAI_MAX_OUTPUT_TOKENS: int = 2000
    OPENAI_REASONING_EFFORT: str = "medium"
    AI_CONTEXT_MAX_BYTES: int = 65_536
    AI_CONTEXT_MAX_ALERTS: int = 20
    AI_CONTEXT_MAX_EVENTS: int = 30
    AI_CONTEXT_MAX_ENTITIES: int = 30
    AI_CONTEXT_MAX_IOCS: int = 20
    AI_CONTEXT_MAX_EVIDENCE: int = 40
    AI_CONTEXT_MAX_NOTES: int = 20
    AI_CONTEXT_MAX_AUDIT_EVENTS: int = 30
    AI_CONVERSATION_HISTORY_LIMIT: int = 12
    AI_REQUEST_IDEMPOTENCY_TTL_SECONDS: int = 86_400
    CORRELATION_WINDOW_MINUTES: int = 15
    CORRELATION_MIN_SCORE: float = 45.0
    CORRELATION_MIN_ALERTS: int = 2
    CORRELATION_ALLOW_REPEATED_ALERTS: bool = False

    # Threat intelligence
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None
    THREAT_INTEL_CACHE_TTL_HOURS: int = 24
    IOC_DEFAULT_TTL_DAYS: int = 90
    IOC_MAX_TTL_DAYS: int = 3650
    IOC_EXPIRATION_BATCH_SIZE: int = 500
    IOC_PROVIDER_RETRY_LIMIT: int = 3
    IOC_PROVIDER_TIMEOUT_SECONDS: int = 15
    IOC_PROVIDER_CONCURRENCY: int = 4
    IOC_HUNT_MAX_DAYS: int = 90
    IOC_HUNT_MAX_EVENTS: int = 100_000
    IOC_HUNT_MAX_RUNTIME_SECONDS: int = 300
    IOC_HUNT_RETENTION_HOURS: int = 168
    IOC_ACTIVE_CACHE_SECONDS: int = 60
    IOC_MAX_WATCHLIST_SIZE: int = 100_000
    IOC_MAX_BULK_SIZE: int = 5_000
    IOC_STIX_MAX_BYTES: int = 10_000_000
    IOC_STIX_MAX_OBJECTS: int = 25_000
    IOC_TAXII_MAX_BYTES: int = 10_000_000
    IOC_TAXII_SYNC_MINUTES: int = 60
    IOC_MISP_MAX_BYTES: int = 10_000_000
    IOC_MISP_SYNC_MINUTES: int = 60
    IOC_SIGHTING_GROUPING_SECONDS: int = 300
    IOC_IMPORT_ARTIFACT_HOURS: int = 24
    IOC_REPORT_ARTIFACT_HOURS: int = 24
    TAXII_SYNC_ENABLED: bool = False
    MISP_SYNC_ENABLED: bool = False
    THREAT_SOURCE_REQUEST_TIMEOUT_SECONDS: int = 15
    THREAT_SOURCE_MAX_REDIRECTS: int = 3
    THREAT_SOURCE_MAX_RESPONSE_BYTES: int = 10_000_000
    THREAT_SOURCE_ALLOWED_DESTINATIONS: List[str] = []
    THREAT_SOURCE_ALLOW_PRIVATE_DEVELOPMENT: bool = False
    TAXII_SYNC_MAX_PAGES: int = 100
    TAXII_SYNC_MAX_OBJECTS: int = 25_000
    TAXII_SYNC_MAX_RUNTIME_SECONDS: int = 300
    MISP_SYNC_MAX_OBJECTS: int = 25_000
    MISP_SYNC_MAX_RUNTIME_SECONDS: int = 300
    IOC_BULK_IMPORT_MAX_BYTES: int = 25_000_000
    IOC_BULK_IMPORT_MAX_ROWS: int = 100_000
    IOC_BULK_ACTION_MAX_SIZE: int = 5_000
    IOC_HUNT_MAX_CONCURRENCY: int = 4
    IOC_GRAPH_MAX_DEPTH: int = 3
    IOC_GRAPH_MAX_NODES: int = 300
    IOC_GRAPH_MAX_EDGES: int = 750
    IOC_REPORT_MAX_ROWS: int = 100_000
    IOC_NOTIFICATION_COOLDOWN_SECONDS: int = 900
    IOC_RESPONSE_RECOMMENDATION_HOURS: int = 24
    THREAT_SYNC_JOB_RETENTION_DAYS: int = 30
    IOC_COMMERCIAL_ARTIFACT_DIRECTORY: str = "./data/ioc-artifacts"
    
    # Admin Bootstrap
    ADMIN_EMAIL: Optional[str] = None
    ADMIN_PASSWORD: Optional[str] = None
    
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() in {"production", "prod"}

    def model_post_init(self, __context) -> None:
        if not self.is_production():
            self.SECRET_KEY = self.SECRET_KEY or secrets.token_urlsafe(48)
            self.JWT_SECRET_KEY = self.JWT_SECRET_KEY or self.SECRET_KEY
            self.REFRESH_TOKEN_SECRET = self.REFRESH_TOKEN_SECRET or secrets.token_urlsafe(48)
            self.COLLECTOR_TOKEN_SECRET = self.COLLECTOR_TOKEN_SECRET or secrets.token_urlsafe(48)
        self.AUDIT_INTEGRITY_KEY = self.AUDIT_INTEGRITY_KEY or self.REFRESH_TOKEN_SECRET

    def validate_for_runtime(self) -> None:
        if self.ENVIRONMENT.lower() not in {"development", "dev", "test", "testing", "production", "prod"}:
            raise RuntimeError("ENVIRONMENT must be one of development, test, or production")
        if self.USE_SQLITE and self.DATABASE_URL_OVERRIDE and "postgresql" in self.DATABASE_URL_OVERRIDE:
            raise RuntimeError("Configuration conflict: USE_SQLITE=true but DATABASE_URL_OVERRIDE is PostgreSQL")
        if not self.USE_SQLITE and self.DATABASE_URL_OVERRIDE and self.DATABASE_URL_OVERRIDE.startswith("sqlite"):
            raise RuntimeError("Configuration conflict: USE_SQLITE=false but DATABASE_URL_OVERRIDE is SQLite")
        if not self.USE_SQLITE:
            missing_postgres = [
                name for name, value in {
                    "POSTGRES_SERVER": self.POSTGRES_SERVER,
                    "POSTGRES_USER": self.POSTGRES_USER,
                    "POSTGRES_PASSWORD": self.POSTGRES_PASSWORD,
                    "POSTGRES_DB": self.POSTGRES_DB,
                }.items()
                if not value
            ]
            if missing_postgres:
                raise RuntimeError("PostgreSQL configuration is incomplete: " + ", ".join(missing_postgres))
        if self.REDIS_PORT < 1 or self.REDIS_PORT > 65535:
            raise RuntimeError("REDIS_PORT must be between 1 and 65535")
        if self.RATE_LIMIT_STORAGE_URL and not (
            self.RATE_LIMIT_STORAGE_URL.startswith("redis://")
            or self.RATE_LIMIT_STORAGE_URL.startswith("rediss://")
            or self.RATE_LIMIT_STORAGE_URL == "memory://"
        ):
            raise RuntimeError("RATE_LIMIT_STORAGE_URL must be redis://, rediss://, or memory://")
        if not self.RATE_LIMIT_DEFAULT.strip():
            raise RuntimeError("RATE_LIMIT_DEFAULT must not be empty")
        if not self.METRICS_PATH.startswith("/"):
            raise RuntimeError("METRICS_PATH must start with /")
        if self.ACCESS_TOKEN_EXPIRE_MINUTES < 1:
            raise RuntimeError("ACCESS_TOKEN_EXPIRE_MINUTES must be at least 1")
        if self.AUDIT_RETENTION_MINIMUM_DAYS < 30:
            raise RuntimeError("AUDIT_RETENTION_MINIMUM_DAYS must be at least 30")
        if self.AUDIT_RETENTION_MAXIMUM_DAYS < self.AUDIT_RETENTION_MINIMUM_DAYS:
            raise RuntimeError("Audit retention range is invalid")
        if self.AUDIT_EXPORT_EXPIRE_HOURS < 1:
            raise RuntimeError("AUDIT_EXPORT_EXPIRE_HOURS must be at least 1")
        if self.AUDIT_INTEGRITY_KEYS_JSON:
            try:
                integrity_keys = json.loads(self.AUDIT_INTEGRITY_KEYS_JSON)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("AUDIT_INTEGRITY_KEYS_JSON must be a JSON object") from exc
            if (
                not isinstance(integrity_keys, dict)
                or str(self.AUDIT_INTEGRITY_KEY_VERSION) not in integrity_keys
                or any(not isinstance(value, str) or len(value) < 32 for value in integrity_keys.values())
            ):
                raise RuntimeError("AUDIT_INTEGRITY_KEYS_JSON must contain strong keys including the current version")
        if self.ENCRYPTION_CURRENT_KEY_VERSION < 1:
            raise RuntimeError("ENCRYPTION_CURRENT_KEY_VERSION must be at least 1")
        if not self.ENCRYPTION_KEYS_JSON and self.ENCRYPTION_CURRENT_KEY_VERSION != 1:
            raise RuntimeError("ENCRYPTION_CONFIGURATION_INVALID")
        if not self.AUDIT_INTEGRITY_KEYS_JSON and self.AUDIT_INTEGRITY_KEY_VERSION != 1:
            raise RuntimeError("AUDIT_INTEGRITY_KEY_VERSION requires a versioned key ring")
        if self.ENCRYPTION_KEYS_JSON:
            try:
                encryption_keys = json.loads(self.ENCRYPTION_KEYS_JSON)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("ENCRYPTION_KEYS_JSON must be a JSON object") from exc
            if (
                not isinstance(encryption_keys, dict)
                or str(self.ENCRYPTION_CURRENT_KEY_VERSION) not in encryption_keys
                or any(not isinstance(value, str) or len(value) < 32 for value in encryption_keys.values())
            ):
                raise RuntimeError("ENCRYPTION_KEYS_JSON must contain strong versioned keys including the current version")
        if self.REFRESH_TOKEN_EXPIRE_DAYS < 1:
            raise RuntimeError("REFRESH_TOKEN_EXPIRE_DAYS must be at least 1")
        if self.MAX_FAILED_LOGIN_ATTEMPTS < 1:
            raise RuntimeError("MAX_FAILED_LOGIN_ATTEMPTS must be at least 1")
        if self.ACCOUNT_LOCKOUT_MINUTES < 1:
            raise RuntimeError("ACCOUNT_LOCKOUT_MINUTES must be at least 1")
        if self.PASSWORD_MIN_LENGTH < 10 or self.PASSWORD_MAX_LENGTH < self.PASSWORD_MIN_LENGTH:
            raise RuntimeError("Password length configuration is invalid")
        if self.PASSWORD_BCRYPT_ROUNDS < 10 or self.PASSWORD_BCRYPT_ROUNDS > 15:
            raise RuntimeError("PASSWORD_BCRYPT_ROUNDS must be between 10 and 15")
        if not self.MFA_ISSUER.strip() or len(self.MFA_ISSUER) > 64:
            raise RuntimeError("MFA_ISSUER must contain between 1 and 64 characters")
        if self.MFA_CHALLENGE_MINUTES < 1 or self.MFA_CHALLENGE_MINUTES > 10:
            raise RuntimeError("MFA_CHALLENGE_MINUTES must be between 1 and 10")
        if self.MFA_FAILURE_LIMIT < 3 or self.MFA_LOCKOUT_MINUTES < 1:
            raise RuntimeError("MFA lockout configuration is unsafe")
        if self.SESSION_INACTIVITY_DAYS < 1 or self.SESSION_MAX_LIFETIME_DAYS < self.SESSION_INACTIVITY_DAYS:
            raise RuntimeError("Session lifetime configuration is invalid")
        if self.COOKIE_SAMESITE not in {"lax", "strict", "none"}:
            raise RuntimeError("COOKIE_SAMESITE must be lax, strict, or none")
        if not self.FRONTEND_PUBLIC_URL.startswith(("http://", "https://")):
            raise RuntimeError("FRONTEND_PUBLIC_URL must be an HTTP(S) URL")
        if self.WEBSOCKET_HEARTBEAT_SECONDS < 5:
            raise RuntimeError("WEBSOCKET_HEARTBEAT_SECONDS must be at least 5")
        if self.WEBSOCKET_SEND_TIMEOUT_SECONDS < 1:
            raise RuntimeError("WEBSOCKET_SEND_TIMEOUT_SECONDS must be at least 1")
        if self.MAX_REQUEST_BODY_BYTES < 1024:
            raise RuntimeError("MAX_REQUEST_BODY_BYTES must be at least 1024")
        if self.COLLECTOR_OFFLINE_AFTER_SECONDS < 60:
            raise RuntimeError("COLLECTOR_OFFLINE_AFTER_SECONDS must be at least 60")
        if not 1 <= self.INGESTION_MAX_BATCH_EVENTS <= 5000:
            raise RuntimeError("INGESTION_MAX_BATCH_EVENTS must be between 1 and 5000")
        if not 1 <= self.SEARCH_DEFAULT_RANGE_HOURS <= 720:
            raise RuntimeError("SEARCH_DEFAULT_RANGE_HOURS must be between 1 and 720")
        if not 1 <= self.SEARCH_MAX_INTERACTIVE_DAYS <= self.SEARCH_MAX_BACKGROUND_DAYS <= 3650:
            raise RuntimeError("Search range limits are invalid")
        if not 100 <= self.SEARCH_MAX_QUERY_LENGTH <= 20_000:
            raise RuntimeError("SEARCH_MAX_QUERY_LENGTH must be between 100 and 20000")
        if not 1 <= self.SEARCH_MAX_CLAUSES <= 200 or not 1 <= self.SEARCH_MAX_NESTING_DEPTH <= 20:
            raise RuntimeError("Search complexity limits are invalid")
        if not 1 <= self.SEARCH_MAX_PAGE_SIZE <= 1000:
            raise RuntimeError("SEARCH_MAX_PAGE_SIZE must be between 1 and 1000")
        if not 1 <= self.ENTITY_GRAPH_MAX_DEPTH <= 5:
            raise RuntimeError("ENTITY_GRAPH_MAX_DEPTH must be between 1 and 5")
        if not 1024 <= self.DETECTION_MAX_RULE_BYTES <= 5_000_000:
            raise RuntimeError("DETECTION_MAX_RULE_BYTES is unsafe")
        if not 1 <= self.DETECTION_MAX_BOOLEAN_CLAUSES <= self.DETECTION_MAX_COMPLEXITY <= 1000:
            raise RuntimeError("Detection complexity limits are invalid")
        if not 2 <= self.DETECTION_MAX_SEQUENCE_STEPS <= 50 or not 1 <= self.DETECTION_MAX_GROUP_BY_FIELDS <= 20:
            raise RuntimeError("Detection sequence or grouping limits are invalid")
        if not 1 <= self.DETECTION_MIN_WINDOW_SECONDS < self.DETECTION_MAX_WINDOW_SECONDS <= 604800:
            raise RuntimeError("Detection window limits are invalid")
        if not 16 <= self.DETECTION_MAX_REGEX_LENGTH <= 4096:
            raise RuntimeError("Detection regex limit is invalid")
        if not 1 <= self.DETECTION_REGEX_TIMEOUT_MS <= 1000 or not 256 <= self.DETECTION_REGEX_MAX_INPUT_BYTES <= 1_000_000:
            raise RuntimeError("Detection regex execution limits are invalid")
        if self.DETECTION_SIMULATION_MAX_EVENTS < 1 or self.DETECTION_SIMULATION_MAX_RUNTIME_SECONDS < 1:
            raise RuntimeError("Detection simulation limits are invalid")
        if not 1 <= self.DETECTION_MAINTENANCE_MAX_HOURS <= 744 or not 1 <= self.DETECTION_EXCEPTION_MAX_DAYS <= 3650:
            raise RuntimeError("Detection maintenance or exception limits are invalid")
        if self.DETECTION_NOISE_ALERTS_PER_HOUR < 1 or not 1 <= self.DETECTION_IMPORT_MAX_RULES <= 10_000:
            raise RuntimeError("Detection analytics or import limits are invalid")
        if not 1024 <= self.DETECTION_CONTENT_PACK_MAX_BYTES <= 100_000_000:
            raise RuntimeError("Detection content-pack size limit is invalid")
        if self.INGESTION_MAX_EVENT_BYTES < 1024 or self.INGESTION_MAX_REQUEST_BYTES < self.INGESTION_MAX_EVENT_BYTES:
            raise RuntimeError("Ingestion payload limits are invalid")
        if self.INGESTION_REPLAY_WINDOW_SECONDS < 30 or self.INGESTION_MAX_RETRY_ATTEMPTS < 1:
            raise RuntimeError("Ingestion replay or retry settings are unsafe")
        if self.COLLECTOR_HEALTH_OFFLINE_SECONDS <= self.COLLECTOR_HEALTH_DELAYED_SECONDS:
            raise RuntimeError("Collector health thresholds are invalid")
        if self.COLLECTOR_CREDENTIAL_LIFETIME_DAYS < 1 or self.COLLECTOR_ENROLLMENT_TOKEN_MINUTES < 5:
            raise RuntimeError("Collector credential settings are invalid")
        if self.TELEMETRY_IMPORT_MAX_BYTES < 1024 or self.TELEMETRY_IMPORT_EXPIRE_HOURS < 1:
            raise RuntimeError("Telemetry import settings are invalid")
        if self.ORGANIZATION_DELETION_COOLING_OFF_DAYS < 1 or self.ORGANIZATION_DELETION_COOLING_OFF_DAYS > 365:
            raise RuntimeError("ORGANIZATION_DELETION_COOLING_OFF_DAYS must be between 1 and 365")
        if self.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS < 1:
            raise RuntimeError("CELERY_TASK_SOFT_TIME_LIMIT_SECONDS must be at least 1")
        if self.CELERY_TASK_TIME_LIMIT_SECONDS < self.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS:
            raise RuntimeError("CELERY_TASK_TIME_LIMIT_SECONDS must be greater than or equal to CELERY_TASK_SOFT_TIME_LIMIT_SECONDS")
        if self.THREAT_INTEL_CACHE_TTL_HOURS < 1:
            raise RuntimeError("THREAT_INTEL_CACHE_TTL_HOURS must be at least 1")
        if not 1 <= self.IOC_DEFAULT_TTL_DAYS <= self.IOC_MAX_TTL_DAYS <= 36500:
            raise RuntimeError("IOC TTL configuration is unsafe")
        if not 1 <= self.IOC_PROVIDER_RETRY_LIMIT <= 10 or not 1 <= self.IOC_PROVIDER_TIMEOUT_SECONDS <= 120:
            raise RuntimeError("IOC provider retry or timeout configuration is unsafe")
        if not 1 <= self.IOC_PROVIDER_CONCURRENCY <= 64:
            raise RuntimeError("IOC provider concurrency is unsafe")
        if not 1 <= self.IOC_HUNT_MAX_DAYS <= 3650 or not 1 <= self.IOC_HUNT_MAX_EVENTS <= 1_000_000:
            raise RuntimeError("IOC hunt limits are unsafe")
        if not 1 <= self.IOC_MAX_BULK_SIZE <= 100_000 or not 1 <= self.IOC_STIX_MAX_OBJECTS <= 100_000:
            raise RuntimeError("IOC import limits are unsafe")
        commercial_limits = {
            "THREAT_SOURCE_REQUEST_TIMEOUT_SECONDS": (self.THREAT_SOURCE_REQUEST_TIMEOUT_SECONDS, 1, 120),
            "THREAT_SOURCE_MAX_REDIRECTS": (self.THREAT_SOURCE_MAX_REDIRECTS, 0, 10),
            "THREAT_SOURCE_MAX_RESPONSE_BYTES": (self.THREAT_SOURCE_MAX_RESPONSE_BYTES, 1024, 100_000_000),
            "TAXII_SYNC_MAX_PAGES": (self.TAXII_SYNC_MAX_PAGES, 1, 1000),
            "TAXII_SYNC_MAX_OBJECTS": (self.TAXII_SYNC_MAX_OBJECTS, 1, 100_000),
            "TAXII_SYNC_MAX_RUNTIME_SECONDS": (self.TAXII_SYNC_MAX_RUNTIME_SECONDS, 1, 3600),
            "MISP_SYNC_MAX_OBJECTS": (self.MISP_SYNC_MAX_OBJECTS, 1, 100_000),
            "MISP_SYNC_MAX_RUNTIME_SECONDS": (self.MISP_SYNC_MAX_RUNTIME_SECONDS, 1, 3600),
            "IOC_BULK_IMPORT_MAX_BYTES": (self.IOC_BULK_IMPORT_MAX_BYTES, 1024, 250_000_000),
            "IOC_BULK_IMPORT_MAX_ROWS": (self.IOC_BULK_IMPORT_MAX_ROWS, 1, 1_000_000),
            "IOC_BULK_ACTION_MAX_SIZE": (self.IOC_BULK_ACTION_MAX_SIZE, 1, 100_000),
            "IOC_HUNT_MAX_CONCURRENCY": (self.IOC_HUNT_MAX_CONCURRENCY, 1, 64),
            "IOC_GRAPH_MAX_DEPTH": (self.IOC_GRAPH_MAX_DEPTH, 1, 5),
            "IOC_GRAPH_MAX_NODES": (self.IOC_GRAPH_MAX_NODES, 10, 5000),
            "IOC_GRAPH_MAX_EDGES": (self.IOC_GRAPH_MAX_EDGES, 10, 10000),
            "IOC_REPORT_MAX_ROWS": (self.IOC_REPORT_MAX_ROWS, 1, 1_000_000),
            "IOC_NOTIFICATION_COOLDOWN_SECONDS": (self.IOC_NOTIFICATION_COOLDOWN_SECONDS, 30, 86400),
            "IOC_RESPONSE_RECOMMENDATION_HOURS": (self.IOC_RESPONSE_RECOMMENDATION_HOURS, 1, 168),
            "THREAT_SYNC_JOB_RETENTION_DAYS": (self.THREAT_SYNC_JOB_RETENTION_DAYS, 1, 3650),
        }
        invalid_commercial = [
            name for name, (value, minimum, maximum) in commercial_limits.items()
            if value < minimum or value > maximum
        ]
        if invalid_commercial:
            raise RuntimeError("IOC commercial limits are unsafe: " + ", ".join(invalid_commercial))
        if not self.OPENAI_MODEL.strip():
            raise RuntimeError("OPENAI_MODEL must not be empty")
        if self.OPENAI_TIMEOUT_SECONDS < 1 or self.OPENAI_TIMEOUT_SECONDS > 300:
            raise RuntimeError("OPENAI_TIMEOUT_SECONDS must be between 1 and 300")
        if self.OPENAI_MAX_OUTPUT_TOKENS < 1 or self.OPENAI_MAX_OUTPUT_TOKENS > 100_000:
            raise RuntimeError("OPENAI_MAX_OUTPUT_TOKENS must be between 1 and 100000")
        if self.OPENAI_REASONING_EFFORT not in {"minimal", "low", "medium", "high"}:
            raise RuntimeError("OPENAI_REASONING_EFFORT must be one of minimal, low, medium, or high")
        bounded_ai_settings = {
            "AI_CONTEXT_MAX_BYTES": (self.AI_CONTEXT_MAX_BYTES, 8_192, 262_144),
            "AI_CONTEXT_MAX_ALERTS": (self.AI_CONTEXT_MAX_ALERTS, 1, 100),
            "AI_CONTEXT_MAX_EVENTS": (self.AI_CONTEXT_MAX_EVENTS, 1, 100),
            "AI_CONTEXT_MAX_ENTITIES": (self.AI_CONTEXT_MAX_ENTITIES, 1, 250),
            "AI_CONTEXT_MAX_IOCS": (self.AI_CONTEXT_MAX_IOCS, 1, 100),
            "AI_CONTEXT_MAX_EVIDENCE": (self.AI_CONTEXT_MAX_EVIDENCE, 1, 100),
            "AI_CONTEXT_MAX_NOTES": (self.AI_CONTEXT_MAX_NOTES, 1, 100),
            "AI_CONTEXT_MAX_AUDIT_EVENTS": (self.AI_CONTEXT_MAX_AUDIT_EVENTS, 1, 100),
            "AI_CONVERSATION_HISTORY_LIMIT": (self.AI_CONVERSATION_HISTORY_LIMIT, 1, 20),
            "AI_REQUEST_IDEMPOTENCY_TTL_SECONDS": (self.AI_REQUEST_IDEMPOTENCY_TTL_SECONDS, 60, 604_800),
        }
        invalid_ai_settings = [
            name for name, (value, minimum, maximum) in bounded_ai_settings.items()
            if value < minimum or value > maximum
        ]
        if invalid_ai_settings:
            raise RuntimeError("AI context configuration is outside supported bounds: " + ", ".join(invalid_ai_settings))
        if not self.is_production():
            return
        if self.DEBUG:
            raise RuntimeError("Production startup blocked: DEBUG must be false")
        if self.DOCS_ENABLED:
            raise RuntimeError("Production startup blocked: DOCS_ENABLED must be false")
        if not self.SECURE_COOKIE:
            raise RuntimeError("Production startup blocked: SECURE_COOKIE must be true")
        if self.AUTH_EMAIL_CAPTURE or self.AUTH_DEV_EXPOSE_TOKENS:
            raise RuntimeError("Production startup blocked: authentication email development modes must be false")
        if self.EMAIL_VERIFICATION_REQUIRED and not self.SMTP_HOST:
            raise RuntimeError("Production startup blocked: SMTP is required when email verification is required")
        if not self.FRONTEND_PUBLIC_URL.startswith("https://"):
            raise RuntimeError("Production startup blocked: FRONTEND_PUBLIC_URL must use HTTPS")
        weak_values = {
            None,
            "",
            "your-secret-key-here-change-in-production",
            "socluma_dev_secret_change_me",
            "collector-secret-key-here-change-in-production",
        }
        required = {
            "SECRET_KEY": self.SECRET_KEY,
            "JWT_SECRET_KEY": self.JWT_SECRET_KEY,
            "REFRESH_TOKEN_SECRET": self.REFRESH_TOKEN_SECRET,
            "COLLECTOR_TOKEN_SECRET": self.COLLECTOR_TOKEN_SECRET,
            "AUDIT_INTEGRITY_KEY": (
                json.loads(self.AUDIT_INTEGRITY_KEYS_JSON).get(str(self.AUDIT_INTEGRITY_KEY_VERSION))
                if self.AUDIT_INTEGRITY_KEYS_JSON else self.AUDIT_INTEGRITY_KEY
            ),
        }
        invalid = []
        for name, value in required.items():
            normalized = value.strip().lower() if isinstance(value, str) else ""
            is_development_placeholder = "_dev_" in normalized and normalized.endswith("_change_me")
            if value in weak_values or value is None or len(value) < 32 or is_development_placeholder:
                invalid.append(name)
        if invalid:
            raise RuntimeError(
                "Production startup blocked: configure strong secrets for "
                + ", ".join(invalid)
            )
        if not self.ALLOWED_HOSTS or "*" in self.ALLOWED_HOSTS:
            raise RuntimeError("Production startup blocked: ALLOWED_HOSTS must not be empty or wildcard")
        invalid_origins = [
            origin
            for origin in self.BACKEND_CORS_ORIGINS
            if origin == "*"
            or urlparse(origin).scheme != "https"
            or not urlparse(origin).netloc
        ]
        if invalid_origins:
            raise RuntimeError("Production startup blocked: CORS origins must be explicit HTTPS origins")
        if self.USE_SQLITE:
            raise RuntimeError("Production startup blocked: USE_SQLITE must be false")
        if self.USE_REDIS_MOCK:
            raise RuntimeError("Production startup blocked: USE_REDIS_MOCK must be false")
        if self.SYSLOG_UDP_ENABLED:
            raise RuntimeError("Production startup blocked: public UDP Syslog is not enabled by default")
        placeholder_values = {"change-me", "changeme", "password", "secret", "socluma_secret"}
        database_password = (
            urlparse(self.DATABASE_URL_OVERRIDE).password
            if self.DATABASE_URL_OVERRIDE
            else self.POSTGRES_PASSWORD
        )
        if (
            not database_password
            or database_password.lower() in placeholder_values
            or database_password.lower().endswith("_secret")
        ):
            raise RuntimeError("Production startup blocked: POSTGRES_PASSWORD is a known placeholder")
        if self.REDIS_HOST.lower() in {"", "localhost", "127.0.0.1"}:
            raise RuntimeError("Production startup blocked: configure a production Redis service")
        if not self.OPENAI_API_KEY or self.OPENAI_API_KEY.lower() in placeholder_values:
            raise RuntimeError("Production startup blocked: OPENAI_API_KEY must be configured")


@lru_cache()
def get_settings():
    return Settings()
