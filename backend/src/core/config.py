import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    PROJECT_NAME: str = "TriageOps"
    ENVIRONMENT: str = "development"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "::1", "testserver"]
    
    # Database
    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "triageops"
    POSTGRES_PASSWORD: str = "triageops_secret"
    POSTGRES_DB: str = "triageops"
    USE_SQLITE: bool = True
    DATABASE_URL_OVERRIDE: Optional[str] = None
    
    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE
        if self.USE_SQLITE:
            return "sqlite:///./triageops.db"
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
    JWT_ISSUER: str = "triageops"
    COLLECTOR_TOKEN_SECRET: Optional[str] = None
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    RATE_LIMIT_STORAGE_URL: Optional[str] = None
    RATE_LIMIT_DEFAULT: str = "200/minute"
    METRICS_ENABLED: bool = True
    METRICS_PATH: str = "/metrics"
    WEBSOCKET_HEARTBEAT_SECONDS: int = 30
    WEBSOCKET_SEND_TIMEOUT_SECONDS: int = 5
    MAX_REQUEST_BODY_BYTES: int = 2_000_000
    COLLECTOR_OFFLINE_AFTER_SECONDS: int = 180
    SOAR_TASK_ALWAYS_EAGER: bool = False
    CELERY_TASK_TIME_LIMIT_SECONDS: int = 300
    CELERY_TASK_SOFT_TIME_LIMIT_SECONDS: int = 240
    
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
        if self.REFRESH_TOKEN_EXPIRE_DAYS < 1:
            raise RuntimeError("REFRESH_TOKEN_EXPIRE_DAYS must be at least 1")
        if self.MAX_FAILED_LOGIN_ATTEMPTS < 1:
            raise RuntimeError("MAX_FAILED_LOGIN_ATTEMPTS must be at least 1")
        if self.ACCOUNT_LOCKOUT_MINUTES < 1:
            raise RuntimeError("ACCOUNT_LOCKOUT_MINUTES must be at least 1")
        if self.WEBSOCKET_HEARTBEAT_SECONDS < 5:
            raise RuntimeError("WEBSOCKET_HEARTBEAT_SECONDS must be at least 5")
        if self.WEBSOCKET_SEND_TIMEOUT_SECONDS < 1:
            raise RuntimeError("WEBSOCKET_SEND_TIMEOUT_SECONDS must be at least 1")
        if self.MAX_REQUEST_BODY_BYTES < 1024:
            raise RuntimeError("MAX_REQUEST_BODY_BYTES must be at least 1024")
        if self.COLLECTOR_OFFLINE_AFTER_SECONDS < 60:
            raise RuntimeError("COLLECTOR_OFFLINE_AFTER_SECONDS must be at least 60")
        if self.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS < 1:
            raise RuntimeError("CELERY_TASK_SOFT_TIME_LIMIT_SECONDS must be at least 1")
        if self.CELERY_TASK_TIME_LIMIT_SECONDS < self.CELERY_TASK_SOFT_TIME_LIMIT_SECONDS:
            raise RuntimeError("CELERY_TASK_TIME_LIMIT_SECONDS must be greater than or equal to CELERY_TASK_SOFT_TIME_LIMIT_SECONDS")
        if self.THREAT_INTEL_CACHE_TTL_HOURS < 1:
            raise RuntimeError("THREAT_INTEL_CACHE_TTL_HOURS must be at least 1")
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
        weak_values = {
            None,
            "",
            "your-secret-key-here-change-in-production",
            "triageops_dev_secret_change_me",
            "collector-secret-key-here-change-in-production",
        }
        required = {
            "SECRET_KEY": self.SECRET_KEY,
            "JWT_SECRET_KEY": self.JWT_SECRET_KEY,
            "REFRESH_TOKEN_SECRET": self.REFRESH_TOKEN_SECRET,
            "COLLECTOR_TOKEN_SECRET": self.COLLECTOR_TOKEN_SECRET,
        }
        invalid = [
            name
            for name, value in required.items()
            if value in weak_values or value is None or len(value) < 32
        ]
        if invalid:
            raise RuntimeError(
                "Production startup blocked: configure strong secrets for "
                + ", ".join(invalid)
            )
        if not self.ALLOWED_HOSTS or "*" in self.ALLOWED_HOSTS:
            raise RuntimeError("Production startup blocked: ALLOWED_HOSTS must not be empty or wildcard")
        if self.USE_SQLITE:
            raise RuntimeError("Production startup blocked: USE_SQLITE must be false")
        if self.USE_REDIS_MOCK:
            raise RuntimeError("Production startup blocked: USE_REDIS_MOCK must be false")
        if not self.OPENAI_API_KEY:
            raise RuntimeError("Production startup blocked: OPENAI_API_KEY must be configured")


@lru_cache()
def get_settings():
    return Settings()
