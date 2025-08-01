import os
from typing import Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """SIEM Configuration Settings"""
    
    # Database Configuration
    database_url: str = Field(
        default="postgresql://siem_user:siem_password@localhost:5432/siem_db",
        env="DATABASE_URL"
    )
    
    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379",
        env="REDIS_URL"
    )
    
    # Elasticsearch Configuration
    elasticsearch_url: str = Field(
        default="http://localhost:9200",
        env="ELASTICSEARCH_URL"
    )
    
    # Security Settings
    secret_key: str = Field(
        default="your-secret-key-change-in-production",
        env="SECRET_KEY"
    )
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # SIEM Settings
    log_retention_days: int = Field(default=90, env="LOG_RETENTION_DAYS")
    max_events_per_minute: int = Field(default=10000, env="MAX_EVENTS_PER_MINUTE")
    correlation_window_minutes: int = Field(default=5, env="CORRELATION_WINDOW_MINUTES")
    
    # Alert Settings
    alert_cooldown_minutes: int = Field(default=15, env="ALERT_COOLDOWN_MINUTES")
    max_alerts_per_hour: int = Field(default=100, env="MAX_ALERTS_PER_HOUR")
    
    # File Paths
    config_dir: str = Field(default="./config", env="CONFIG_DIR")
    log_dir: str = Field(default="./logs", env="LOG_DIR")
    rules_dir: str = Field(default="./config/rules", env="RULES_DIR")
    
    # Performance Settings
    worker_processes: int = Field(default=4, env="WORKER_PROCESSES")
    batch_size: int = Field(default=1000, env="BATCH_SIZE")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings"""
    return settings