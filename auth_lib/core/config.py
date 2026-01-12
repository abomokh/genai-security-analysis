import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    # Database (SQLite - also used for rate limiting, no Redis needed)
    DATABASE_URL: str = "sqlite:///./auth_lib.db"

    # Security Keys (Should be set in environment)
    # Using default values only for development; production MUST set these
    SECRET_KEY: str = "y3f8v2n9m4c7x1z0l9k8j7h6g5f4d3s2"
    ENCRYPTION_KEY_LATEST: str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=" 
    
    # Argon2id Settings
    ARGON2_MEMORY_COST: int = 64 * 1024  # 64 MB in KB
    ARGON2_TIME_COST: int = 3
    ARGON2_PARALLELISM: int = 2

    # Session Settings
    SESSION_ID_LENGTH: int = 16  # 128 bits = 16 bytes
    SESSION_ABSOLUTE_TIMEOUT: int = 120  # 2 hours in minutes
    SESSION_IDLE_TIMEOUT: int = 10  # 10 minutes
    SESSION_ROTATION_INTERVAL: int = 150  # 2.5 minutes in seconds

    # MFA Settings
    TOTP_STEP: int = 30  # 30 seconds
    TOTP_DIGITS: int = 6

    # API Keys
    HIBP_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # Rate Limiting
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: List[int] = [5, 15, 30, 60, 60 * 24] # Progressive lockouts

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

