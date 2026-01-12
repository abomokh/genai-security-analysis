from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Security tracking
    last_password_change = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    mfa = relationship("MFASetting", back_populates="user", uselist=False)
    sessions = relationship("Session", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user")

class MFASetting(Base):
    __tablename__ = "mfa_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    totp_secret_encrypted = Column(Text, nullable=False) # Encrypted at rest
    is_enabled = Column(Boolean, default=True)
    
    user = relationship("User", back_populates="mfa")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    session_id_hash = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False) # Absolute timeout
    device_fingerprint = Column(String, nullable=True)
    
    user = relationship("User", back_populates="sessions")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token_hash = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)
    rotation_counter = Column(Integer, default=0)
    
    user = relationship("User", back_populates="refresh_tokens")

class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token_hash = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    type = Column(String) # 'email_verification' or 'password_reset'

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    ip_address = Column(String, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    was_successful = Column(Boolean, default=False)


class RateLimitBucket(Base):
    """Token bucket for rate limiting (replaces Redis bucket storage)."""
    __tablename__ = "rate_limit_buckets"
    
    id = Column(Integer, primary_key=True, index=True)
    bucket_key = Column(String, unique=True, index=True, nullable=False)  # e.g., "rl:bucket:192.168.1.1"
    tokens = Column(Integer, nullable=False)  # Current token count
    last_refill = Column(DateTime, nullable=False)  # Last time tokens were refilled
    

class FailedLoginCounter(Base):
    """Tracks failed login attempts per identifier (email or IP)."""
    __tablename__ = "failed_login_counters"
    
    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String, unique=True, index=True, nullable=False)  # email or IP
    count = Column(Integer, default=0, nullable=False)
    first_attempt = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_attempt = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AccountLockout(Base):
    """Temporary lockout records (replaces Redis lockout keys)."""
    __tablename__ = "account_lockouts"
    
    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String, unique=True, index=True, nullable=False)  # email or IP
    locked_until = Column(DateTime, nullable=False)  # When the lockout expires
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))