"""
Rate Limiting Service using SQLite (instead of Redis).

This implementation uses the database for:
- Token bucket rate limiting
- Failed login attempt tracking
- Temporary account/IP lockouts

Trade-off: Slightly slower than Redis but simpler deployment (no Redis dependency).
"""

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session as DBSession
from auth_lib.models.models import RateLimitBucket, FailedLoginCounter, AccountLockout
from auth_lib.core.config import settings


class RateLimitService:
    def __init__(self, db: DBSession):
        self.db = db

    def is_rate_limited(self, key: str, capacity: int, refill_rate: float) -> bool:
        """
        Token Bucket Rate Limiter (SQLite-backed).
        
        Args:
            key: Unique identifier for the bucket (e.g., IP address)
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
            
        Returns:
            True if rate limited (no tokens available), False otherwise
        """
        bucket_key = f"rl:bucket:{key}"
        now = datetime.now(timezone.utc)
        
        # Get or create bucket
        bucket = self.db.query(RateLimitBucket).filter(
            RateLimitBucket.bucket_key == bucket_key
        ).first()
        
        if not bucket:
            # Create new bucket with full capacity minus 1 (for this request)
            bucket = RateLimitBucket(
                bucket_key=bucket_key,
                tokens=capacity - 1,
                last_refill=now
            )
            self.db.add(bucket)
            self.db.commit()
            return False  # Not limited
        
        # Calculate token refill
        elapsed = (now - bucket.last_refill.replace(tzinfo=timezone.utc)).total_seconds()
        new_tokens = min(capacity, bucket.tokens + int(elapsed * refill_rate))
        
        if new_tokens >= 1:
            # Consume a token
            bucket.tokens = new_tokens - 1
            bucket.last_refill = now
            self.db.commit()
            return False  # Not limited
        else:
            # No tokens available
            return True  # Limited

    def increment_failed_login(self, identifier: str) -> int:
        """
        Increments failed login counter and returns current count.
        Counters older than 24 hours are reset.
        
        Args:
            identifier: Email or IP address
            
        Returns:
            Current failed attempt count
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=24)
        
        counter = self.db.query(FailedLoginCounter).filter(
            FailedLoginCounter.identifier == identifier
        ).first()
        
        if not counter:
            # Create new counter
            counter = FailedLoginCounter(
                identifier=identifier,
                count=1,
                first_attempt=now,
                last_attempt=now
            )
            self.db.add(counter)
            self.db.commit()
            return 1
        
        # Reset if older than 24 hours
        if counter.first_attempt.replace(tzinfo=timezone.utc) < cutoff:
            counter.count = 1
            counter.first_attempt = now
            counter.last_attempt = now
        else:
            counter.count += 1
            counter.last_attempt = now
        
        self.db.commit()
        return counter.count

    def reset_failed_login(self, identifier: str):
        """
        Resets failed login counter after successful login.
        
        Args:
            identifier: Email or IP address
        """
        self.db.query(FailedLoginCounter).filter(
            FailedLoginCounter.identifier == identifier
        ).delete()
        self.db.commit()

    def is_account_locked(self, identifier: str) -> bool:
        """
        Checks if an account/IP is temporarily locked.
        Also cleans up expired lockouts.
        
        Args:
            identifier: Email or IP address
            
        Returns:
            True if locked, False otherwise
        """
        now = datetime.now(timezone.utc)
        
        lockout = self.db.query(AccountLockout).filter(
            AccountLockout.identifier == identifier
        ).first()
        
        if not lockout:
            return False
        
        # Check if lockout has expired
        if lockout.locked_until.replace(tzinfo=timezone.utc) < now:
            # Expired - remove it
            self.db.delete(lockout)
            self.db.commit()
            return False
        
        return True

    def set_lockout(self, identifier: str, duration_minutes: int):
        """
        Sets a temporary lockout for an account/IP.
        
        Args:
            identifier: Email or IP address
            duration_minutes: How long to lock out
        """
        now = datetime.now(timezone.utc)
        locked_until = now + timedelta(minutes=duration_minutes)
        
        # Upsert lockout record
        lockout = self.db.query(AccountLockout).filter(
            AccountLockout.identifier == identifier
        ).first()
        
        if lockout:
            lockout.locked_until = locked_until
        else:
            lockout = AccountLockout(
                identifier=identifier,
                locked_until=locked_until
            )
            self.db.add(lockout)
        
        self.db.commit()

    def cleanup_expired(self):
        """
        Cleans up expired lockouts and old rate limit buckets.
        Call this periodically (e.g., via a background job or on startup).
        """
        now = datetime.now(timezone.utc)
        cutoff_24h = now - timedelta(hours=24)
        cutoff_1h = now - timedelta(hours=1)
        
        # Remove expired lockouts
        self.db.query(AccountLockout).filter(
            AccountLockout.locked_until < now
        ).delete()
        
        # Remove old failed login counters (older than 24 hours)
        self.db.query(FailedLoginCounter).filter(
            FailedLoginCounter.first_attempt < cutoff_24h
        ).delete()
        
        # Remove stale rate limit buckets (not used in 1 hour)
        self.db.query(RateLimitBucket).filter(
            RateLimitBucket.last_refill < cutoff_1h
        ).delete()
        
        self.db.commit()
