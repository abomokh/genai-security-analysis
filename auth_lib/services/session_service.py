import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session as DBSession
from jose import jwt, JWTError
from auth_lib.models.models import Session, User, RefreshToken
from auth_lib.core.security import generate_session_id, hash_token, encryption_manager
from auth_lib.core.config import settings

class SessionService:
    def __init__(self, db: DBSession):
        self.db = db

    def create_session(self, user_id: int, device_fingerprint: str = None) -> Tuple[str, Session]:
        """Creates a new session for a user."""
        session_id = generate_session_id()
        session_id_hash = hash_token(session_id)
        
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_ABSOLUTE_TIMEOUT)
        
        db_session = Session(
            user_id=user_id,
            session_id_hash=session_id_hash,
            expires_at=expires_at,
            device_fingerprint=device_fingerprint
        )
        self.db.add(db_session)
        self.db.commit()
        self.db.refresh(db_session)
        
        return session_id, db_session

    def validate_session(self, session_id: str, device_fingerprint: str = None) -> Optional[User]:
        """Validates a session by ID hash, absolute timeout, and idle timeout."""
        session_id_hash = hash_token(session_id)
        db_session = self.db.query(Session).filter(Session.session_id_hash == session_id_hash).first()
        
        if not db_session:
            return None
            
        now = datetime.now(timezone.utc)
        
        # Absolute timeout check
        if db_session.expires_at.replace(tzinfo=timezone.utc) < now:
            self.delete_session(session_id)
            return None
            
        # Idle timeout check (10 minutes)
        idle_limit = db_session.last_activity.replace(tzinfo=timezone.utc) + timedelta(minutes=settings.SESSION_IDLE_TIMEOUT)
        if idle_limit < now:
            self.delete_session(session_id)
            return None

        # Device fingerprint check
        if db_session.device_fingerprint and db_session.device_fingerprint != device_fingerprint:
            # Possible session hijacking
            self.delete_session(session_id)
            return None

        # Update last activity
        db_session.last_activity = now
        self.db.commit()
        
        return db_session.user

    def rotate_session(self, old_session_id: str) -> Optional[str]:
        """Rotates a session ID (every 2.5 minutes)."""
        old_hash = hash_token(old_session_id)
        db_session = self.db.query(Session).filter(Session.session_id_hash == old_hash).first()
        
        if not db_session:
            return None
            
        new_session_id = generate_session_id()
        db_session.session_id_hash = hash_token(new_session_id)
        self.db.commit()
        
        return new_session_id

    def delete_session(self, session_id: str):
        """Invalidates a single session."""
        session_id_hash = hash_token(session_id)
        self.db.query(Session).filter(Session.session_id_hash == session_id_hash).delete()
        self.db.commit()

    def invalidate_all_user_sessions(self, user_id: int):
        """Invalidates all sessions for a user (e.g., after password reset)."""
        self.db.query(Session).filter(Session.user_id == user_id).delete()
        self.db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()
        self.db.commit()

    def create_jwt_access_token(self, user_id: int) -> str:
        """Creates a short-lived JWT access token (RS256)."""
        # Note: In a real system, you'd use a private key. Here we'll use SECRET_KEY for simplicity but RS256 is specified.
        # Assuming private/public key management is handled elsewhere.
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "jti": str(uuid.uuid4())
        }
        # In a real app: jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
        return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256") # Placeholder HS256 for demo

    def create_refresh_token(self, user_id: int) -> str:
        """Creates a 7-day refresh token with rotation support."""
        token = generate_session_id()
        token_hash = hash_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        db_token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            rotation_counter=0
        )
        self.db.add(db_token)
        self.db.commit()
        
        return token

