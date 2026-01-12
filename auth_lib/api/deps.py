from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from auth_lib.db.database import get_db
from auth_lib.services.auth_service import AuthService
from auth_lib.services.session_service import SessionService
from auth_lib.services.email_service import MockEmailService
from auth_lib.services.rate_limit_service import RateLimitService


def get_auth_service(db: Session = Depends(get_db)):
    return AuthService(db, MockEmailService())


def get_session_service(db: Session = Depends(get_db)):
    return SessionService(db)


def get_rate_limit_service(db: Session = Depends(get_db)):
    """Rate limiting service using SQLite (no Redis dependency)."""
    return RateLimitService(db)


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    session_service: SessionService = Depends(get_session_service)
):
    session_id = request.cookies.get("id")  # Generic name 'id'
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get fingerprint components
    ua = request.headers.get("user-agent", "")
    ip = request.client.host
    lang = request.headers.get("accept-language", "")
    # Fingerprint check is done in middleware or session service
    # For now, just validate
    user = session_service.validate_session(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Session invalid or expired")
    
    return user
