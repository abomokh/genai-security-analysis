import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from auth_lib.core.security import generate_device_fingerprint, hash_token
from auth_lib.core.config import settings
from auth_lib.db.database import SessionLocal
from auth_lib.models.models import Session
from datetime import datetime, timezone, timedelta

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. Device Fingerprinting
        ua = request.headers.get("user-agent", "")
        ip_parts = request.client.host.split('.')
        ip_subnet = ".".join(ip_parts[:3]) if len(ip_parts) == 4 else request.client.host
        lang = request.headers.get("accept-language", "")
        
        fingerprint = generate_device_fingerprint(ua, ip_subnet, lang)
        request.state.device_fingerprint = fingerprint

        # 2. Session Rotation and Timing Check
        session_id = request.cookies.get("id")
        new_session_id = None
        
        if session_id:
            db = SessionLocal()
            try:
                session_hash = hash_token(session_id)
                db_session = db.query(Session).filter(Session.session_id_hash == session_hash).first()
                
                if db_session:
                    now = datetime.now(timezone.utc)
                    # Check if it's time to rotate (2.5 minutes)
                    elapsed = (now - db_session.created_at.replace(tzinfo=timezone.utc)).total_seconds()
                    if elapsed > settings.SESSION_ROTATION_INTERVAL:
                        from auth_lib.services.session_service import SessionService
                        svc = SessionService(db)
                        new_session_id = svc.rotate_session(session_id)
            finally:
                db.close()

        response: Response = await call_next(request)

        # 3. Security Headers
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        # 4. Set rotated session cookie if needed
        if new_session_id:
            response.set_cookie(
                key="id",
                value=new_session_id,
                httponly=True,
                secure=True,
                samesite="lax"
            )
            
        return response

