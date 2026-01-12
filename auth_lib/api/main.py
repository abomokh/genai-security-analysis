from fastapi import FastAPI, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session
from auth_lib.db.database import get_db, init_db
from auth_lib.api import deps
from auth_lib.schemas import schemas
from auth_lib.services.auth_service import AuthService
from auth_lib.services.session_service import SessionService
from auth_lib.services.rate_limit_service import RateLimitService
from auth_lib.middleware.security_middleware import SecurityMiddleware
from auth_lib.core.config import settings

app = FastAPI(title="Secure Crypto Wallet Auth API")

# Add Security Middleware
app.add_middleware(SecurityMiddleware)

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/register", response_model=schemas.UserResponse)
def register(
    user_data: schemas.UserCreate,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(deps.get_auth_service)
):
    try:
        user = auth_service.register_user(user_data.email, user_data.password)
        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
def login(
    login_data: schemas.MFALogin,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(deps.get_auth_service),
    session_service: SessionService = Depends(deps.get_session_service),
    rate_limit: RateLimitService = Depends(deps.get_rate_limit_service)
):
    # 1. Rate Limiting check
    ip = request.client.host
    if rate_limit.is_account_locked(login_data.email) or rate_limit.is_account_locked(ip):
        raise HTTPException(status_code=429, detail="Account or IP locked. Please try again later.")

    # 2. Authenticate
    user = auth_service.authenticate_step1(login_data.email, login_data.password, ip)
    if not user:
        count = rate_limit.increment_failed_login(login_data.email)
        rate_limit.increment_failed_login(ip)
        
        if count >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            # Progressive lockout logic
            lockout_idx = min(count - settings.MAX_FAILED_LOGIN_ATTEMPTS, len(settings.LOCKOUT_DURATION_MINUTES) - 1)
            duration = settings.LOCKOUT_DURATION_MINUTES[lockout_idx]
            rate_limit.set_lockout(login_data.email, duration)
            rate_limit.set_lockout(ip, duration)
            
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 3. MFA Verification (Required by default)
    if not auth_service.mfa_service.verify_totp(user.mfa.totp_secret_encrypted, login_data.totp_code):
        rate_limit.increment_failed_login(login_data.email)
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # 4. Successful Login - Reset counters
    rate_limit.reset_failed_login(login_data.email)
    
    # 5. Create Session
    session_id, _ = session_service.create_session(
        user.id, 
        device_fingerprint=request.state.device_fingerprint
    )
    
    # 6. Set Secure Cookie
    response.set_cookie(
        key="id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    
    return {"message": "Login successful"}

@app.post("/logout")
def logout(
    response: Response,
    request: Request,
    session_service: SessionService = Depends(deps.get_session_service)
):
    session_id = request.cookies.get("id")
    if session_id:
        session_service.delete_session(session_id)
        
    response.delete_cookie("id")
    return {"message": "Logged out"}

@app.post("/password-reset/request")
def request_password_reset(
    data: schemas.PasswordResetRequest,
    auth_service: AuthService = Depends(deps.get_auth_service)
):
    auth_service.initiate_password_reset(data.email)
    return {"message": "If the account exists, a reset email has been sent."}

@app.post("/password-reset/confirm")
def confirm_password_reset(
    data: schemas.PasswordResetConfirm,
    auth_service: AuthService = Depends(deps.get_auth_service),
    session_service: SessionService = Depends(deps.get_session_service)
):
    try:
        user = auth_service.complete_password_reset(data.token, data.new_password, data.totp_code)
        # Invalidate all sessions on password reset
        session_service.invalidate_all_user_sessions(user.id)
        return {"message": "Password reset successful. All sessions invalidated."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/me", response_model=schemas.UserResponse)
def get_me(user = Depends(deps.get_current_user)):
    return user

