from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session as DBSession
from auth_lib.models.models import User, VerificationToken, MFASetting, LoginAttempt
from auth_lib.core.security import hash_password, verify_password, generate_secure_token, hash_token
from auth_lib.core.config import settings
from auth_lib.services.external_api_service import ExternalSecurityService
from auth_lib.services.email_service import EmailServiceInterface
from auth_lib.services.mfa_service import MFAService

class AuthService:
    def __init__(self, db: DBSession, email_service: EmailServiceInterface):
        self.db = db
        self.email_service = email_service
        self.mfa_service = MFAService()

    def register_user(self, email: str, password: str) -> User:
        # 1. Complexity check
        if len(password) < 14 or len(password) > 128:
            raise ValueError("Password must be between 14 and 128 characters.")
        
        # 2. HIBP check
        if ExternalSecurityService.is_password_pwned(password):
            raise ValueError("This password has been found in a data breach. Please choose another.")
            
        # 3. Duplicate check
        if self.db.query(User).filter(User.email == email).first():
            raise ValueError("Email already registered.")
            
        # 4. Hash and save
        user = User(
            email=email,
            hashed_password=hash_password(password),
            is_verified=False
        )
        self.db.add(user)
        self.db.flush() # Get user ID
        
        # 5. Setup MFA by default
        mfa_secret = self.mfa_service.generate_new_totp_secret()
        mfa_setting = MFASetting(
            user_id=user.id,
            totp_secret_encrypted=self.mfa_service.encrypt_secret(mfa_secret)
        )
        self.db.add(mfa_setting)
        
        # 6. Verification token
        token = generate_secure_token(16) # 128 bits
        v_token = VerificationToken(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            type='email_verification'
        )
        self.db.add(v_token)
        self.db.commit()
        
        # 7. Send email
        self.email_service.send_verification_email(email, token)
        
        return user

    def verify_email(self, token: str) -> bool:
        token_hash = hash_token(token)
        v_token = self.db.query(VerificationToken).filter(
            VerificationToken.token_hash == token_hash,
            VerificationToken.is_used == False,
            VerificationToken.type == 'email_verification'
        ).first()
        
        if not v_token or v_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            return False
            
        user = self.db.query(User).get(v_token.user_id)
        user.is_verified = True
        v_token.is_used = True
        self.db.commit()
        return True

    def authenticate_step1(self, email: str, password: str, ip_address: str) -> User:
        """First step of authentication: Password check."""
        user = self.db.query(User).filter(User.email == email).first()
        
        # Record attempt
        attempt = LoginAttempt(email=email, ip_address=ip_address)
        self.db.add(attempt)
        
        if not user or not verify_password(user.hashed_password, password):
            attempt.was_successful = False
            self.db.commit()
            return None
            
        attempt.was_successful = True
        self.db.commit()
        return user

    def initiate_password_reset(self, email: str):
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            return # Don't reveal if user exists

        token = generate_secure_token(16)
        r_token = VerificationToken(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            type='password_reset'
        )
        self.db.add(r_token)
        self.db.commit()
        self.email_service.send_password_reset_email(email, token)

    def complete_password_reset(self, token: str, new_password: str, totp_code: str):
        token_hash = hash_token(token)
        r_token = self.db.query(VerificationToken).filter(
            VerificationToken.token_hash == token_hash,
            VerificationToken.is_used == False,
            VerificationToken.type == 'password_reset'
        ).first()
        
        if not r_token or r_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise ValueError("Invalid or expired reset token.")
            
        user = self.db.query(User).get(r_token.user_id)
        
        # Require MFA for password reset
        if not self.mfa_service.verify_totp(user.mfa.totp_secret_encrypted, totp_code):
            raise ValueError("Invalid MFA code.")

        if len(new_password) < 14:
            raise ValueError("Password too short.")
            
        if ExternalSecurityService.is_password_pwned(new_password):
            raise ValueError("Password is pwned.")
            
        user.hashed_password = hash_password(new_password)
        user.last_password_change = datetime.now(timezone.utc)
        r_token.is_used = True
        self.db.commit()
        return user

