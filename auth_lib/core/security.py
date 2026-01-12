import secrets
import base64
import hashlib
from typing import Optional, Tuple
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, MultiFernet
from auth_lib.core.config import settings

# Argon2id setup
ph = PasswordHasher(
    memory_cost=settings.ARGON2_MEMORY_COST,
    time_cost=settings.ARGON2_TIME_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    type=Type.ID
)

def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    return ph.hash(password)

def verify_password(hashed_password: str, password: str) -> bool:
    """Verifies a password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False

def verify_password(hashed_password: str, password: str) -> tuple[bool, bool]:
    try:
        ph.verify(hashed_password, password)
        needs_rehash = ph.check_needs_rehash(hashed_password)
        return True, needs_rehash
    except VerifyMismatchError:
        return False, False

def generate_secure_token(nbytes: int = 16) -> str:
    """Generates a CSPRNG cryptographically-secure random token (128 bits default)."""
    return secrets.token_urlsafe(nbytes)

def hash_token(token: str) -> str:
    """Hashes a token for secure storage (e.g., session IDs, verification tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()

class EncryptionManager:
    """Handles encryption and decryption with key rotation support."""
    def __init__(self, keys: list[str]):
        # keys[0] is the primary (newest) key
        self.fernets = [Fernet(k.encode() if isinstance(k, str) else k) for k in keys]
        self.multi_fernet = MultiFernet(self.fernets)

    def encrypt(self, data: str) -> str:
        if not data:
            return ""
        return self.multi_fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        if not encrypted_data:
            return ""
        return self.multi_fernet.decrypt(encrypted_data.encode()).decode()

# Global encryption manager (should be initialized with real keys from env/secrets manager)
# In production, this would load multiple keys for rotation (up to 90 days)
encryption_manager = EncryptionManager([settings.ENCRYPTION_KEY_LATEST])

def generate_session_id() -> str:
    """Generates a 128-bit session ID, Base64 URL-encoded."""
    # 128 bits = 16 bytes
    return secrets.token_urlsafe(16)

def generate_device_fingerprint(user_agent: str, ip_subnet: str, language: str) -> str:
    """Generates a SHA256 fingerprint of device-specific headers."""
    fingerprint_str = f"{user_agent}|{ip_subnet}|{language}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

