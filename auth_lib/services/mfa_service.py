import pyotp
from auth_lib.core.security import encryption_manager, generate_secure_token
from auth_lib.core.config import settings

class MFAService:
    @staticmethod
    def generate_new_totp_secret() -> str:
        """Generates a new base32 TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_instance(secret: str) -> pyotp.TOTP:
        """Returns a TOTP instance with the configured time step and digits."""
        return pyotp.TOTP(
            secret, 
            interval=settings.TOTP_STEP, 
            digits=settings.TOTP_DIGITS
        )

    def verify_totp(self, secret_encrypted: str, code: str) -> bool:
        """Decrypts the secret and verifies the 6-digit TOTP code."""
        secret = encryption_manager.decrypt(secret_encrypted)
        totp = self.get_totp_instance(secret)
        # Allows a small window for clock skew (1 step)
        return totp.verify(code, valid_window=1)

    def encrypt_secret(self, secret: str) -> str:
        """Encrypts the TOTP secret for storage."""
        return encryption_manager.encrypt(secret)

