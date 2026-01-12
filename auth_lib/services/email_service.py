import abc
import logging

logger = logging.getLogger(__name__)

class EmailServiceInterface(abc.ABC):
    @abc.abstractmethod
    def send_verification_email(self, email: str, token: str):
        pass

    @abc.abstractmethod
    def send_password_reset_email(self, email: str, token: str):
        pass

    @abc.abstractmethod
    def send_security_alert(self, email: str, message: str):
        pass

class MockEmailService(EmailServiceInterface):
    def send_verification_email(self, email: str, token: str):
        logger.info(f"MOCK EMAIL: Sending verification to {email}. Token: {token}")
        print(f"\n[EMAIL MOCK] Verification for {email}: {token}\n")

    def send_password_reset_email(self, email: str, token: str):
        logger.info(f"MOCK EMAIL: Sending password reset to {email}. Token: {token}")
        print(f"\n[EMAIL MOCK] Password Reset for {email}: {token}\n")

    def send_security_alert(self, email: str, message: str):
        logger.info(f"MOCK EMAIL: Sending security alert to {email}. Message: {message}")
        print(f"\n[SECURITY ALERT] for {email}: {message}\n")

