import hashlib
import requests
import logging
from auth_lib.core.config import settings

logger = logging.getLogger(__name__)

class ExternalSecurityService:
    @staticmethod
    def is_password_pwned(password: str) -> bool:
        """Checks if a password has been leaked using HIBP k-anonymity API."""
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count) > 0
            return False
        except Exception as e:
            logger.error(f"HIBP API error: {e}")
            # Fail-safe: In case of API error, we might want to allow or deny. 
            # High-risk: Deny. But for UX, we might allow if the service is down.
            return False

    @staticmethod
    def get_ip_reputation(ip_address: str) -> int:
        """Gets IP reputation score from AbuseIPDB (0-100)."""
        if not settings.ABUSEIPDB_API_KEY:
            return 0 # Default to 0 if not configured
            
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': settings.ABUSEIPDB_API_KEY
        }
        
        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            response.raise_for_status()
            data = response.json()
            return data['data']['abuseConfidenceScore']
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")
            return 0

    @staticmethod
    def check_geographic_anomaly(ip_address: str, user_history: list[str]) -> bool:
        """Checks if the IP is from an unusual country compared to user history."""
        # In a real app, use GeoIP2 or an external API
        # Placeholder logic:
        return False 

