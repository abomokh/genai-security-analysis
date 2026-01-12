# Secure Auth & Session Management Library (Cryptocurrency Wallet)

## Student IDs
- **Student-1 ID:** 
- **Student-2 ID:** 

---

## 1. Design Explanation

### Authentication Flow
The library implements a multi-step secure authentication flow:
1. **Password Check**: Uses `Argon2id` (64MB, 3 iterations, 2 parallelism) for robust resistance against GPU/ASIC cracking.
2. **Breach Check**: Integrates with "Have I Been Pwned" API using k-anonymity to reject leaked passwords.
3. **MFA (TOTP)**: Required by default for all logins. Secrets are stored encrypted at rest using Fernet (AES-128-CBC) with key rotation support.
4. **Rate Limiting**: Uses a Redis-based **Token Bucket** algorithm, limiting by both IP and Account ID. Progressive lockouts (5m to 24h) prevent brute-force without allowing permanent DoS.

### MFA Integration
MFA is treated as a first-class citizen:
- **Default Enablement**: Automatically set up during registration.
- **Sensitive Actions**: Required for password changes, MFA setting modifications, and high-risk API calls.
- **Implementation**: Uses 6-digit codes with a 2-minute time step (more conservative than the standard 30s for better user experience in high-latency environments while maintaining security).

### Session Lifecycle
- **Storage**: Sessions are stored in SQLite (hashed session IDs) and validated against absolute (2h) and idle (10m) timeouts.
- **Rotation**: Session IDs are rotated every 2.5 minutes during active use to minimize the window for session hijacking.
- **Invalidation**: 
    - Full destruction on logout.
    - Automatic invalidation of ALL active sessions on password change or reset.
- **Security**: 
    - Cookies use `HttpOnly`, `Secure`, and `SameSite=Lax`.
    - Generic cookie name `id` to prevent fingerprinting.
    - `Cache-Control: no-store` headers on all responses containing session data.

### Protection Mechanisms
- **Device Fingerprinting**: Generates a SHA256 hash of `User-Agent`, `IP Subnet`, and `Language`. Validated on every request.
- **JTI Tracking**: JWTs use UUID-v4 JTIs, tracked in Redis to prevent replay attacks.
- **Credential Stuffing Defense**: Combines HIBP checks, AbuseIPDB reputation scoring (requiring MFA or blocking doubtful IPs), and geographic anomaly detection.

---

## 2. Security Trade-offs and Assumptions

1. **SQLite for Persistence**: Chosen for demonstration as requested. In a massive-scale production environment, PostgreSQL would be preferred for better concurrency.
2. **Redis Dependency**: The system assumes a highly available Redis instance. If Redis is down, rate limiting and JTI tracking will fail-open/closed depending on implementation (currently fails-open for UX, but could be configured otherwise for max security).
3. **Email Mocking**: The `EmailServiceInterface` is abstract. In production, this must be connected to a secure provider (e.g., SendGrid/AWS SES) using TLS.
4. **Time Step (2 min)**: We chose a 2-minute TOTP step to reduce support tickets due to clock drift on mobile devices, though 30-60s is technically more "secure".

---

## 3. Example Usage

```python
# Registration
POST /register
{
  "email": "user@example.com",
  "password": "SecurePassword123!" 
}

# Login (Step 1 & 2 combined)
POST /login
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "totp_code": "123456"
}

# Protected Resource
GET /me
Headers: Cookie: id=xyz...

# Logout
POST /logout
```

