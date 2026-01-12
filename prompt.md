# Introduction
You are a senior security-focused backend engineer.
Your task is to generate a secure, production-grade authentication and session
management library for server-side applications.
The library will later be audited for security vulnerabilities, so correctness,
clarity, and adherence to security best practices are critical.

# Details

## 1. Context:

**Student-1 ID:** [REMOVED].
**Student-2 ID:** [REMOVED].

**Assigned Application Context:** A server-side authentication and session management library for a **cryptocurrency wallet app** supporting both web and mobile backend clients.


## 2. Technical Scope
**Programming language:** mainly python

**Target usage:**
- Server-side web applications
- Server-side mobile backends (REST APIs)

**Non-goals:**
- No frontend or UI code
- No blockchain or transaction-signing logic
- No client-side secret storage
- No wallet key management logic

## 3. Authentication requirements
The library MUST implement secure authentication mechanisms suitable for a high-risk, high-value cryptocurrency wallet environment.

Authentication requirements include:

1. **Secure password hashing:**
   - Use `Argon2id` as the password hashing algorithm, with the following configuration:
      - memory cost: 64 MB.
      - time cost: 3 iterations.
      - Parallelism: 2.
   - Password hashes must never be logged or exposed


2. **Password complexity policy enforcement:**
   - Enforce a password length between 14 - 128 characters.
   - Do NOT enforce arbitrary complexity rules such as mandatory symbols.
   - Reject passwords found in known data breaches using `"Have I Been Pwned" API`.
   - Enforce this policy at both registration and password reset.

3. **Multi-Factor Authentication:**
   - MFA MUST be supported and enabled by default.
   - Implement Time-based One-Time Passwords (TOTP) with 6-digit codes and 30-seconds time step.
   - Securely generate TOTP (cryptographically random).
   - Securely store TOTP secrets (encrypted at rest).
   - MFA must be required for both login and sensitive account actions (e.g. Changing account password, Enabling, disabling, or modifying 2FA methods, Adding or removing trusted devices, Adding, changing, or removing recovery email or phone).
   - MFA should be Required during high-risk scenarios, such as logins from a new device or unusual location, or when performing high-risk activities.
   - MFA should support explicit invoking (asking for MFA on demand) for high-risk app-spesific activities (e.g. large currency transactions).

4. **Brute-force login protection:**
   - Implement protection against repeated failed login attempts by Enforcing rate limiting based on IP address and Account identifier.
   - Lock accounts temporarily after a configurable number of failed attempts. Use configurable progressive lockout durations.
   - Reset failed-attempt counters after successful authentication.
   - Ensure protections do not allow permanent denial-of-service attacks.

5. **Email-Based account verification flow:**
   - Implement an email-based account verification mechanism.
   - Generate verification tokens that are cryptographically random.
   - Tokens must be 128 bits and must be single-use.
   - Expire after a time window of 10 minutes.
   - Store verification tokens hashed (not in plaintext).
   - Require successful verification before enabling wallet functionality.


6. **Secure password reset mechanism:**
   - Implement a secure password reset flow using cryptographically-random, time-limited tokens.
   - Reset tokens must be 128 bits and must be single-use.
   - Expire Reset tokens after a duration of 5 minutes.
   - Store reset tokens hashed in persistent storage.
   - Rate-limit password reset requests.
   - Upon successful password reset: Invalidate all active sessions and Require MFA re-verification on next login.

7. **Protection against credential-stuffing:**
Implement layered defenses against credential-stuffing attacks:
- Breached-password detection: Reject passwords known from public breaches - Use `"Have I Been Pwned" API` (k-anonymity check).
- Rate limiting and lockouts: Limit repeated login attempts to stop automated guessing - Use: `Token Bucket Rate Limiter`.
- IP reputation: Requir MFA for Doubtful IPs - Use `AbuseIPDB` Reputation Scoring.
- geographic anomaly detection: Flag logins from unusual countries compared to user history.


## 4. Session management requirements
The library MUST implement secure session and token management appropriate for a high-value financial system.

Session management requirements include:

1. **Cryptographically secure random session ID generation:**
- Use CSPRNG for generating cryptographically-random session IDs.
- The length of session ID should be 128 bits.
- Use Base64 for URL-encoding.
- Session IDs MUST be generated ONLY BY THE SERVER.
- session IDs should Never derived from user data.
- session ID should be hashed before storing.
- Use generic name for the session-IDs (e.g. `id`) to prevent fingerprinting.

2. **Session expiration (absolute timeout):**
- Absolute lifetime should be 2 hours.
- Enforce this timeout on every request.
- Sessions should NOT be extendable in any way beyond this maximum lifetime.

3. **Idle session timeout:**
- Enforce sliding inactivity timeout Mechanism.
- Inactivity/Idle timeout should be 10 minutes.

4. **Session renewal/rotation after login:**
- Enforce Session renewal Mechanism.
- Renewal/Rotation interval should be 2.5 minutes.

5. **Secure logout and full session invalidation:**
   - loging-out should Delete session record from server. - Support `Logout from all devices`.
   - Logout should require valid CSRF protection.
   - Use `Cache-Control: no-store` in responses containing session IDs to ensure they are never cached by the browser.

6. **Automatic invalidation on password change:**
   - Upon successful password change, sessions should be Destructed and any previous session IDs must be destroyed.
   - Password Change should be treated as a high-risk. Thus, requiring MFA to complete the password change.

7. **Token-based authentication support - JWT:**
   - Support JWT with the use of cookies.
   - Insure you follow the security requirements for Cookies and token (specified bellow).


## 5. Cookie / token security requirements:
All authentication tokens and cookies MUST be handled securely.

Cookie/token security requirements include:

1. **Use HttpOnly, Secure, and SameSite attributes for cookies:**
   - HttpOnly=true.
   - Secure=true
   - SameSite=Lax.
2. **No localStorage for tokens:**
   - Do NOT store authentication tokens in localStorage.
3. **Short-lived access tokens:**
   - Use short-lived access tokens.
   - Use RS256.
   - Use UUID-v4 for JTI Claims.
4. **Secure refresh token handling:**
   - Implement refresh tokens with secure rotation and invalidation.
   - Refresh tokens MUST be single-use and rotated on every refresh operation.
   - When a refresh token is presented, it MUST be invalidated immediately and replaced with a newly generated token.
   - If a previously used refresh token is ever presented again, the system MUST treat this as a token compromise and invalidate all active sessions and refresh tokens for the affected user.
   - Refresh tokens should have 7-day expiry.
   - Refresh tokens should be stored in a persistent storage.
   - Make use to implement rotation counter tracking and immediate invalidation mechanism.

5. **Prevent token reuse and replay attacks:**
   - Use the following "Triple Layer" defence mecahmisim:
      - *JTI Tracking:* Redis-based, millisecond latency, -   Auto-cleanup when token expires.
      - *Device Fingerprinting:* SHA256(user-agent + IP-subnet + language), validate device hasn't changed, and alert if mismatch detected. 
      - *Request Nonce:* For high-risk operations, request one-time use per request.

## 6. Strict forbidden elements

The implementation **MUST NOT** include:

- **Hard-coded secrets or credentials:** secrets (such as Passwords, API keys, encryption keys, JWT keys, salts, or credentials) MUST NEVER be embedded directly in the code or in a config files. Additionally, secrets should not appear in log files unless they are encrypted. Use environment variables insted.
- **Plaintext password storage:** you MUST NEVER save or log plaintext passwords anywhere. (use Argon2id as specified earlier).
- **MD5 or SHA-1 hashing:** you MUST NEVER using these two methods.
- **Weak or predictable random values:** you MUST NEVER use predictable random values (such as Math.random()). Instead, ONLY use cryptographically random values.
- **Infinite-lifetime tokens or sessions**: tokens or sessions MUST NEVER have Infinite-lifetime.
- **Static encryption keys:** encryption keys MUST NEVER be static - a rotation mechanism should be implemented instead. Keep old invalid keys for 90 days.
- **Client-side storage of authentication tokens:**  you MUST NOT allow for Client-side storage of authentication tokens.

## 7. Additional Clarifications

* **database:** Use SQLite as the primary database.
* **Redis:** is required and available (use it for rate limiting, JTI tracking, nonces, and session invalidation).
* **Email service:** Provide an abstract email interface just for code/logic review.
* **Docker / deployment:** is out of scope.
* **Example usage:** Use FastAPI for demonstration.
* **Logging:** Implement logging whereever needed.

## 8.Code Quality & Documentation Requirements
The code MUST be:

- Clean, modular, and well-structured.
- Clearly separated into logical components.
- Fully documented, especially for security-sensitive logic.
- Free of placeholder or TODO security code.
- Written as production-quality backend code.

## 9. Required Deliverables

You MUST provide:

1. The **complete source code** of the authentication and session management library
2. **Example usage code** demonstrating:
   - User registration
   - Login with MFA
   - Session creation and validation
   - Logout
   - Password reset
3. A detailed **design explanation** describing:
   - Authentication flow
   - MFA integration
   - Session lifecycle
   - Security trade-offs and assumptions

## 10. Security Expectations
- Assume the system is a high-value target under active attack.
- Design defensively.
- When trade-offs exist, prioritize security over convenience.

# Action
Generate the complete implementation and explanation in a single response.

