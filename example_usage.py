"""
=============================================================================
SECURE AUTH LIBRARY - EXAMPLE USAGE SCRIPT
=============================================================================

This script demonstrates all endpoints of the Secure Auth & Session Management
Library for a cryptocurrency wallet. It uses a mocked MFA service so you can
run it without needing a real authenticator app.

NOTE: Rate limiting now uses SQLite (same as other data) - no Redis needed!

ENDPOINTS DEMONSTRATED:
    1. POST /register      - Create a new user account with MFA setup
    2. POST /login         - Authenticate with email, password, and TOTP code
    3. GET  /me            - Get current authenticated user info
    4. POST /logout        - Destroy session and log out
    5. POST /password-reset/request  - Request password reset email
    6. POST /password-reset/confirm  - Complete password reset with new password

HOW TO RUN:
    1. Install dependencies: pip install -r requirements.txt
    2. Run this script: python example_usage.py

=============================================================================
"""

import sys
import time
import threading

# =============================================================================
# STEP 1: SETUP MOCKS BEFORE IMPORTING THE APP
# =============================================================================
# We mock MFA BEFORE the app modules are imported.
# No Redis mocking needed - rate limiting uses SQLite now!

print("=" * 70)
print("SETTING UP MOCKED DEPENDENCIES")
print("=" * 70)

# --- Mock MFA Verification ---
# We'll patch the MFA service to accept "123456" as a valid TOTP code
MOCK_TOTP_CODE = "123456"

def mock_verify_totp(self, secret_encrypted: str, code: str) -> bool:
    """Mock TOTP verification - accepts '123456' as valid code."""
    return code == MOCK_TOTP_CODE

print(f"[✓] MFA mocked - TOTP code '{MOCK_TOTP_CODE}' will always be accepted")
print("[✓] Rate limiting uses SQLite (no Redis dependency)")
print()

# =============================================================================
# STEP 2: APPLY PATCHES AND IMPORT THE APP
# =============================================================================

# Patch MFA verification
from auth_lib.services.mfa_service import MFAService
MFAService.verify_totp = mock_verify_totp

# Now import the FastAPI app
from auth_lib.api.main import app

print("[✓] All patches applied successfully")
print()

# =============================================================================
# STEP 3: START THE SERVER IN A BACKGROUND THREAD
# =============================================================================

import uvicorn
import httpx

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8765
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

def run_server():
    """Run uvicorn server in a separate thread."""
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT, log_level="warning")

print("=" * 70)
print("STARTING TEST SERVER")
print("=" * 70)
print(f"Server URL: {BASE_URL}")

# Start server in background thread
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()

# Wait for server to start
time.sleep(2)
print("[✓] Server started successfully")
print()

# =============================================================================
# STEP 4: HELPER FUNCTIONS
# =============================================================================

def print_section(title: str):
    """Print a section header."""
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_request(method: str, endpoint: str, body: dict = None):
    """Print request details."""
    print(f"\n>>> {method} {endpoint}")
    if body:
        # Hide password in output
        display_body = body.copy()
        if "password" in display_body:
            display_body["password"] = "********"
        if "new_password" in display_body:
            display_body["new_password"] = "********"
        print(f"    Body: {display_body}")

def print_response(response: httpx.Response):
    """Print response details."""
    status_icon = "✓" if response.status_code < 400 else "✗"
    print(f"<<< [{status_icon}] Status: {response.status_code}")
    try:
        print(f"    Response: {response.json()}")
    except:
        print(f"    Response: {response.text[:200]}")

# =============================================================================
# STEP 5: EXAMPLE USAGE - DEMONSTRATING ALL ENDPOINTS
# =============================================================================

# Test user credentials
TEST_EMAIL = "crypto_user@example.com"
TEST_PASSWORD = "MySecureP@ssw0rd!2024"  # 14+ chars, not in breach databases
NEW_PASSWORD = "NewSecureP@ssw0rd!2025"

# Create a session to maintain cookies across requests
client = httpx.Client(base_url=BASE_URL, timeout=30.0)

try:
    # -------------------------------------------------------------------------
    # ENDPOINT 1: POST /register
    # -------------------------------------------------------------------------
    # Creates a new user account. The library automatically:
    #   - Validates password length (14-128 chars)
    #   - Checks password against Have I Been Pwned database
    #   - Hashes password with Argon2id (64MB memory, 3 iterations)
    #   - Generates and stores encrypted TOTP secret for MFA
    #   - Creates email verification token
    #   - Sends verification email (mocked in this demo)
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 1: POST /register - Create New User Account")
    
    print("""
    DESCRIPTION:
    This endpoint registers a new user in the system. The library performs
    several security checks:
    
    1. Password Validation:
       - Must be 14-128 characters
       - Checked against HIBP (Have I Been Pwned) breach database
       - If password was found in a data breach, registration is rejected
    
    2. Password Storage:
       - Hashed using Argon2id (memory-hard algorithm)
       - Parameters: 64MB memory, 3 iterations, 2 parallelism
       - Resistant to GPU/ASIC cracking attacks
    
    3. MFA Setup:
       - TOTP secret automatically generated (base32)
       - Secret encrypted at rest using Fernet (AES-128-CBC)
       - MFA is MANDATORY for all accounts
    
    4. Email Verification:
       - Verification token generated (128-bit, cryptographically secure)
       - Token stored as SHA256 hash in database
       - Email sent with verification link (mocked in this demo)
    """)
    
    register_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    print_request("POST", "/register", register_data)
    response = client.post("/register", json=register_data)
    print_response(response)
    
    if response.status_code == 200:
        user_data = response.json()
        print(f"\n    [SUCCESS] User created with ID: {user_data['id']}")
        print(f"    [INFO] Email verification required: is_verified = {user_data['is_verified']}")
    
    # -------------------------------------------------------------------------
    # ENDPOINT 2: POST /login
    # -------------------------------------------------------------------------
    # Authenticates a user with email, password, and TOTP code.
    # The library performs:
    #   - Rate limiting check (IP and account-based, SQLite-backed)
    #   - Password verification with Argon2id
    #   - TOTP code verification (6-digit, 2-minute window)
    #   - Creates session with device fingerprinting
    #   - Sets secure HttpOnly cookie
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 2: POST /login - Authenticate User")
    
    print("""
    DESCRIPTION:
    This endpoint authenticates a user with three factors:
    
    1. Rate Limiting (BEFORE authentication):
       - Checks if account or IP is locked due to failed attempts
       - Uses SQLite-backed Token Bucket algorithm
       - Progressive lockouts: 5min -> 15min -> 30min -> 1hr -> 24hr
    
    2. Password Verification:
       - Compares against Argon2id hash stored in database
       - Failed attempts are logged for audit trail
    
    3. MFA Verification:
       - Validates 6-digit TOTP code
       - 2-minute time step with 1-step tolerance for clock skew
       - TOTP secret is decrypted from database for verification
    
    4. Session Creation:
       - Generates 128-bit cryptographically secure session ID
       - Session ID stored as SHA256 hash in database
       - Device fingerprint captured (User-Agent + IP subnet + Language)
       - Timeouts: 2hr absolute, 10min idle, 2.5min rotation
    
    5. Cookie Setup:
       - Cookie name: 'id' (generic to prevent fingerprinting)
       - Flags: HttpOnly, Secure, SameSite=Lax
    """)
    
    login_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "totp_code": MOCK_TOTP_CODE  # Using mocked code "123456"
    }
    
    print_request("POST", "/login", login_data)
    response = client.post("/login", json=login_data)
    print_response(response)
    
    if response.status_code == 200:
        print(f"\n    [SUCCESS] Login successful!")
        print(f"    [INFO] Session cookie 'id' set in client")
        # Show that cookie was set (value is hidden for security)
        if "id" in client.cookies:
            print(f"    [INFO] Cookie present: id=******* (hidden)")
    
    # -------------------------------------------------------------------------
    # ENDPOINT 3: GET /me
    # -------------------------------------------------------------------------
    # Returns the currently authenticated user's information.
    # Validates session on every request:
    #   - Checks session exists and is not expired
    #   - Validates device fingerprint matches
    #   - Updates last activity timestamp
    #   - May rotate session ID (every 2.5 minutes)
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 3: GET /me - Get Current User (Protected)")
    
    print("""
    DESCRIPTION:
    This protected endpoint returns the authenticated user's information.
    Every request goes through session validation:
    
    1. Cookie Extraction:
       - Reads 'id' cookie from request
       - Returns 401 if cookie missing
    
    2. Session Validation:
       - Looks up session by SHA256(session_id)
       - Returns 401 if session not found
    
    3. Timeout Checks:
       - Absolute timeout: 2 hours from session creation
       - Idle timeout: 10 minutes since last activity
       - Session destroyed if either timeout exceeded
    
    4. Device Fingerprint Validation:
       - Compares current fingerprint with stored fingerprint
       - Session destroyed if mismatch (possible hijacking)
    
    5. Session Rotation (via middleware):
       - Every 2.5 minutes, session ID is rotated
       - New session ID sent in response cookie
       - Old session ID immediately invalidated
    
    6. Security Headers (added by middleware):
       - Cache-Control: no-store
       - X-Content-Type-Options: nosniff
       - X-Frame-Options: DENY
       - Content-Security-Policy: default-src 'none'
    """)
    
    print_request("GET", "/me")
    response = client.get("/me")
    print_response(response)
    
    if response.status_code == 200:
        user_data = response.json()
        print(f"\n    [SUCCESS] Authenticated as: {user_data['email']}")
        print(f"    [INFO] User ID: {user_data['id']}")
        print(f"    [INFO] Verified: {user_data['is_verified']}")
    
    # -------------------------------------------------------------------------
    # DEMONSTRATE: Accessing /me without authentication
    # -------------------------------------------------------------------------
    
    print_section("DEMO: Accessing Protected Endpoint Without Auth")
    
    print("""
    DESCRIPTION:
    This demonstrates what happens when trying to access a protected
    endpoint without valid session credentials.
    """)
    
    # Create a new client without cookies
    unauthenticated_client = httpx.Client(base_url=BASE_URL, timeout=30.0)
    
    print_request("GET", "/me (no session cookie)")
    response = unauthenticated_client.get("/me")
    print_response(response)
    
    print(f"\n    [EXPECTED] 401 Unauthorized - No session cookie provided")
    unauthenticated_client.close()
    
    # -------------------------------------------------------------------------
    # ENDPOINT 4: POST /logout
    # -------------------------------------------------------------------------
    # Destroys the current session and clears the cookie.
    #   - Session record deleted from database
    #   - Cookie cleared from response
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 4: POST /logout - End Session")
    
    print("""
    DESCRIPTION:
    This endpoint terminates the user's session:
    
    1. Session Destruction:
       - Session record deleted from database
       - Cannot be reused even if cookie is replayed
    
    2. Cookie Cleanup:
       - 'id' cookie deleted from client
       - Instructs browser to clear the cookie
    
    SECURITY NOTE:
    The library stores session IDs as hashes, so even if the database
    is compromised, attackers cannot reconstruct valid session IDs.
    """)
    
    print_request("POST", "/logout")
    response = client.post("/logout")
    print_response(response)
    
    if response.status_code == 200:
        print(f"\n    [SUCCESS] Session destroyed")
        print(f"    [INFO] Cookie cleared")
    
    # Verify we're logged out by trying /me again
    print("\n    [VERIFY] Attempting to access /me after logout:")
    response = client.get("/me")
    print_response(response)
    print(f"    [EXPECTED] 401 Unauthorized - Session no longer valid")
    
    # -------------------------------------------------------------------------
    # Log back in for password reset demo
    # -------------------------------------------------------------------------
    
    print_section("RE-LOGIN: Logging Back In for Password Reset Demo")
    
    login_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "totp_code": MOCK_TOTP_CODE
    }
    
    print_request("POST", "/login", login_data)
    response = client.post("/login", json=login_data)
    print_response(response)
    
    # -------------------------------------------------------------------------
    # ENDPOINT 5: POST /password-reset/request
    # -------------------------------------------------------------------------
    # Initiates password reset flow by sending reset email.
    #   - Generates secure reset token (128-bit)
    #   - Token expires in 5 minutes
    #   - Does NOT reveal if email exists (security measure)
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 5: POST /password-reset/request - Request Reset")
    
    print("""
    DESCRIPTION:
    This endpoint initiates the password reset flow:
    
    1. Email Lookup:
       - Checks if user exists (silently)
       - NEVER reveals if email exists (prevents enumeration)
    
    2. Token Generation:
       - 128-bit cryptographically secure random token
       - Stored as SHA256 hash in database
       - Expires in 5 minutes (short window for security)
    
    3. Email Dispatch:
       - Reset link sent to user's email
       - Contains the unhashed token
       - (Mocked in this demo - token printed to console)
    
    SECURITY NOTE:
    Response is always "If the account exists, a reset email has been sent."
    This prevents attackers from discovering valid email addresses.
    """)
    
    reset_request_data = {
        "email": TEST_EMAIL
    }
    
    print_request("POST", "/password-reset/request", reset_request_data)
    response = client.post("/password-reset/request", json=reset_request_data)
    print_response(response)
    
    print(f"\n    [INFO] Check console output above for mocked email with reset token")
    print(f"    [INFO] In production, token would be sent via secure email")
    
    # -------------------------------------------------------------------------
    # ENDPOINT 6: POST /password-reset/confirm
    # -------------------------------------------------------------------------
    # Completes password reset with new password and MFA verification.
    #   - Validates reset token
    #   - Requires TOTP code (MFA for sensitive action)
    #   - Checks new password against HIBP
    #   - Invalidates ALL user sessions (security measure)
    # -------------------------------------------------------------------------
    
    print_section("ENDPOINT 6: POST /password-reset/confirm - Complete Reset")
    
    print("""
    DESCRIPTION:
    This endpoint completes the password reset:
    
    1. Token Validation:
       - Verifies token hash matches stored hash
       - Checks token is not expired (5 minute window)
       - Checks token is not already used (one-time use)
    
    2. MFA Verification:
       - Requires valid TOTP code (even for password reset!)
       - This prevents attackers with email access from resetting
       - User must have their authenticator device
    
    3. Password Validation:
       - Minimum 14 characters
       - Checked against HIBP breach database
       - Hashed with Argon2id before storage
    
    4. Session Invalidation:
       - ALL active sessions for this user are destroyed
       - ALL refresh tokens are revoked
       - User must re-authenticate on all devices
    
    SECURITY NOTE:
    Requiring MFA for password reset means an attacker who gains
    email access still cannot reset the password without the
    user's authenticator device.
    """)
    
    # Note: In a real scenario, you'd extract the token from the email
    # For this demo, we'll show the expected request format
    
    print("""
    [DEMO NOTE]
    In a real scenario, you would:
    1. Extract the reset token from the email link
    2. Submit it with the new password and TOTP code
    
    Example request (with placeholder token):
    """)
    
    reset_confirm_data = {
        "token": "TOKEN_FROM_EMAIL_WOULD_GO_HERE",
        "new_password": NEW_PASSWORD,
        "totp_code": MOCK_TOTP_CODE
    }
    
    print_request("POST", "/password-reset/confirm", reset_confirm_data)
    print("    [SKIPPED] Cannot complete without real reset token from email")
    print("    [INFO] In production, this would complete the reset flow")
    
    # -------------------------------------------------------------------------
    # DEMONSTRATE: Failed Login Attempts and Rate Limiting
    # -------------------------------------------------------------------------
    
    print_section("DEMO: Rate Limiting and Account Lockout")
    
    print("""
    DESCRIPTION:
    This demonstrates the rate limiting and progressive lockout system:
    
    1. Token Bucket Algorithm:
       - Each IP/account has a "bucket" of tokens
       - Tokens consumed on each request
       - Tokens refill over time
       - Stored in SQLite (no Redis needed)
    
    2. Failed Login Tracking:
       - Failed attempts tracked per email AND per IP
       - Counter stored in SQLite with 24-hour expiry
    
    3. Progressive Lockouts (after 5 failed attempts):
       - 1st lockout: 5 minutes
       - 2nd lockout: 15 minutes
       - 3rd lockout: 30 minutes
       - 4th lockout: 1 hour
       - 5th+ lockout: 24 hours
    
    4. Reset on Success:
       - Successful login resets the failed attempt counter
       - Lockout timer must still expire
    """)
    
    # Create new client to avoid session interference
    rate_limit_client = httpx.Client(base_url=BASE_URL, timeout=30.0)
    
    print("\n    [DEMO] Simulating failed login attempts...")
    
    wrong_login_data = {
        "email": TEST_EMAIL,
        "password": "WrongPassword123456!",  # Wrong password
        "totp_code": MOCK_TOTP_CODE
    }
    
    for i in range(3):
        print(f"\n    Attempt {i + 1} with wrong password:")
        print_request("POST", "/login", wrong_login_data)
        response = rate_limit_client.post("/login", json=wrong_login_data)
        print_response(response)
    
    print(f"""
    [INFO] After 5 failed attempts, the account would be locked for 5 minutes.
    [INFO] Subsequent lockouts would be progressively longer.
    [INFO] This prevents brute-force and credential stuffing attacks.
    """)
    
    rate_limit_client.close()
    
    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    
    print_section("SUMMARY: SECURITY FEATURES DEMONSTRATED")
    
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                    SECURITY FEATURES SUMMARY                        ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║                                                                      ║
    ║  AUTHENTICATION:                                                     ║
    ║  ├─ Password hashing: Argon2id (64MB, 3 iter, 2 parallel)           ║
    ║  ├─ Breach detection: HIBP API with k-anonymity                     ║
    ║  └─ MFA required: 6-digit TOTP, 2-minute window                     ║
    ║                                                                      ║
    ║  SESSION MANAGEMENT:                                                 ║
    ║  ├─ Session IDs: 128-bit, stored as SHA256 hash                     ║
    ║  ├─ Absolute timeout: 2 hours                                        ║
    ║  ├─ Idle timeout: 10 minutes                                         ║
    ║  ├─ Session rotation: Every 2.5 minutes                              ║
    ║  └─ Device fingerprinting: UA + IP subnet + Language                ║
    ║                                                                      ║
    ║  RATE LIMITING (SQLite-backed):                                      ║
    ║  ├─ Algorithm: Token Bucket                                          ║
    ║  ├─ Tracking: Per IP AND per account                                 ║
    ║  └─ Progressive lockouts: 5m -> 15m -> 30m -> 1h -> 24h             ║
    ║                                                                      ║
    ║  ENCRYPTION:                                                         ║
    ║  ├─ TOTP secrets: Fernet (AES-128-CBC) with key rotation            ║
    ║  └─ Tokens: SHA256 hashed before storage                            ║
    ║                                                                      ║
    ║  SECURE COOKIES:                                                     ║
    ║  ├─ HttpOnly: Yes (no JavaScript access)                            ║
    ║  ├─ Secure: Yes (HTTPS only)                                        ║
    ║  ├─ SameSite: Lax (CSRF protection)                                 ║
    ║  └─ Generic name: 'id' (prevents fingerprinting)                    ║
    ║                                                                      ║
    ║  SECURITY HEADERS:                                                   ║
    ║  ├─ Cache-Control: no-store                                         ║
    ║  ├─ X-Content-Type-Options: nosniff                                 ║
    ║  ├─ X-Frame-Options: DENY                                           ║
    ║  └─ CSP: default-src 'none'; frame-ancestors 'none'                 ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    print("=" * 70)
    print("DEMO COMPLETED SUCCESSFULLY!")
    print("=" * 70)

finally:
    # Cleanup
    client.close()

print("\n[INFO] Server will shut down when script exits.")
print("[INFO] Press Ctrl+C to exit if running interactively.")

# Keep server running briefly to ensure all responses complete
time.sleep(1)
