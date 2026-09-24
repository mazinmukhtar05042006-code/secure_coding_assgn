"""
Password Security and Authentication Module
Demonstrates:
- Vulnerable pattern: Storing passwords in plain text, insecure comparisons.
- Secure pattern: Industry-standard salted password hashing (Werkzeug / PBKDF2 / scrypt)
  and constant-time verification.
"""
from typing import Dict, Tuple, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from security.validation import validate_username, validate_password_strength

# In-memory storage for demonstration purposes (separated for Vulnerable vs Secure)
VULNERABLE_USER_STORE: Dict[str, str] = {
    "alice_demo": "Password123!",
    "bob_admin": "AdminSecret2026"
}

SECURE_USER_STORE: Dict[str, str] = {
    # Pre-hashed with strong work factor (scrypt / pbkdf2)
    "alice_demo": generate_password_hash("Password123!"),
    "bob_admin": generate_password_hash("AdminSecret2026")
}


# --- VULNERABLE DEMONSTRATION ---

def register_user_vulnerable(username: str, password: str) -> Tuple[bool, str]:
    """
    VULNERABLE: Stores passwords directly in plain text.
    Risk: Any data leak, backup exposure, or SQL/directory compromise exposes all user passwords directly.
    """
    if not username or not password:
        return False, "Username and password required."
    
    if username in VULNERABLE_USER_STORE:
        return False, "User already exists in vulnerable store."
        
    VULNERABLE_USER_STORE[username] = password
    return True, "User registered with PLAINTEXT password in storage."


def login_user_vulnerable(username: str, password: str) -> Tuple[bool, str, Optional[str]]:
    """
    VULNERABLE: Direct plaintext string comparison.
    """
    if username not in VULNERABLE_USER_STORE:
        return False, "User not found in vulnerable store.", None
        
    stored_password = VULNERABLE_USER_STORE[username]
    if stored_password == password:
        return True, "Login successful (using vulnerable plaintext check).", stored_password
    else:
        return False, "Incorrect password.", None


def get_vulnerable_store_view() -> Dict[str, str]:
    """Exposes the vulnerable store contents for educational visualization."""
    return dict(VULNERABLE_USER_STORE)


# --- SECURE IMPLEMENTATION ---

def register_user_secure(username: str, password: str) -> Tuple[bool, str]:
    """
    SECURE:
    1. Validates username and password complexity server-side.
    2. Hashes password using cryptographic salt and slow key-derivation function.
    3. Never stores or logs the plaintext password.
    """
    # Step 1: Input Validation
    valid_user, user_err = validate_username(username)
    if not valid_user:
        return False, user_err

    valid_pwd, pwd_err = validate_password_strength(password)
    if not valid_pwd:
        return False, pwd_err

    if username in SECURE_USER_STORE:
        return False, "Username is already taken."

    # Step 2: Generate salted cryptographic hash (PBKDF2-HMAC-SHA256 or scrypt)
    # werkzeug.security generates salt automatically and includes algorithm identifier
    password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')

    # Step 3: Store hash only
    SECURE_USER_STORE[username] = password_hash
    return True, "User registered securely. Only the salted hash is stored."


def login_user_secure(username: str, password: str) -> Tuple[bool, str]:
    """
    SECURE:
    1. Uses constant-time hash comparison function check_password_hash() to prevent timing attacks.
    2. Employs generic error messages to avoid username enumeration.
    3. Plaintext password is discarded immediately after verification.
    """
    if not username or not password:
        return False, "Invalid credentials."

    stored_hash = SECURE_USER_STORE.get(username)
    
    # Timing attack prevention dummy verification if user doesn't exist
    if stored_hash is None:
        # Compute dummy hash check to mitigate timing side-channel
        check_password_hash("pbkdf2:sha256:600000$dummy$salt", password)
        return False, "Invalid username or password."

    if check_password_hash(stored_hash, password):
        return True, "Authentication successful (Verified securely via cryptographic hash)."
    else:
        return False, "Invalid username or password."


def get_secure_store_view() -> Dict[str, str]:
    """Returns the hashed store contents for educational visualization."""
    return dict(SECURE_USER_STORE)
