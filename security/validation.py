"""
Input Validation Module
Demonstrates robust server-side input validation principles:
- Treat external/user input as untrusted.
- Validate type, length, and format.
- Prefer allowlists over blocklists.
- Defense in Depth: Do not rely solely on client-side checks.
"""
import re
import ipaddress
from typing import Tuple, Optional


def validate_hostname_or_ip(value: str) -> Tuple[bool, str]:
    """
    Validates that a string is a safe IP address or strictly alphanumeric domain/hostname.
    Rejects shell metacharacters, semicolons, pipes, backticks, and whitespace.
    """
    if not value or not isinstance(value, str):
        return False, "Input must be a non-empty string."

    value = value.strip()
    if len(value) > 255:
        return False, "Input length exceeds maximum permitted limit (255 characters)."

    # Check if valid IPv4 or IPv6
    try:
        ipaddress.ip_address(value)
        return True, ""
    except ValueError:
        pass

    # Allow strictly standard domain names / hostnames (alphanumeric, dots, hyphens)
    # Disallows shell injection characters like ; & | ` $ > < ( ) \
    hostname_regex = re.compile(
        r"^(?=.{1,255}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )
    if hostname_regex.match(value):
        return True, ""

    return False, "Invalid target format. Only valid IP addresses or domain names are permitted."


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validates username format and length using an allowlist approach.
    """
    if not username or not isinstance(username, str):
        return False, "Username is required."

    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters in length."

    # Allow alphanumeric, underscore, and hyphen only
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False, "Username may only contain letters, numbers, underscores, and hyphens."

    return True, ""


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates password complexity: minimum length and character variety.
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if len(password) > 128:
        return False, "Password length exceeds maximum allowed limit (128 characters)."

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, and one number."

    return True, ""


def validate_filename_safe(filename: str) -> Tuple[bool, str]:
    """
    Validates simple filename input to ensure no directory separators or path traversal tokens.
    """
    if not filename or not isinstance(filename, str):
        return False, "Filename is required."

    filename = filename.strip()
    if len(filename) > 100:
        return False, "Filename is too long."

    # Disallow path separators and null bytes
    if any(char in filename for char in ["/", "\\", "\0", ".."]):
        return False, "Filename contains invalid characters or path traversal sequences."

    # Allow basic alphanumeric, dot, underscore, hyphen
    if not re.match(r"^[a-zA-Z0-9_.-]+$", filename):
        return False, "Filename contains forbidden characters."

    return True, ""
