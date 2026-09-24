"""
Automated Test Suite for Secure Coding Demonstration Application.
Tests:
1. Input validation accepts valid targets and rejects shell injection tokens.
2. Secure file reader prevents directory traversal attempts.
3. Password hashing creates salted non-plaintext hashes and verifies valid credentials.
4. Specific exceptions are caught safely without exposing system tracebacks.
5. Secure temporary file generator creates unpredictable files and cleans up properly.
6. Flask web routes and security headers are functional.
"""
import pytest
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from app import create_app
from security.validation import validate_hostname_or_ip, validate_username, validate_password_strength
from security.command_security import run_command_secure
from security.file_security import read_file_secure
from security.password_security import register_user_secure, login_user_secure, SECURE_USER_STORE
from security.exception_security import process_operation_secure
from security.temp_file_security import create_temp_file_secure


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


class TestValidationAndCommandSecurity:
    def test_valid_hostname_and_ip(self):
        valid, msg = validate_hostname_or_ip("127.0.0.1")
        assert valid is True
        assert msg == ""

        valid, msg = validate_hostname_or_ip("example.com")
        assert valid is True

    def test_command_injection_rejection(self):
        # Shell metacharacters must be rejected by input validation
        payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1 && dir",
            "127.0.0.1 | ls",
            "127.0.0.1`calc`",
            "127.0.0.1$(id)",
            "127.0.0.1\ncat /etc/passwd"
        ]
        for payload in payloads:
            valid, msg = validate_hostname_or_ip(payload)
            assert valid is False, f"Payload {payload} should have been rejected."
            
            # Secure command runner must reject without executing
            result = run_command_secure(payload)
            assert result["status"] == "rejected"
            assert "Validation Error" in result["output"]


class TestFileSecurityAndPathTraversal:
    def test_read_valid_safe_file(self):
        result = read_file_secure("report_2026.txt")
        assert result["status"] == "success"
        assert "CONFIDENTIAL COMPANY REPORT" in result["content"]

    def test_path_traversal_blocked(self):
        # Traversal attempts outside safe_files/ must be rejected
        traversal_attempts = [
            "../app.py",
            "../../config.py",
            "..\\..\\app.py",
            "../../../Windows/win.ini",
            "/etc/passwd"
        ]
        for attempt in traversal_attempts:
            result = read_file_secure(attempt)
            assert result["status"] in ("rejected", "error")
            if result["status"] == "rejected":
                assert "Path traversal attempt detected" in result["error"]


class TestPasswordSecurity:
    def test_password_strength_validator(self):
        # Weak password (too short)
        valid, msg = validate_password_strength("Short1!")
        assert valid is False

        # Strong password
        valid, msg = validate_password_strength("SecureP@ssw0rd2026")
        assert valid is True

    def test_secure_registration_and_hash_storage(self):
        username = "test_user_sec"
        password = "ComplexPassword123"

        # Register
        success, msg = register_user_secure(username, password)
        assert success is True

        # Verify password is NOT stored as plaintext
        stored_value = SECURE_USER_STORE.get(username)
        assert stored_value is not None
        assert stored_value != password
        assert stored_value.startswith("pbkdf2:sha256:") or stored_value.startswith("scrypt:")

        # Verify correct login succeeds
        login_ok, login_msg = login_user_secure(username, password)
        assert login_ok is True

        # Verify incorrect login fails
        login_fail, _ = login_user_secure(username, "WrongPassword123")
        assert login_fail is False


class TestExceptionHandlingSecurity:
    def test_file_not_found_handled_safely(self):
        result = process_operation_secure("file_not_found")
        assert result["status"] == "safe_error"
        assert "The requested document or file could not be found." in result["user_message"]
        # Ensure raw stack trace is not exposed
        assert "Traceback (most recent call last)" not in str(result)

    def test_division_by_zero_handled_safely(self):
        result = process_operation_secure("division_by_zero", custom_input="0")
        assert result["status"] == "safe_error"
        assert "Cannot divide by zero" in result["user_message"]

    def test_invalid_input_handled_safely(self):
        result = process_operation_secure("division_by_zero", custom_input="not_a_number")
        assert result["status"] == "error"
        assert "Invalid input" in result["user_message"]


class TestTempFileSecurity:
    def test_unpredictable_temp_file_creation_and_cleanup(self):
        content = "Confidential automated test token 987654"
        result = create_temp_file_secure(content)

        assert result["status"] == "secure_created_and_cleaned"
        assert result["cleaned_up"] is True
        assert result["content_verified"] == content
        # Check that the filename has random prefix/suffix and is not static
        assert "sec_report_" in result["generated_filename"]
        assert not Path(result["full_path"]).exists()  # Cleaned up


class TestWebRoutesAndHeaders:
    def test_routes_status_200(self, client):
        endpoints = [
            "/",
            "/command",
            "/file-security",
            "/authentication",
            "/exception-handling",
            "/temp-files",
            "/dependencies",
            "/principles",
            "/threat-model",
            "/report"
        ]
        for ep in endpoints:
            res = client.get(ep)
            assert res.status_code == 200, f"Endpoint {ep} failed with status {res.status_code}"
            # Check security headers
            assert res.headers.get("X-Content-Type-Options") == "nosniff"
            assert res.headers.get("X-Frame-Options") == "DENY"
