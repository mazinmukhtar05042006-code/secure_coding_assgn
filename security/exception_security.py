"""
Exception Handling Security Module
Demonstrates:
- Vulnerable pattern: Generic bare `except:` swallowing all exceptions, leaking system paths or full stack traces.
- Secure pattern: Explicit, typed exception handlers, centralized logging, clean user-facing error messages,
  and proper resource cleanup with context managers.
"""
import logging
import traceback
from typing import Dict, Any
from pathlib import Path
import config

# Configure safe internal logging (server-side only)
logger = logging.getLogger("secure_app_logger")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def process_operation_vulnerable(scenario: str, custom_input: str = "") -> Dict[str, Any]:
    """
    VULNERABLE:
    Demonstrates:
    1. Bare `except:` that catches everything indiscriminately (including KeyboardInterrupt or SystemExit).
    2. Directly dumps raw exception details, stack traces, and internal server paths to user output.
    """
    try:
        if scenario == "file_not_found":
            # Trying to open a non-existent file
            f = open(config.BASE_DIR / "non_existent_system_file_12345.conf", "r")
            data = f.read()
            f.close()
            return {"status": "success", "result": data}

        elif scenario == "division_by_zero":
            divisor = int(custom_input) if custom_input else 0
            res = 100 / divisor
            return {"status": "success", "result": res}

        elif scenario == "permission_error":
            # Attempting an illegal write operation
            raise PermissionError("Access Denied: Attempted unauthorized write to C:\\Windows\\System32\\drivers\\etc\\hosts")

        elif scenario == "invalid_type":
            val = int("non_numeric_string_input")
            return {"status": "success", "result": val}

        else:
            return {"status": "info", "result": "Unknown scenario requested."}

    except:
        # Bare except! Catches everything and exposes internal system traceback
        raw_traceback = traceback.format_exc()
        return {
            "status": "vulnerable_exception_exposed",
            "message": "INSECURE EXCEPTION HANDLING: Generic except caught an error and leaked internal traceback.",
            "exposed_traceback": raw_traceback,
            "flaw": "Exposing raw traceback leaks file paths, function names, library versions, and system architecture to attackers."
        }


def process_operation_secure(scenario: str, custom_input: str = "") -> Dict[str, Any]:
    """
    SECURE:
    1. Catches specific, expected exception classes.
    2. Logs complete diagnostic details securely on server console/log file.
    3. Returns safe, generic, user-friendly messages without leaking paths or internals.
    4. Ensures resource management via `with` statement.
    """
    try:
        if scenario == "file_not_found":
            target = config.SAFE_FILES_DIR / "non_existent_file.txt"
            with open(target, "r", encoding="utf-8") as f:
                data = f.read()
            return {"status": "success", "result": data}

        elif scenario == "division_by_zero":
            try:
                divisor = int(custom_input)
            except (ValueError, TypeError):
                logger.warning("Invalid input provided for calculation: %s", custom_input)
                return {
                    "status": "error",
                    "user_message": "Invalid input: Please enter a valid non-zero integer."
                }

            if divisor == 0:
                raise ZeroDivisionError("Divisor cannot be zero.")
            res = 100 / divisor
            return {"status": "success", "result": f"Result: {res}"}

        elif scenario == "permission_error":
            raise PermissionError("Simulated filesystem permission failure.")

        elif scenario == "invalid_type":
            raise ValueError("Input value format is invalid.")

        else:
            return {"status": "info", "user_message": "Scenario completed normally."}

    except FileNotFoundError as e:
        logger.error("File operation failed: Resource missing. Details: %s", str(e))
        return {
            "status": "safe_error",
            "user_message": "The requested document or file could not be found.",
            "secure_handling": "Handled explicitly with 'except FileNotFoundError'. Diagnostic logs kept server-side."
        }
    except PermissionError as e:
        logger.error("Filesystem permission denied: %s", str(e))
        return {
            "status": "safe_error",
            "user_message": "Access to the requested resource is restricted.",
            "secure_handling": "Handled explicitly with 'except PermissionError'. No internal paths exposed."
        }
    except ZeroDivisionError as e:
        logger.warning("Arithmetic calculation error: %s", str(e))
        return {
            "status": "safe_error",
            "user_message": "Calculation error: Cannot divide by zero.",
            "secure_handling": "Handled explicitly with 'except ZeroDivisionError'."
        }
    except ValueError as e:
        logger.warning("Value error encountered: %s", str(e))
        return {
            "status": "safe_error",
            "user_message": "Invalid parameter value provided.",
            "secure_handling": "Handled explicitly with 'except ValueError'."
        }
    except OSError as e:
        logger.error("OS level error encountered: %s", str(e))
        return {
            "status": "safe_error",
            "user_message": "An operating system service error occurred. Please try again later.",
            "secure_handling": "Handled explicitly with 'except OSError'."
        }
    except Exception as e:
        # Fallback catch for truly unexpected bugs, but logged and sanitized
        logger.critical("Unexpected application exception: %s", str(e), exc_info=True)
        return {
            "status": "safe_error",
            "user_message": "An unexpected error occurred. The incident has been logged for review.",
            "secure_handling": "Catch-all logs full traceback internally and presents generic response to user (Fail Securely)."
        }
