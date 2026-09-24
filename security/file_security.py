"""
File Security and Path Traversal Module
Demonstrates:
- Vulnerable pattern: Directly trusting user-supplied file paths (`open(BASE + user_path)`).
- Secure pattern: Complete canonicalization using pathlib.Path.resolve(), verifying base directory containment,
  and handling file errors safely.
"""
import os
from pathlib import Path
from typing import Dict, Any
import config


def read_file_vulnerable(user_filename: str) -> Dict[str, Any]:
    """
    VULNERABLE IMPLEMENTATION (Educational Demonstration Only)
    Flaw: Directly concatenates user input with the base directory path without canonicalization.
    Risk: Path Traversal (e.g., ../../windows/win.ini or ../../etc/passwd) allows attackers
          to read arbitrary system or sensitive configuration files.
    """
    if not user_filename:
        return {"status": "error", "error": "No filename provided."}

    # Naive path joining: os.path.join resolves absolute paths or ../ outside intended directory
    target_path = os.path.join(str(config.SAFE_FILES_DIR), user_filename)

    try:
        # Intentionally insecure: directly opening untrusted path
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return {
            "status": "success",
            "requested_path": user_filename,
            "resolved_path": target_path,
            "content": content,
            "warning": "VULNERABLE: Direct access allowed path traversal outside the safe sandbox!"
        }
    except Exception as e:
        # Insecurely exposing raw internal paths and system exceptions
        return {
            "status": "error",
            "requested_path": user_filename,
            "resolved_path": target_path,
            "error": f"Internal System Error: {str(e)}"
        }


def read_file_secure(user_filename: str) -> Dict[str, Any]:
    """
    SECURE IMPLEMENTATION
    1. Treats input as strictly untrusted.
    2. Uses pathlib.Path.resolve() to canonicalize the requested path (resolves symlinks and '..').
    3. Verifies that the resolved path is strictly within the authorized BASE directory.
    4. Rejects any path escaping the permitted directory.
    5. Specific and safe exception handling (no leaked internal system paths).
    """
    if not user_filename or not isinstance(user_filename, str):
        return {
            "status": "rejected",
            "error": "Invalid request: Filename is required."
        }

    # Strip leading/trailing whitespace
    user_filename = user_filename.strip()

    try:
        base_path = config.SAFE_FILES_DIR.resolve()
        
        # Combine base path with untrusted input and resolve canonical absolute path
        # In pathlib, if user_filename is absolute (e.g. C:\Windows or /etc), (base_path / user_filename).resolve()
        # handles it cleanly so we can verify if it starts with base_path
        target_path = (base_path / user_filename).resolve()

        # Step 4: Verify that the resolved target path remains inside base_path
        try:
            # is_relative_to is available in Python 3.9+
            is_inside = target_path.is_relative_to(base_path)
        except AttributeError:
            # Fallback compatibility
            is_inside = str(target_path).startswith(str(base_path))

        if not is_inside:
            return {
                "status": "rejected",
                "requested_path": user_filename,
                "error": "Security Violation: Path traversal attempt detected. Access denied outside sandbox.",
                "explanation": "Path canonicalization detected directory breakout (resolved outside safe_files/)."
            }

        # Verify it is an actual file, not a directory
        if not target_path.is_file():
            return {
                "status": "error",
                "requested_path": user_filename,
                "error": "The requested resource was not found.",
                "explanation": "File does not exist or is a directory."
            }

        # Step 5: Read file safely with proper context manager
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(10000)  # Safe bounded read limit (10KB)

        return {
            "status": "success",
            "requested_path": user_filename,
            "filename": target_path.name,
            "content": content,
            "explanation": "Path successfully validated and canonicalized within safe directory boundary."
        }

    except PermissionError:
        return {
            "status": "error",
            "error": "Permission denied: Unable to read the requested file."
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error": "The requested file was not found."
        }
    except Exception:
        # Fail securely: do not expose internal exception or filesystem layout
        return {
            "status": "error",
            "error": "A safe internal error occurred while processing the file request."
        }
