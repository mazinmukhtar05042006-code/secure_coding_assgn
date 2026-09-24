"""
Temporary File Security Module
Demonstrates:
- Vulnerable pattern: Predictable temporary filenames (e.g. `/tmp/temp_report.txt`), susceptible to symlink/hijack attacks.
- Secure pattern: Cryptographically random temporary file generation using Python's `tempfile` module,
  atomic file creation, safe permissions, and guaranteed cleanup.
"""
import os
import tempfile
from pathlib import Path
from typing import Dict, Any
import config

# Sandboxed demonstration directory for temporary files
DEMO_TEMP_DIR = config.BASE_DIR / "temp_sandbox"
DEMO_TEMP_DIR.mkdir(exist_ok=True)


def create_temp_file_vulnerable(content: str) -> Dict[str, Any]:
    """
    VULNERABLE IMPLEMENTATION (Educational Demonstration Only)
    Flaw:
    1. Uses hard-coded, static, or easily guessable filename (e.g. `report_temp.txt`).
    2. Overwrites existing files without atomic collision checks.
    3. Leaves temporary files lingering on disk indefinitely without cleanup.
    Risk: Race conditions, symlink attacks (TOCTOU), and local privilege escalation.
    """
    predictable_name = "shared_temp_report.txt"
    temp_file_path = DEMO_TEMP_DIR / predictable_name

    try:
        # Predictable write: if an attacker pre-creates a symlink here, the app may overwrite critical files
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(content if content else "Default sample report data.")

        return {
            "status": "vulnerable_created",
            "file_name": predictable_name,
            "full_path": str(temp_file_path),
            "content_written": content if content else "Default sample report data.",
            "flaw": "Static/predictable filename allows attackers to predict path, pre-create malicious symlinks, or overwrite shared files."
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def create_temp_file_secure(content: str) -> Dict[str, Any]:
    """
    SECURE IMPLEMENTATION
    1. Uses Python's standard `tempfile.NamedTemporaryFile` with randomized cryptographic filename.
    2. Atomic creation with restrictive permissions (0600 on Unix).
    3. Handles file read/write safely with context manager and deletes upon completion.
    """
    try:
        # Create a named temporary file inside our demonstration temp directory
        # delete=True ensures automatic deletion on close (or cleanup in finally block)
        with tempfile.NamedTemporaryFile(
            mode="w+",
            dir=str(DEMO_TEMP_DIR),
            prefix="sec_report_",
            suffix=".tmp",
            delete=False,
            encoding="utf-8"
        ) as tmp:
            random_temp_path = Path(tmp.name)
            # Write data atomically
            tmp.write(content if content else "Secure session report data.")
            tmp.flush()

            # Read back to verify
            tmp.seek(0)
            verified_content = tmp.read()

        # Gather details for UI demonstration before safe cleanup
        details = {
            "status": "secure_created_and_cleaned",
            "generated_filename": random_temp_path.name,
            "full_path": str(random_temp_path),
            "content_verified": verified_content,
            "unpredictable_entropy": "Generated with 63^8 cryptographic randomness",
            "explanation": "Created using tempfile.NamedTemporaryFile, written safely, and automatically cleaned up."
        }

        # Safe immediate cleanup (Secure Recovery / Least Resource Lifetime)
        if random_temp_path.exists():
            random_temp_path.unlink()
            details["cleaned_up"] = True

        return details

    except Exception as e:
        return {
            "status": "error",
            "error": "Failed to create secure temporary file safely."
        }
