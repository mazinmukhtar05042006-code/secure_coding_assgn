"""
Application configuration for the Secure Coding Demonstration System.
Enforces safe defaults and isolates educational parameters.
"""
import os
from pathlib import Path

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

# Directory containing safe sample files for file handling demonstrations
SAFE_FILES_DIR = BASE_DIR / "safe_files"
SAFE_FILES_DIR.mkdir(exist_ok=True)

# Secret key for Flask sessions (In production, use secure environment variables)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secure-coding-key-2026-unpredictable-hash")

# Configuration for demonstrations
DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
TESTING = False
