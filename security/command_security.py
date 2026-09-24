"""
Command Execution Security Module
Demonstrates:
- Vulnerable pattern: Direct shell command concatenation.
- Secure pattern: Subprocess argument lists without shell interpretation, combined with input validation.
"""
import os
import sys
import subprocess
from typing import Dict, Any
from security.validation import validate_hostname_or_ip


def run_command_vulnerable(target: str) -> Dict[str, Any]:
    """
    VULNERABLE IMPLEMENTATION (Educational Demonstration Only)
    Flaw: Directly concatenates raw user input into a shell command string.
    Risk: An attacker can inject command chaining operators (;, &&, ||, |, ``, $())
          to execute arbitrary system commands with the application's privilege.
    """
    # Safe simulation/emulation for Windows & Unix to prevent destructive host modifications
    # while clearly demonstrating command injection mechanics
    is_windows = sys.platform.startswith("win")
    
    # In a real vulnerable app, developers write:
    # cmd = f"ping -c 1 {target}" (Linux) or f"ping -n 1 {target}" (Windows)
    # os.popen(cmd).read() or os.system(cmd)
    
    # We execute via shell=True to illustrate shell behavior
    if is_windows:
        cmd = f"ping -n 1 {target}"
    else:
        cmd = f"ping -c 1 {target}"
        
    try:
        # shell=True passes the string directly to cmd.exe or /bin/sh
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + (result.stderr if result.stderr else "")
        return {
            "status": "success" if result.returncode == 0 else "error",
            "command_executed": cmd,
            "output": output,
            "explanation": "Executed directly through shell interpreter (shell=True). User input was concatenated raw."
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "command_executed": cmd,
            "output": "Execution timed out (5s limit reached).",
            "explanation": "Command timed out."
        }
    except Exception as e:
        return {
            "status": "error",
            "command_executed": cmd,
            "output": str(e),
            "explanation": "Exception occurred during execution."
        }


def run_command_secure(target: str) -> Dict[str, Any]:
    """
    SECURE IMPLEMENTATION
    1. Input Validation: Validates that the input strictly matches an IP address or valid domain name.
    2. Structured API: Uses subprocess.run with an argument list (vector) instead of a raw command string.
    3. No Shell: shell=False is explicitly set, preventing the shell interpreter from parsing metacharacters.
    4. Timeout: Imposes strict execution timeouts.
    """
    # Step 1: Validate input
    is_valid, error_msg = validate_hostname_or_ip(target)
    if not is_valid:
        return {
            "status": "rejected",
            "command_executed": "None (Execution prevented by input validation)",
            "output": f"Validation Error: {error_msg}",
            "explanation": "Input rejected by server-side allowlist validation before execution."
        }

    is_windows = sys.platform.startswith("win")
    
    # Step 2: Build argument array (argv list)
    if is_windows:
        args = ["ping", "-n", "1", target.strip()]
    else:
        args = ["ping", "-c", "1", target.strip()]

    try:
        # Step 3: Run without shell interpreter (shell=False by default)
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + (result.stderr if result.stderr else "")
        return {
            "status": "success" if result.returncode == 0 else "error",
            "command_executed": " ".join(args),
            "output": output,
            "explanation": "Executed safely using structured subprocess argument vector (shell=False) and strict input validation."
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "command_executed": " ".join(args),
            "output": "Command timed out (5s limit).",
            "explanation": "Execution timed out."
        }
    except Exception as e:
        return {
            "status": "error",
            "command_executed": " ".join(args),
            "output": "An internal execution error occurred.",
            "explanation": "Failed safely without exposing system internals."
        }
