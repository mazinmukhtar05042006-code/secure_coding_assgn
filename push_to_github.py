"""
Automated push script accepting GitHub Personal Access Token (PAT) via environment variable or argument.
Usage:
  python push_to_github.py <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>
or set $env:GITHUB_TOKEN="ghp_xxxx" and run:
  python push_to_github.py
"""
import os
import sys
from pathlib import Path
from dulwich import porcelain
from dulwich.repo import Repo

REPO_PATH = Path(__file__).resolve().parent
repo = Repo(str(REPO_PATH))

token = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GITHUB_TOKEN", "")

if not token:
    print("[!] Error: No GitHub Personal Access Token provided.")
    print("    Usage: python push_to_github.py <TOKEN>")
    print("    Or set GITHUB_TOKEN environment variable.")
    sys.exit(1)

# Format authenticated URL (HTTPS with PAT)
# https://<TOKEN>@github.com/mazinmukhtar05042006-code/secure-coding-practices-.git
AUTH_REMOTE_URL = f"https://{token}@github.com/mazinmukhtar05042006-code/secure-coding-practices-.git"

print("[*] Connecting to remote with provided authentication...")
try:
    porcelain.push(repo, AUTH_REMOTE_URL, refspecs="refs/heads/master:refs/heads/main")
    print("[+] SUCCESS: All project files successfully pushed to GitHub repository on branch 'main'!")
except Exception as e:
    print(f"[!] Push failed: {type(e).__name__} -> {e}")
    sys.exit(1)
