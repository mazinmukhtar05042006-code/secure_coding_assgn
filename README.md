# Secure Coding Lab — Interactive Cybersecurity Laboratory

**Academic Assignment 1 — Vulnerability Demonstration & Mitigation System**

An interactive cybersecurity laboratory developed in Python (Flask) that demonstrates the six core software security weaknesses identified in the case study, their real-world security impacts, and their industry-standard secure-coding remediations guided by **Module 1 & Module 2**.

---

## 📌 Project Overview

This repository contains a full-stack, modular web application designed for academic evaluation and live cybersecurity demonstrations. For every security weakness, the laboratory provides an isolated, safe test-bench contrasting:
1. **The Insecure Pattern:** Demonstrating how naive code behaves and why it fails.
2. **The Secure Mitigation:** Demonstrating robust defensive controls (allowlists, canonicalization, cryptographic key derivation, typed exceptions, atomic tempfiles).

---

## 🛡️ Six Case-Study Vulnerabilities & Secure Controls

| # | Vulnerability | Insecure Approach | Secure Coding Mitigation | Key Principles |
|---|---|---|---|---|
| **1** | **OS Command Injection** | Directly concatenating raw user strings into shell commands (`shell=True`). | Structured argument lists via `subprocess.run(["ping", "-n", "1", ip], shell=False)` + server-side IP/hostname allowlist regex. | *Defense in Depth*, *Least Privilege* |
| **2** | **File Path Traversal** | Naively joining paths using `os.path.join(BASE, user_path)`. | Path canonicalization via `pathlib.Path.resolve()` + sandbox boundary containment verification (`is_relative_to`). | *Complete Mediation*, *Secure by Default* |
| **3** | **Plaintext Password Storage** | Storing cleartext password strings in storage/memory. | Salted cryptographic key derivation (PBKDF2-HMAC-SHA256 with 600,000 iterations) + constant-time timing-safe verification. | *Secure Data Handling*, *Defense in Depth* |
| **4** | **Improper Exception Handling** | Generic bare `except:` blocks leaking raw system tracebacks and server directory structures. | Specific typed exception handling (`FileNotFoundError`, `ValueError`), server-side logging only, and sanitized user error messages. | *Fail Securely*, *Secure Recovery* |
| **5** | **Predictable Temporary Files** | Hard-coded or predictable filenames (`shared_temp_report.txt`) subject to TOCTOU and symlink attacks. | Cryptographically randomized filenames via `tempfile.NamedTemporaryFile`, atomic file creation, and guaranteed context-manager cleanup. | *Minimize Attack Surface*, *Least Privilege* |
| **6** | **Unmanaged External Dependencies** | Installing unchecked, unpinned third-party libraries exposing the application to supply-chain CVEs. | Minimal dependency footprint in `requirements.txt`, version locking, package inventory tracking, and Software Composition Analysis (SCA) tooling (`pip-audit`). | *Minimize Attack Surface*, *Defense in Depth* |

---

## 🧭 Additional Laboratory Sections

- **7. Input Validation Playground (`/validation`):** Interactive testing of server-side allowlists, type, length, and format restrictions across multiple data categories.
- **8. Secure Coding Principles (`/principles`):** Mapping of fundamental security principles (*Least Privilege*, *Defense in Depth*, *Secure by Default*, *Fail Securely*, *Complete Mediation*, *Minimize Attack Surface*, *Secure Data Handling*, *Secure Recovery*).
- **9. Risk Assessment & Prioritization (`/risk-assessment`):** Full evaluation matrix based on $Risk = Likelihood \times Impact$ with a 6-tier implementation priority roadmap.
- **10. STRIDE Threat Model (`/threat-model`):** Threat cards covering protected assets, trust boundaries, threat actors, and control mappings.
- **11. Final Security Report (`/report`):** Comprehensive academic audit and remediation report.

---

## 🗺️ Implementation Priority Roadmap

Based on calculated risk ($Risk = Likelihood \times Impact$), the recommended remediation order is:

```text
🚨 IMMEDIATE PRIORITY (PHASE 1)
  01. OS Command Injection           [CRITICAL RISK] -> Direct Remote Code Execution (RCE) / Host Takeover
  02. Plaintext Password Storage     [CRITICAL RISK] -> Total Credential Loss & Credential Stuffing

⚠️ HIGH PRIORITY (PHASE 2)
  03. File Path Traversal            [HIGH RISK]     -> Arbitrary File Disclosure / Source Code Theft
  04. Unmanaged External Dependencies [HIGH RISK]     -> Inherited Third-Party Supply Chain CVEs

🔍 FOLLOW-UP PRIORITY (PHASE 3)
  05. Predictable Temporary Files    [MEDIUM RISK]   -> Symlink Hijacking & TOCTOU Race Conditions
  06. Improper Exception Handling    [MEDIUM RISK]   -> Stack Trace Reconnaissance & Information Leaks
```

---

## 🛠️ Technology Stack

- **Backend:** Python 3.9+ / Flask 3.x
- **Security & Cryptography:** `werkzeug.security` (PBKDF2/scrypt), `pathlib`, `subprocess`, `tempfile`, `ipaddress`, `re`, `logging`
- **Frontend:** Vanilla CSS & Semantic HTML5 (Dark Mode, high-contrast terminal styling, responsive)
- **Testing & Verification:** `pytest` / Python standard `unittest`

---

## 📁 Project Structure

```text
secure-coding-practices-/
│
├── app.py                      # Flask Application factory, blueprints, & HTTP security headers
├── config.py                   # Centralized application configuration & sandbox settings
├── requirements.txt            # Minimal required dependencies
├── README.md                   # Comprehensive lab documentation & setup guide
├── .gitignore                  # Git ignore rules for Python, caches, and secrets
│
├── routes/                     # Blueprint web routes
│   ├── __init__.py
│   ├── main_routes.py          # Dashboard, Validation Playground, Principles, Risk & Threat Model
│   ├── command_routes.py       # Command injection vs. safe subprocess demo
│   ├── file_routes.py          # Path traversal vs. canonicalization demo
│   ├── auth_routes.py          # Plaintext vs. salted hash authentication demo
│   ├── exception_routes.py     # Bare except vs. specific typed exceptions demo
│   ├── temp_routes.py          # Predictable vs. cryptographic temp files demo
│   └── dependency_routes.py    # SCA tool guide & active package inspector
│
├── security/                   # Core security and mitigation implementations
│   ├── __init__.py
│   ├── validation.py           # Server-side allowlist validators
│   ├── command_security.py     # Safe subprocess execution with argument vectors
│   ├── file_security.py        # Path canonicalization and sandbox boundary enforcement
│   ├── password_security.py    # Salted PBKDF2/scrypt hashing & verification
│   ├── exception_security.py   # Explicit exception catches & diagnostic logging
│   └── temp_file_security.py   # Cryptographic temp file generation & auto-cleanup
│
├── templates/                  # Modular HTML templates with educational callouts
│   ├── base.html
│   ├── index.html
│   ├── command.html
│   ├── file_security.html
│   ├── authentication.html
│   ├── exception_handling.html
│   ├── temp_files.html
│   ├── dependencies.html
│   ├── validation.html
│   ├── principles.html
│   ├── risk_assessment.html
│   ├── threat_model.html
│   └── report.html
│
├── static/
│   └── style.css               # Cybersecurity training lab dark stylesheet
│
├── safe_files/                 # Sandbox directory for authorized file operations
│   ├── report_2026.txt
│   ├── company_policy.txt
│   └── system_status.txt
│
└── tests/
    ├── __init__.py
    └── test_security.py        # Automated test suite covering all 6 security controls
```

---

## 🚀 Installation & Execution

### 1. Clone the Repository
```bash
git clone https://github.com/mazinmukhtar05042006-code/secure-coding-practices-.git
cd secure-coding-practices-
```

### 2. Set Up a Virtual Environment

**On Windows (PowerShell / Command Prompt):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Web Application
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your web browser.

---

## 🧪 Running Automated Tests

Run the full security test suite:
```bash
pytest
```
Or using Python's standard `unittest`:
```bash
python -m unittest discover tests
```

---

## ⚠️ Educational Safety Notice

All vulnerable demonstrations in this application are strictly **isolated and sandboxed** for academic training and demonstration purposes. Insecure patterns are simulated and restricted to ensure they do not create arbitrary host execution or compromise real system assets.
