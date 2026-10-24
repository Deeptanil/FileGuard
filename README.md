# FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics

[![Automated Security Test Suite](https://img.shields.io/badge/Security_Tests-37%2F37_Passed-10B981?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Python Version](https://img.shields.io/badge/Python-3.11_|_3.12_|_3.14-3B82F6?style=for-the-badge&logo=python&logoColor=white)](run.py)
[![Architecture](https://img.shields.io/badge/Architecture-Flask_%2B_SQLAlchemy_%2B_SQLite-06B6D4?style=for-the-badge)](app/)
[![Project Category](https://img.shields.io/badge/Category-Information_&_Network_Security-F59E0B?style=for-the-badge)](docs/PROJECT_REPORT.md)

> **Undergraduate Information and Network Security (INS) Mini Project (Academic Year 2026)**  
> Developed by:  
> - **Deeptanil Sinha** (Student ID: `245811402`) — *Application Architecture, UI/UX, Access Control & Security Hardening*  
> - **Aaditya Abhijit** (Student ID: `245811404`) — *Cryptographic Integrity Monitoring, Digital Forensics & Penetration Testing*  

---

## 1. Project Overview & Problem Statement

Standard temporary file sharing tools leave sensitive files vulnerable to indefinite cloud retention, unauthorized enumeration attacks (IDOR), and silent storage-layer tampering. 

**FileGuard** is a security-hardened, full-stack web application designed to demonstrate practical defensive engineering and digital forensics:
- **Strict 12-Hour Ephemeral Retention:** Files are authoritative strictly for 12 hours from upload UTC time. Expired links are rejected immediately by the backend, and disk payloads are securely purged.
- **SHA-256 Cryptographic Integrity Monitoring:** Reference hashes are computed on upload. Every download performs a pre-flight cryptographic recalculation; if even a single byte differs, transmission is blocked with HTTP 409 and a critical security incident is logged.
- **CSPRNG 256-Bit Sharing Tokens:** Unpredictable sharing tokens are generated via `secrets.token_urlsafe(32)`. To protect tokens at rest, only their SHA-256 hashes are stored in the database.
- **Administrative Digital Forensics Workspace:** Allows security officers to compare application metadata with operating system filesystem `stat` properties (`st_size`, `st_ctime`, `st_mtime`, `st_atime`) and execute live simulated tampering scenarios.
- **Integrated Web Application Penetration Testing:** Validated with 37 automated test cases covering path traversal, stored XSS, CSRF enforcement, SQL injection resilience, and cookie hardening.

---

## 2. Technology Stack

- **Backend:** Python 3.11+ / 3.14, Flask, Werkzeug, SQLAlchemy ORM, Flask-Limiter
- **Database:** SQLite 3 (isolated relational database with indexing on tokens and expiration timestamps)
- **Frontend:** Semantic HTML5, Vanilla CSS3 (custom dark navy SaaS palette), Modern JavaScript (Fetch/XHR)
- **Cryptography:** Python standard library `hashlib` (SHA-256) & `secrets` (CSPRNG tokens)
- **QR Code Engine:** `qrcode` & Pillow (rendering canonical sharing URLs)
- **Testing:** `pytest` (37 unit, integration, and penetration test cases)

---

## 3. Project Directory Structure

```
FileGuard/
├── app/
│   ├── __init__.py           # Application Factory & Security Headers
│   ├── config.py             # Environment configurations
│   ├── extensions.py         # SQLAlchemy and Flask-Limiter
│   ├── models.py             # Database models (FileRecord, SecurityEvent, IntegrityCheck, Admin)
│   ├── security.py           # CSRF, CSPRNG tokens, MIME sniffing, Path sanitization
│   ├── storage.py            # Isolated storage handler, OS stat extraction
│   ├── integrity.py          # Dual-stage SHA-256 verification engine
│   ├── expiration.py         # Authoritative 12-hour expiration logic
│   ├── cleanup.py            # Disk unlinking and lifecycle maintenance
│   ├── audit.py              # Structured security audit logger
│   ├── routes/
│   │   ├── public.py         # Landing page and direct upload views
│   │   ├── uploads.py        # Secure upload pipeline & QR code generation
│   │   ├── downloads.py      # 5-stage verified download pipeline
│   │   ├── admin.py          # Admin portal, SOC dashboard, file inventory
│   │   └── forensics.py      # Forensic analysis & live examiner demo suite
│   ├── templates/            # Jinja2 templates (index, upload, share, forensics...)
│   └── static/               # Enterprise stylesheet and countdown scripts
├── instance/                 # SQLite database storage (fileguard.db)
├── storage/                  # Server-side file storage outside webroot
├── tests/                    # 37 Automated pytest test cases
│   ├── conftest.py           # Test fixtures & isolated temp storage
│   ├── test_uploads.py       # Upload validation tests (1-7)
│   ├── test_downloads.py     # Sharing & download tests (8-13)
│   ├── test_integrity.py     # SHA-256 integrity tests (14-19)
│   ├── test_expiration.py    # Expiration & cleanup tests (20-24)
│   ├── test_admin.py         # Admin access control tests (25-30)
│   └── test_penetration.py   # Web application penetration testing suite
├── scripts/
│   ├── init_db.py            # Database schema creation & admin seeding
│   ├── cleanup_expired.py    # Scheduled worker for purging expired files
│   └── demo_tamper.py        # CLI tool for live examiner tampering demo
├── docs/
│   ├── PROJECT_REPORT.md     # Full academic INS mini-project report
│   ├── PENETRATION_TEST_REPORT.md # OWASP penetration testing audit report
│   ├── THREAT_MODEL.md       # STRIDE threat model & residual risks
│   └── DEMONSTRATION_GUIDE.md# Live evaluator script & 20 Viva Voce Q&As
├── .env.example              # Configuration template
├── requirements.txt          # Production dependencies
├── pytest.ini                # Pytest configuration
├── run.py                    # Application launch entry point
└── README.md
```

---

## 4. Local Installation & Setup

### Step 1: Clone or Navigate to the Workspace
```powershell
cd "e:\Pupu Do not delete\IS project"
```

### Step 2: Activate the Virtual Environment
Windows PowerShell:
```powershell
.\venv\Scripts\Activate.ps1
```
*(On Linux/macOS: `source venv/bin/activate`)*

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env` (a pre-configured `.env` is already present for local execution):
```powershell
cp .env.example .env
```

### Step 5: Initialize Database & Seed Administrator Credentials
```powershell
python scripts/init_db.py
```
*Creates all tables in `instance/fileguard.db` and provisions default administrator credentials:*
- **Username:** `admin`
- **Password:** `FileGuard@Sec2026!`

---

## 5. Running the Application

Start the local server:
```powershell
python run.py
```
Open your browser to: **`http://localhost:5000`**

### Administrative Access:
- **Login URL:** `http://localhost:5000/admin/login`
- **Security Dashboard:** `http://localhost:5000/admin/dashboard`
- **Forensic Investigation:** `http://localhost:5000/admin/forensics`

---

## 6. Running the Automated Security Test Suite

Execute the full suite of 37 automated tests:
```powershell
.\venv\Scripts\pytest -v tests/
```
**Expected Result:**
```
============================= 37 passed in 6.50s ==============================
```

---

## 7. Running the Expired File Cleanup Worker

To run the background purge process manually or on a scheduled task:
```powershell
python scripts/cleanup_expired.py
```

---

## 8. Live Examiner Demonstration Workflow

Refer to **[DEMONSTRATION_GUIDE.md](docs/DEMONSTRATION_GUIDE.md)** for complete evaluation scripts.

### Quick Demonstration Sequences:
1. **Normal Flow:** Upload a file at `http://localhost:5000`. Copy the sharing link or scan the QR code in an incognito window. Download the file.
2. **Tampering Detection:**
   - Go to `/admin/forensics` and select the file.
   - Click **"Demo: Corrupt Storage Bytes (Tamper)"** (or run `python scripts/demo_tamper.py <id>`).
   - Observe the live hash mismatch.
   - In the recipient window, try downloading the file: **The download is blocked immediately with HTTP 409 Conflict** and a `CRITICAL` alert is recorded.
3. **12-Hour Expiration:**
   - In `/admin/forensics`, click **"Demo: Fast-Forward Expiration"**.
   - Attempt download in the recipient window: Access is denied with HTTP 410 Gone.
   - Click **"Run Purge Cleanup"**: the file is deleted from `storage/`.

---

## 9. Academic Documentation

Complete academic project documentation is available in the `docs/` folder:
- **[PROJECT_REPORT.md](docs/PROJECT_REPORT.md):** Full academic report covering system architecture, mathematical principles, data dictionary, and test results.
- **[PENETRATION_TEST_REPORT.md](docs/PENETRATION_TEST_REPORT.md):** OWASP-aligned penetration test assessment with vulnerability findings, remediations, and retest evidence.
- **[THREAT_MODEL.md](docs/THREAT_MODEL.md):** STRIDE threat modeling analysis.
- **[DEMONSTRATION_GUIDE.md](docs/DEMONSTRATION_GUIDE.md):** Step-by-step evaluator guide with complete answers to 20 viva voce questions.

