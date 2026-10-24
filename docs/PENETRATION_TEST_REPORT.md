# FileGuard — Web Application Penetration Testing Report
## Information and Network Security (INS) Laboratory Assessment

**Target System:** FileGuard (Secure Temporary File Sharing Application)  
**Assessment Type:** Grey-box Web Application Security Audit & Penetration Test  
**Testing Environment:** Local Sandboxed Environment (`http://127.0.0.1:5000`)  
**Security Analysts:**
- Deeptanil Sinha (Student ID: `245811402`)
- Aaditya Abhijit (Student ID: `245811404`)  
**Date of Assessment:** October 2026  

---

## 1. SCOPE AND AUTHORIZATION
This assessment was conducted strictly within an authorized educational laboratory environment pursuant to the requirements of the Information and Network Security (INS) curriculum. Testing was confined to the local FileGuard deployment. External third-party services and host infrastructure were excluded from testing.

---

## 2. METHODOLOGY & TOOLING
Testing adhered to the **OWASP Web Security Testing Guide (WSTG v4.2)** and OWASP Top 10 Application Security Risks.

### Tools Utilized:
- **Pytest Security Test Harness:** Automated test runner executing regression and attack simulation payloads (`tests/test_penetration.py`).
- **Python Requests & Test Client:** Scripted fuzzing and header inspection.
- **Manual Penetration Testing:** Browser developer tools, HTTP request interception, and curl/PowerShell manipulation.

---

## 3. SUMMARY OF FINDINGS

| Vulnerability ID | Vulnerability Category | Severity | Initial Status | Remediated Status |
|---|---|---|---|---|
| **VULN-01** | Path Traversal via Upload Filename | High | Mitigated | Verified Resilient |
| **VULN-02** | Stored Cross-Site Scripting (XSS) in Metadata | High | Mitigated | Verified Resilient |
| **VULN-03** | Cross-Site Request Forgery (CSRF) on Uploads | Medium | Mitigated | Verified Resilient |
| **VULN-04** | SQL Injection on Authentication Forms | Critical | Mitigated | Verified Resilient |
| **VULN-05** | Insecure Direct Object Reference (IDOR) | High | Mitigated | Verified Resilient |
| **VULN-06** | Missing HTTP Defensive Headers | Medium | Mitigated | Verified Resilient |
| **VULN-07** | Insecure Session Cookie Flags | Medium | Mitigated | Verified Resilient |
| **VULN-08** | Unauthorized Admin Route Access | High | Mitigated | Verified Resilient |
| **VULN-09** | Serving Corrupted / Tampered File Payloads | Critical | Mitigated | Verified Resilient |
| **VULN-10** | Expired File Access Post-Deadline | High | Mitigated | Verified Resilient |

---

## 4. DETAILED VULNERABILITY ASSESSMENTS & EVIDENCE

### 4.1 PEN-TEST 01: Path Traversal Assessment (WSTG-INPV-12)
- **Objective:** Verify whether an attacker can upload a file that writes outside the designated storage folder using relative directory traversal characters (`../../`).
- **Test Procedure:** Dispatched multipart POST requests containing filenames:
  - `../../../../etc/passwd.txt`
  - `..\..\..\windows\win.ini.txt`
  - `nested/../../traversal.txt`
- **Expected Secure Behavior:** Path traversal characters must be stripped. The stored file must reside strictly inside `current_app.config['STORAGE_DIR']`.
- **Actual Result:** `secure_filename()` stripped all directory slashes. Files were stored under safe generated UUIDs (`fg_<hex>`). Path resolution in `get_storage_path()` threw `StorageError` if any path escaped the storage directory.
- **Test Status:** **PASS** (Evidence: `tests/test_penetration.py::test_pen_path_traversal_prevention`).

---

### 4.2 PEN-TEST 02: Stored Cross-Site Scripting (XSS) (WSTG-INPV-02)
- **Objective:** Determine if malicious JavaScript injected into an uploaded filename will execute when rendered on the recipient download page or administrator dashboard.
- **Test Procedure:** Uploaded a file named `<script>alert('XSS_POC')</script>.txt` and opened the share view `/share/<token>`.
- **Expected Secure Behavior:** Filename must be sanitized and HTML characters must be entity-encoded (`&lt;script&gt;`). No unescaped `<script>` execution.
- **Actual Result:** Jinja2 autoescaping combined with `sanitize_filename()` neutralized the payload into `script.txt`. The raw executable script tag did not exist in the rendered DOM.
- **Test Status:** **PASS** (Evidence: `tests/test_penetration.py::test_pen_stored_xss_prevention`).

---

### 4.3 PEN-TEST 03: Cross-Site Request Forgery (CSRF) (WSTG-SESS-05)
- **Objective:** Verify whether an attacker can force an authenticated session to execute state-changing actions (e.g., file upload or cleanup purge) without a valid CSRF token.
- **Test Procedure:**
  1. Sent upload requests without `csrf_token` or `X-CSRFToken` headers.
  2. Sent requests with forged random CSRF tokens.
- **Expected Secure Behavior:** Both requests must be rejected with HTTP 403 Forbidden.
- **Actual Result:** The application validated the token using constant-time comparison `hmac.compare_digest()`. Both unauthorized requests were blocked with HTTP 403.
- **Test Status:** **PASS** (Evidence: `tests/test_penetration.py::test_pen_csrf_enforcement`).

---

### 4.4 PEN-TEST 04: SQL Injection Defense (WSTG-INPV-05)
- **Objective:** Attempt authentication bypass on the administrator login portal using classical SQLi payloads.
- **Test Payloads Tested:**
  - `' OR '1'='1`
  - `admin' --`
  - `' UNION SELECT 1, 'admin', 'hash', datetime('now'), datetime('now'), 1 --`
- **Expected Secure Behavior:** SQLAlchemy parameterized queries treat the payload as literal string values. Authentication must fail without syntax errors or leakage.
- **Actual Result:** No queries were concatenated dynamically. All login attempts were safely rejected with `Invalid administrative credentials`.
- **Test Status:** **PASS** (Evidence: `tests/test_penetration.py::test_pen_sql_injection_defense`).

---

### 4.5 PEN-TEST 05: Insecure Direct Object Reference (IDOR) (WSTG-ATHZ-04)
- **Objective:** Test if file downloads can be accessed or enumerated by guessing sequential integer IDs (`1, 2, 3...`).
- **Test Procedure:** Sent GET requests to `/api/files/1/download`, `/api/files/2/download`, and `/share/1`.
- **Expected Secure Behavior:** Sequential lookup must not exist. The application must only resolve 256-bit CSPRNG tokens.
- **Actual Result:** All numeric ID access attempts yielded HTTP 404 Not Found. File lookup strictly matches the SHA-256 hash of the 256-bit random sharing token.
- **Test Status:** **PASS** (Evidence: `tests/test_penetration.py::test_pen_idor_and_enumeration_resistance`).

---

### 4.6 PEN-TEST 06: Cryptographic Integrity Verification & Tampering Abort
- **Objective:** Verify whether modifying a single byte of a file in storage is detected and blocked prior to delivery.
- **Test Procedure:**
  1. Uploaded a valid file and recorded reference SHA-256 hash.
  2. Injected simulated corruption bytes directly into the stored file on disk.
  3. Dispatched a download request via the legitimate sharing URL.
- **Expected Secure Behavior:** The server must compute the SHA-256 hash of storage bytes, compare it with the reference hash, detect the mismatch, abort the download with HTTP 409, and log a `CRITICAL` audit event.
- **Actual Result:** Download aborted with HTTP 409 Conflict. Security event `DOWNLOAD_BLOCKED_INTEGRITY_FAIL` recorded. Modified file was never served.
- **Test Status:** **PASS** (Evidence: `tests/test_integrity.py::test_19_failed_integrity_blocks_downloads`).

---

## 5. RESIDUAL RISKS AND LIMITATIONS
1. **Physical Server & Database Compromise:** If an adversary attains root shell access to the host server, they can alter both the file bytes and the SQLite database reference hash simultaneously. In enterprise environments, this would be mitigated by publishing signed hash manifests to an immutable append-only ledger or external KMS.
2. **Server-Side File Encryption at Rest:** Files are currently stored unencrypted on disk with restricted filesystem permissions. While protected against web directory traversal, host-level disk encryption (e.g., BitLocker / LUKS) should be maintained in production.
3. **Clock Skew / Synchronization:** Expiration enforcement relies on accurate server UTC time. Host systems must maintain active NTP synchronization.

---

## 6. CONCLUSION
The penetration testing evaluation confirmed that FileGuard successfully enforces defense-in-depth across input validation, cryptographic hashing, authentication, session security, and access control. All 10 assessed vulnerability classes were verified to be securely mitigated.

