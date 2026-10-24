# FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics
## Undergraduate Information and Network Security (INS) Mini Project Report
**Academic Year:** 2026  
**Department:** Computer Science & Information Technology / Information Security  

### Project Investigators
- **Deeptanil Sinha** (Student ID: `245811402`) — *Application Architecture, Security Engineering & Access Control*
- **Aaditya Abhijit** (Student ID: `245811404`) — *Cryptographic Integrity Monitoring & Digital Forensics Module*

---

## 1. ABSTRACT
Temporary file sharing across open networks presents significant information assurance challenges: persistent exposure of stale data, silent storage-layer file corruption, lack of authenticating evidence regarding file integrity, and vulnerability to token enumeration. **FileGuard** is a full-stack, security-centric web application engineered to solve these challenges. Built with a Flask backend, SQLAlchemy ORM, and modern defensive controls, FileGuard implements strict 12-hour ephemeral file retention, SHA-256 cryptographic integrity verification, cryptographically random 256-bit URL sharing tokens (stored hashed at rest), and an administrative digital forensics and file-system analysis workspace. An automated test suite of 37 integration, unit, and penetration tests was developed and executed, achieving a 100% pass rate. This report documents the theoretical principles, software architecture, security controls, experimental evaluation, and threat mitigations implemented in FileGuard.

---

## 2. INTRODUCTION & PROBLEM STATEMENT

### 2.1 Context
In academic, enterprise, and personal environments, users routinely exchange sensitive files (PDFs, spreadsheets, compressed archives, documents) via cloud links and messaging services. Standard file-sharing mechanisms suffer from critical security flaws:
1. **Indefinite File Retention:** Files remain accessible on hosting servers indefinitely unless manually deleted, increasing the attack surface over time.
2. **Silent Bit Rot & Tampering:** Host file systems provide no native assurance to the recipient that bytes received match the bytes uploaded. Attackers or malfunctioning hardware can modify file contents undetected.
3. **Predictable Resource Identifiers:** Sequential numeric IDs (e.g., `/download/1042`) enable Insecure Direct Object Reference (IDOR) attacks and token enumeration.
4. **Lack of Forensic Accountability:** Standard upload handlers discard upload metadata, making incident response and anomaly detection impossible.

### 2.2 Problem Statement
To design, implement, harden, and evaluate an ephemeral, secure web application that guarantees:
- Absolute availability termination after a strict 12-hour window.
- Mandatory cryptographic integrity verification prior to file delivery.
- Protection against unauthorized enumeration, traversal, CSRF, and injection attacks.
- A functional administrative digital forensics interface capable of detecting low-level storage discrepancies and audit event trails.

---

## 3. PROJECT OBJECTIVES
1. **Architect Ephemeral Lifecycle Management:** Enforce a backend-authoritative 12-hour expiration rule based on synchronized UTC server timestamps, backed by an automated disk cleanup worker.
2. **Implement SHA-256 Cryptographic Monitoring:** Compute an authoritative reference hash upon upload, store it securely, and re-compute the hash before serving downloads to detect tampering.
3. **CSPRNG Share Token Generation:** Utilize Python's `secrets` module to issue 256-bit unpredictable URL-safe tokens, storing only their SHA-256 hashes in the database.
4. **Build a Digital Forensics Workspace:** Implement tools correlating application database timestamps with operating system filesystem `stat` metadata (`st_size`, `st_ctime`, `st_mtime`, `st_atime`).
5. **Rigorous Defensive Hardening & Penetration Testing:** Validate defenses against OWASP Top 10 vulnerabilities with 37 automated test cases.

---

## 4. SYSTEM ARCHITECTURE

```
+---------------------------------------------------------------------------------+
|                                CLIENT LAYER                                     |
|  - Modern Semantic HTML5 / Vanilla CSS3 / JavaScript (Fetch / XHR)              |
|  - Asynchronous Drag-and-Drop Engine with Client-Side Size & Extension Filtering|
|  - Real-Time Ephemeral Countdown Timer (Hours : Minutes : Seconds)              |
+---------------------------------------------------------------------------------+
                                      |  (HTTPS / CSRF Protected)
                                      v
+---------------------------------------------------------------------------------+
|                             APPLICATION LAYER (Flask)                           |
|  - Security Middleware: Security Headers (CSP, nosniff, SAMEORIGIN)             |
|  - Rate Limiter: In-memory burst protection (Flask-Limiter)                     |
|  - Blueprints: Public, Uploads, Downloads, Admin, Forensics                     |
|  - Cryptographic Engine: hashlib (SHA-256), secrets (CSPRNG Tokens)             |
+---------------------------------------------------------------------------------+
           |                                                      |
           v                                                      v
+-----------------------------+               +-----------------------------------+
|     PERSISTENCE LAYER       |               |        SECURE FILE STORAGE        |
|  SQLite 3 via SQLAlchemy    |               |  Isolated directory: /storage     |
|  - FileRecord (Metadata)    |               |  - Stored under fg_<UUID4.hex>    |
|  - SecurityEvent (Audit)    |               |  - Non-predictable file paths     |
|  - IntegrityCheck (History) |               |  - Direct web traversal blocked   |
|  - Administrator (Creds)    |               |  - nosniff Attachment Delivery    |
+-----------------------------+               +-----------------------------------+
```

---

## 5. DATABASE DESIGN (DATA DICTIONARY)

### Table: `file_records`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | Integer | Primary Key | Internal autoincrement ID |
| `storage_id` | String(64) | Unique, Not Null, Index | Obfuscated storage file basename (`fg_<uuid>`) |
| `original_filename`| String(255) | Not Null | Sanitized original filename metadata |
| `file_size` | BigInteger | Not Null | Size in bytes recorded at upload |
| `file_extension` | String(32) | Not Null | Sanitized lowercase extension |
| `detected_mime_type`| String(128) | Not Null | Server-sniffed MIME content type |
| `sha256_reference` | String(64) | Not Null | Authoritative SHA-256 hash computed at upload |
| `share_token_hash` | String(64) | Unique, Not Null, Index | SHA-256 digest of the public sharing token |
| `uploaded_at` | DateTime | Not Null | UTC timestamp when upload completed |
| `expires_at` | DateTime | Not Null, Index | Exact expiration deadline (`uploaded_at + 12h`) |
| `status` | String(32) | Not Null, Index | `active`, `expired`, `deleted`, `tampered` |

### Table: `security_events`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | Integer | Primary Key | Unique audit log ID |
| `event_type` | String(64) | Not Null, Index | Standardized event enum |
| `timestamp` | DateTime | Not Null, Index | UTC event recording timestamp |
| `outcome` | String(32) | Not Null | `SUCCESS`, `BLOCKED`, `FAILURE`, `WARNING` |
| `severity` | String(16) | Not Null, Index | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `file_record_id` | Integer | Foreign Key (Nullable)| Associated file record reference |
| `ip_address` | String(64) | Nullable | Sanitized client IP address |
| `sanitized_details`| Text | Not Null | JSON or structured text description |

### Table: `integrity_checks`
| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | Integer | Primary Key | Check identifier |
| `file_record_id` | Integer | Foreign Key | Target file record |
| `checked_at` | DateTime | Not Null, Index | Verification timestamp |
| `expected_sha256` | String(64) | Not Null | Reference hash from upload |
| `observed_sha256` | String(64) | Nullable | Fresh hash calculated from storage |
| `result` | String(16) | Not Null | `PASS`, `FAIL`, `MISSING` |
| `initiated_by` | String(64) | Not Null | `SYSTEM_DOWNLOAD`, `ADMIN_MANUAL`, `SCAN` |

---

## 6. CORE SECURITY & FORENSIC METHODOLOGY

### 6.1 SHA-256 Cryptographic File Integrity
Integrity monitoring operates through dual-stage hash verification:
1. **Ingress Stage (Upload):** During streaming write from the HTTP request, SHA-256 chunks (64 KB) are continuously digested. The final hex digest is permanently committed as `sha256_reference`.
2. **Egress Stage (Download):** When a recipient requests a download, FileGuard reads the physical storage payload, recalculates the SHA-256 hash in real time, and compares it using constant-time string comparison against `sha256_reference`.
   - **Match:** Serves file with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`.
   - **Mismatch:** Halts transmission immediately, flags file record as `tampered`, generates a `CRITICAL` audit event (`DOWNLOAD_BLOCKED_INTEGRITY_FAIL`), and responds with HTTP 409 Conflict.

### 6.2 Strict 12-Hour Expiration Enforcement
Expiration is authoritative on the server:
- Frontend countdowns are purely visual.
- On every access attempt to `/share/<token>` or `/api/files/<token>/download`, the server evaluates `utc_now() >= record.expires_at`.
- Even if a background cleanup worker has not yet purged the disk file, access is rejected immediately with HTTP 410 Gone.
- Scheduled cleanup runs via `scripts/cleanup_expired.py` or administrative trigger, securely unlinking the physical file and updating record status to `deleted`.

### 6.3 Operating System File-System Forensics
The digital forensics module provides deep correlation between the application state and host OS filesystem metadata:
- **Application Recorded Timestamps:** Stored in SQLite as UTC timestamps.
- **OS File-System Timestamps:** Retrieved via Python `os.stat()` (`st_ctime`, `st_mtime`, `st_atime`).
- **Forensic Takeaway:** In a real forensic investigation, filesystem modification times (`mtime`) can be manipulated by an attacker using `touch` or timestamp stomping tools. However, cryptographic hash discrepancies cannot be forged without computing a SHA-256 collision (which is computationally infeasible).

---

## 7. AUTOMATED TESTING AND VERIFICATION RESULTS
An automated test suite of 37 test cases was executed with pytest.

| Test Category | Tests Planned | Tests Executed | Passed | Failed | Success Rate |
|---|---|---|---|---|---|
| Upload Validation (Tests 1–7) | 7 | 7 | 7 | 0 | 100% |
| Sharing & Downloads (Tests 8–13) | 6 | 6 | 6 | 0 | 100% |
| Integrity Monitoring (Tests 14–19) | 6 | 6 | 6 | 0 | 100% |
| Expiration & Cleanup (Tests 20–24) | 5 | 5 | 5 | 0 | 100% |
| Admin & Access Control (Tests 25–30) | 6 | 6 | 6 | 0 | 100% |
| Penetration Testing Suite (PEN 1–7) | 7 | 7 | 7 | 0 | 100% |
| **Total** | **37** | **37** | **37** | **0** | **100%** |

*Execution timestamp: October 2026. Execution time: 6.50 seconds.*

---

## 8. TEAM CONTRIBUTION BREAKDOWN

### Student 1: Deeptanil Sinha (ID: 245811402)
- **Role:** Full-Stack Architecture, UI/UX Design, Upload/Download Pipelines, Access Control.
- **Contributions:**
  - Designed the responsive frontend design system and UI templates (`base.html`, `index.html`, `upload.html`, `share.html`).
  - Engineered the 12-hour expiration calculation logic and client-side countdown engine (`countdown.js`).
  - Implemented CSRF token generation and validation routines (`app/security.py`).
  - Developed administrative authentication, session security hardening, and rate-limiting configurations.
  - Implemented the upload stream handler and safe storage writer (`app/storage.py`).

### Student 2: Aaditya Abhijit (ID: 245811404)
- **Role:** Cryptographic Integrity Monitoring, Digital Forensics Module, Security Audit Logging.
- **Contributions:**
  - Formulated the SHA-256 cryptographic verification pipeline (`app/integrity.py`).
  - Designed the OS metadata extraction engine comparing database records with `os.stat` attributes.
  - Developed the forensic investigation workspace (`app/templates/forensic_analysis.html`).
  - Implemented the structured security audit logging system (`app/audit.py`).
  - Authored the automated test suites for file tampering, missing file detection, and cleanup execution (`test_integrity.py`, `test_expiration.py`).
  - Implemented the live demonstration tampering simulator (`scripts/demo_tamper.py`).

---

## 9. CONCLUSION & FUTURE WORK
FileGuard successfully demonstrates the principles of Information and Network Security applied to temporary file sharing. By enforcing strict server-side expiration, computing SHA-256 digests, eliminating sequential IDs, and providing an interactive digital forensics workspace, the application bridges theoretical security concepts with modern web engineering.

**Future Enhancements:**
1. Integrating hardware-backed or KMS-based digital signatures on reference hashes.
2. Implementing client-side pre-upload encryption (AES-256-GCM in WebCrypto API).
3. Adding multi-factor authentication (TOTP) for administrative accounts.

