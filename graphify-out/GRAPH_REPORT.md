# Graph Report - IS project  (2026-10-25)

## Corpus Check
- 41 files · ~69,475 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 445 nodes · 923 edges · 21 communities (19 shown, 2 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 54 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `303ca6e2`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- FileRecord
- 3. VIVA VOCE QUESTIONS & EXPERT ANSWERS
- utc_now
- hash_token
- models.py
- run_expired_files_cleanup
- test_uploads.py
- test_penetration.py
- test_admin.py
- upload.js
- countdown.js
- FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics
- storage.py
- FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics
- history.js
- FileGuard — Web Application Penetration Testing Report
- FileGuard — Free Deployment Guide
- update_report

## God Nodes (most connected - your core abstractions)
1. `FileRecord` - 61 edges
2. `utc_now()` - 32 edges
3. `hash_token()` - 31 edges
4. `get_storage_path()` - 31 edges
5. `log_security_event()` - 22 edges
6. `3. VIVA VOCE QUESTIONS & EXPERT ANSWERS` - 21 edges
7. `verify_file_integrity()` - 20 edges
8. `run_expired_files_cleanup()` - 19 edges
9. `generate_csrf_token()` - 19 edges
10. `create_app()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `db_session()` --uses--> `FileRecord`  [INFERRED]
  tests/conftest.py → app/models.py
- `test_12_file_cannot_be_downloaded_after_expiration()` --uses--> `FileRecord`  [INFERRED]
  tests/test_downloads.py → app/models.py
- `test_13_expiration_enforced_without_cleanup_worker()` --uses--> `FileRecord`  [INFERRED]
  tests/test_downloads.py → app/models.py
- `test_20_expired_files_deleted_from_storage()` --uses--> `FileRecord`  [INFERRED]
  tests/test_expiration.py → app/models.py
- `test_22_cleanup_does_not_delete_active_files()` --uses--> `FileRecord`  [INFERRED]
  tests/test_expiration.py → app/models.py

## Import Cycles
- None detected.

## Communities (21 total, 2 thin omitted)

### Community 0 - "FileRecord"
Cohesion: 0.07
Nodes (49): Scheduled background scan of active unexpired files., Perform SHA-256 cryptographic verification of a file against its reference…, scheduled_integrity_scan(), verify_file_integrity(), FileRecord, Represents a temporary file uploaded and monitored by FileGuard., User-facing title or original filename fallback., Whether download requires a password or PIN. (+41 more)

### Community 1 - "3. VIVA VOCE QUESTIONS & EXPERT ANSWERS"
Cohesion: 0.05
Nodes (36): 1. PRE-DEMONSTRATION SETUP, 2. REPEATABLE DEMONSTRATION SEQUENCES, 3. VIVA VOCE QUESTIONS & EXPERT ANSWERS, Evaluation Script for INS Mini-Project Reviewers, FileGuard — Live Project Demonstration & Viva Voce Guide, Q10: Why is frontend-only expiration insufficient?, Q11: What happens if the cleanup worker fails?, Q12: How does FileGuard detect file modification? (+28 more)

### Community 2 - "utc_now"
Cohesion: 0.07
Nodes (39): Return current UTC datetime (timezone-aware converted to naive UTC for SQLite…, Check if file has passed its 12-hour expiration deadline., Seconds remaining before expiration (returns 0 if expired)., utc_now(), Test that the user activity & history page loads successfully., Test batch querying file statuses., Test immediate revocation and deletion of a file by token bearer., Test SEO and AI discovery endpoints (robots.txt, sitemap.xml, llms.txt, JSON-… (+31 more)

### Community 3 - "hash_token"
Cohesion: 0.08
Nodes (47): log_security_event(), Log a structured security audit event into the database. Severity levels: INFO,…, is_file_expired(), Authoritative server-side expiration check. Returns True if current UTC time >=…, Authoritative filename for Content-Disposition header with proper extension…, batch_file_status(), download_file(), download_qr() (+39 more)

### Community 4 - "models.py"
Cohesion: 0.08
Nodes (42): Config, DevelopmentConfig, ProductionConfig, Base application configuration., TestingConfig, create_app(), Register uniform, security-hardened error handlers., Application factory for FileGuard. (+34 more)

### Community 5 - "run_expired_files_cleanup"
Cohesion: 0.11
Nodes (29): Find expired files, securely remove the physical files from server storage,…, run_expired_files_cleanup(), cookie_policy(), dmca(), get_csrf(), history_page(), index(), llms_txt() (+21 more)

### Community 6 - "test_uploads.py"
Cohesion: 0.14
Nodes (20): get_client_with_csrf(), Test 6: A disallowed file type (.exe, .sh) is rejected., Test 7: An empty or malformed upload is handled safely., Test 38: Uploading multiple files auto-bundles them into a valid ZIP archive., Test 39: IP upload quota restricts uploads beyond 100 MB in 12 hours., Test 1: A valid file uploads successfully., Test 2: The application calculates and stores the correct SHA-256 hash., Test 3: The application creates a unique, unpredictable sharing token. (+12 more)

### Community 7 - "test_penetration.py"
Cohesion: 0.13
Nodes (14): PEN-TEST 05: Insecure Direct Object Reference (IDOR) & Token Enumeration…, PEN-TEST 06: HTTP Security Headers Audit Target: Response headers across public…, PEN-TEST 07: Session Cookie Hardening Target: Flask session cookie…, PEN-TEST 02: Stored Cross-Site Scripting (XSS) Assessment Target: Filename…, PEN-TEST 03: Cross-Site Request Forgery (CSRF) Assessment Target: Upload and…, PEN-TEST 01: Path Traversal Vulnerability Assessment Target: Upload filename…, PEN-TEST 04: SQL Injection Assessment Target: Administrative login form & token…, test_pen_cookie_security_flags() (+6 more)

### Community 8 - "test_admin.py"
Cohesion: 0.15
Nodes (12): Test 26: Unauthenticated visitors cannot access forensic reports., Test 27: Invalid administrator credentials are rejected., Test 28: Valid administrator credentials successfully authenticate., Test 29: State-changing administrative requests enforce CSRF protection., Test 25: Unauthenticated visitors cannot access the administrative dashboard., Test 30: Public routes do not expose internal storage paths or sensitive tokens., test_25_unauthenticated_cannot_access_dashboard(), test_26_unauthenticated_cannot_access_forensics() (+4 more)

### Community 9 - "upload.js"
Cohesion: 0.35
Nodes (10): clearError(), clearSelectedFiles(), formatBytes(), getBundleSummaryName(), handleFilesSelect(), readEntryFiles(), resetUploadBtn(), showError() (+2 more)

### Community 13 - "FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics"
Cohesion: 0.09
Nodes (22): 1. ABSTRACT, 2.1 Context, 2.2 Problem Statement, 2. INTRODUCTION & PROBLEM STATEMENT, 3. PROJECT OBJECTIVES, 4. SYSTEM ARCHITECTURE, 5. DATABASE DESIGN (DATA DICTIONARY), 6.1 SHA-256 Cryptographic File Integrity (+14 more)

### Community 14 - "storage.py"
Cohesion: 0.14
Nodes (19): decrypt_at_rest(), encrypt_at_rest(), get_storage_master_key(), Derive a 256-bit AES-GCM master key deterministically from application…, Encrypt raw plaintext bytes using AES-256-GCM authenticated cipher before…, Decrypt stored bytes using AES-256-GCM. If bytes do not have the FG_ENC_V1…, delete_stored_file(), get_decrypted_stream() (+11 more)

### Community 15 - "FileGuard — Secure Temporary File Sharing with Integrity Monitoring and Digital Forensics"
Cohesion: 0.12
Nodes (17): 1. Project Overview & Problem Statement, 2. Technology Stack, 3. Project Directory Structure, 4. Local Installation & Setup, 5. Running the Application, 6. Running the Automated Security Test Suite, 7. Running the Expired File Cleanup Worker, 8. Live Examiner Demonstration Workflow (+9 more)

### Community 16 - "history.js"
Cohesion: 0.31
Nodes (13): escapeHtml(), executeRevoke(), formatBytes(), formatRemaining(), formatTime(), getCsrfToken(), renderCurrentTab(), renderUploads() (+5 more)

### Community 17 - "FileGuard — Web Application Penetration Testing Report"
Cohesion: 0.13
Nodes (15): 1. SCOPE AND AUTHORIZATION, 2. METHODOLOGY & TOOLING, 3. SUMMARY OF FINDINGS, 4.1 PEN-TEST 01: Path Traversal Assessment (WSTG-INPV-12), 4.2 PEN-TEST 02: Stored Cross-Site Scripting (XSS) (WSTG-INPV-02), 4.3 PEN-TEST 03: Cross-Site Request Forgery (CSRF) (WSTG-SESS-05), 4.4 PEN-TEST 04: SQL Injection Defense (WSTG-INPV-05), 4.5 PEN-TEST 05: Insecure Direct Object Reference (IDOR) (WSTG-ATHZ-04) (+7 more)

### Community 18 - "FileGuard — Free Deployment Guide"
Cohesion: 0.33
Nodes (5): FileGuard — Free Deployment Guide, Method 1: PythonAnywhere (Recommended — Persistent Free Storage), Method 2: Render.com (Free Web Service via GitHub), Step-by-Step Instructions:, Step-by-Step Instructions:

## Knowledge Gaps
- **75 isolated node(s):** `1. Project Overview & Problem Statement`, `2. Technology Stack`, `3. Project Directory Structure`, `Step 1: Clone or Navigate to the Workspace`, `Step 2: Activate the Virtual Environment` (+70 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `FileRecord` connect `FileRecord` to `utc_now`, `hash_token`, `models.py`, `run_expired_files_cleanup`, `test_uploads.py`, `test_penetration.py`, `test_admin.py`?**
  _High betweenness centrality (0.148) - this node is a cross-community bridge._
- **Why does `hash_token()` connect `hash_token` to `FileRecord`, `utc_now`, `test_uploads.py`, `test_penetration.py`, `test_admin.py`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Why does `utc_now()` connect `utc_now` to `FileRecord`, `hash_token`, `models.py`, `run_expired_files_cleanup`, `test_uploads.py`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 36 inferred relationships involving `FileRecord` (e.g. with `run_expired_files_cleanup()` and `is_file_expired()`) actually correct?**
  _`FileRecord` has 36 INFERRED edges - model-reasoned connections that need verification._
- **What connects `1. Project Overview & Problem Statement`, `2. Technology Stack`, `3. Project Directory Structure` to the rest of the system?**
  _75 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `FileRecord` be split into smaller, more focused modules?**
  _Cohesion score 0.06892230576441102 - nodes in this community are weakly interconnected._
- **Should `3. VIVA VOCE QUESTIONS & EXPERT ANSWERS` be split into smaller, more focused modules?**
  _Cohesion score 0.04878048780487805 - nodes in this community are weakly interconnected._