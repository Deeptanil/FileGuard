# Graph Report - IS project  (2026-10-24)

## Corpus Check
- Corpus is ~23,437 words - fits in a single context window. You may not need a graph.

## Summary
- 254 nodes · 634 edges · 13 communities (12 shown, 1 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 44 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Cryptographic Integrity & SHA-256 Verification
- File Records & Ephemeral Expiration Engine
- Automated File Cleanup & Disk Purge
- Secure File Uploads & QR Code Generation
- Application Environment Configuration
- Security Event Logging & Audit Telemetry
- Uploads Unit & Functional Test Suite
- OWASP Penetration Testing Suite
- Admin Authentication & Access Control Tests
- Client-Side Upload & Drag-Drop Engine
- Countdown Timer & Clipboard Utilities

## God Nodes (most connected - your core abstractions)
1. `FileRecord` - 48 edges
2. `utc_now()` - 28 edges
3. `get_storage_path()` - 28 edges
4. `hash_token()` - 23 edges
5. `log_security_event()` - 21 edges
6. `verify_file_integrity()` - 20 edges
7. `run_expired_files_cleanup()` - 19 edges
8. `create_app()` - 17 edges
9. `SecurityEvent` - 16 edges
10. `upload_file()` - 15 edges

## Surprising Connections (you probably didn't know these)
- `main()` --uses--> `FileRecord`  [INFERRED]
  scripts/demo_tamper.py → app/models.py
- `db_session()` --uses--> `FileRecord`  [INFERRED]
  tests/conftest.py → app/models.py
- `test_20_expired_files_deleted_from_storage()` --uses--> `FileRecord`  [INFERRED]
  tests/test_expiration.py → app/models.py
- `test_22_cleanup_does_not_delete_active_files()` --uses--> `FileRecord`  [INFERRED]
  tests/test_expiration.py → app/models.py
- `test_23_missing_expired_files_handled_gracefully()` --uses--> `FileRecord`  [INFERRED]
  tests/test_expiration.py → app/models.py

## Import Cycles
- None detected.

## Communities (13 total, 1 thin omitted)

### Community 0 - "Cryptographic Integrity & SHA-256 Verification"
Cohesion: 0.10
Nodes (36): Scheduled background scan of active unexpired files., Perform SHA-256 cryptographic verification of a file against its reference…, scheduled_integrity_scan(), verify_file_integrity(), IntegrityCheck, Forensic verification history record for a managed file., demo_expire(), demo_tamper() (+28 more)

### Community 1 - "File Records & Ephemeral Expiration Engine"
Cohesion: 0.10
Nodes (31): is_file_expired(), Authoritative server-side expiration check. Returns True if current UTC time >=…, FileRecord, Represents a temporary file uploaded and monitored by FileGuard., Public or admin dictionary representation., download_file(), download_qr(), file_status() (+23 more)

### Community 2 - "Automated File Cleanup & Disk Purge"
Cohesion: 0.11
Nodes (28): Find expired files, securely remove the physical files from server storage,…, run_expired_files_cleanup(), Check if file has passed its 12-hour expiration deadline., Seconds remaining before expiration (returns 0 if expired)., Return current UTC datetime (timezone-aware converted to naive UTC for SQLite…, utc_now(), get_csrf(), index() (+20 more)

### Community 3 - "Secure File Uploads & QR Code Generation"
Cohesion: 0.11
Nodes (28): generate_qr_base64(), limit, route, Render upload completion page with sharing link and QR code., Generate QR code PNG as base64 data URI., Handle secure file upload. Validates CSRF, size, extension, MIME signature,…, upload_file(), upload_success() (+20 more)

### Community 4 - "Application Environment Configuration"
Cohesion: 0.14
Nodes (22): Config, DevelopmentConfig, ProductionConfig, Base application configuration., TestingConfig, create_app(), Register uniform, security-hardened error handlers., Application factory for FileGuard. (+14 more)

### Community 5 - "Security Event Logging & Audit Telemetry"
Cohesion: 0.14
Nodes (22): log_security_event(), Log a structured security audit event into the database. Severity levels: INFO,…, Structured security audit log record for FileGuard operations., SecurityEvent, dashboard(), events_list(), files_list(), login() (+14 more)

### Community 6 - "Uploads Unit & Functional Test Suite"
Cohesion: 0.17
Nodes (16): get_client_with_csrf(), Test 6: A disallowed file type (.exe, .sh) is rejected., Test 7: An empty or malformed upload is handled safely., Test 1: A valid file uploads successfully., Test 2: The application calculates and stores the correct SHA-256 hash., Test 3: The application creates a unique, unpredictable sharing token., Test 4: The expiration timestamp is 12 hours after the upload timestamp., Establish a session and return client with CSRF header. (+8 more)

### Community 7 - "OWASP Penetration Testing Suite"
Cohesion: 0.13
Nodes (14): PEN-TEST 05: Insecure Direct Object Reference (IDOR) & Token Enumeration…, PEN-TEST 06: HTTP Security Headers Audit Target: Response headers across public…, PEN-TEST 07: Session Cookie Hardening Target: Flask session cookie…, PEN-TEST 02: Stored Cross-Site Scripting (XSS) Assessment Target: Filename…, PEN-TEST 03: Cross-Site Request Forgery (CSRF) Assessment Target: Upload and…, PEN-TEST 01: Path Traversal Vulnerability Assessment Target: Upload filename…, PEN-TEST 04: SQL Injection Assessment Target: Administrative login form & token…, test_pen_cookie_security_flags() (+6 more)

### Community 8 - "Admin Authentication & Access Control Tests"
Cohesion: 0.15
Nodes (12): Test 26: Unauthenticated visitors cannot access forensic reports., Test 27: Invalid administrator credentials are rejected., Test 28: Valid administrator credentials successfully authenticate., Test 29: State-changing administrative requests enforce CSRF protection., Test 25: Unauthenticated visitors cannot access the administrative dashboard., Test 30: Public routes do not expose internal storage paths or sensitive tokens., test_25_unauthenticated_cannot_access_dashboard(), test_26_unauthenticated_cannot_access_forensics() (+4 more)

### Community 9 - "Client-Side Upload & Drag-Drop Engine"
Cohesion: 0.62
Nodes (6): clearError(), formatBytes(), handleFileSelect(), resetUploadBtn(), showError(), startUpload()

## Knowledge Gaps
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `FileRecord` connect `File Records & Ephemeral Expiration Engine` to `Cryptographic Integrity & SHA-256 Verification`, `Automated File Cleanup & Disk Purge`, `Secure File Uploads & QR Code Generation`, `Application Environment Configuration`, `Security Event Logging & Audit Telemetry`, `Uploads Unit & Functional Test Suite`, `OWASP Penetration Testing Suite`, `Admin Authentication & Access Control Tests`?**
  _High betweenness centrality (0.273) - this node is a cross-community bridge._
- **Why does `utc_now()` connect `Automated File Cleanup & Disk Purge` to `Cryptographic Integrity & SHA-256 Verification`, `File Records & Ephemeral Expiration Engine`, `Secure File Uploads & QR Code Generation`, `Application Environment Configuration`, `Security Event Logging & Audit Telemetry`, `Uploads Unit & Functional Test Suite`?**
  _High betweenness centrality (0.072) - this node is a cross-community bridge._
- **Why does `get_storage_path()` connect `Cryptographic Integrity & SHA-256 Verification` to `File Records & Ephemeral Expiration Engine`, `Automated File Cleanup & Disk Purge`, `Secure File Uploads & QR Code Generation`, `OWASP Penetration Testing Suite`?**
  _High betweenness centrality (0.066) - this node is a cross-community bridge._
- **Are the 28 inferred relationships involving `FileRecord` (e.g. with `run_expired_files_cleanup()` and `is_file_expired()`) actually correct?**
  _`FileRecord` has 28 INFERRED edges - model-reasoned connections that need verification._
- **Should `Cryptographic Integrity & SHA-256 Verification` be split into smaller, more focused modules?**
  _Cohesion score 0.09878048780487805 - nodes in this community are weakly interconnected._
- **Should `File Records & Ephemeral Expiration Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.10420168067226891 - nodes in this community are weakly interconnected._
- **Should `Automated File Cleanup & Disk Purge` be split into smaller, more focused modules?**
  _Cohesion score 0.1051693404634581 - nodes in this community are weakly interconnected._