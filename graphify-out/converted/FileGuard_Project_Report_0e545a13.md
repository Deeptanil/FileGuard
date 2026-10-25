<!-- converted from FileGuard_Project_Report.docx -->




FILEGUARD: SECURE FILE SHARING SYSTEM
IT_3121 : INFORMATION SECURITY

Under the guidance of​

Dr. Abhijit Das​
Assistant Professor - Senior Scale,
School of Computer Engineering
Manipal Institute of Technology Bengaluru​
MANIPAL ACADEMY OF HIGHER EDUCATION


By

Aditya Abhijit (245811404) & Deeptanil Sinha (245811402)


1. Abstract & Problem Statement
Temporary file transmission across open networks presents critical security vulnerabilities: persistent data exposure on remote servers, silent data corruption (bit-rot or malicious in-flight modification), unauthorized token enumeration, and intrusive user tracking. FileGuard is an academic and production-oriented web platform providing privacy-focused temporary file sharing. It implements transparent AES-256-GCM encryption at rest, strict 12-hour automated lifecycle purging, pre-flight SHA-256 cryptographic verification, in-memory folder ZIP bundling, client-IP upload quota controls, and an administrative digital forensics inspection lab.
2. Architectural Overview & Subsystem Specifications
The system coordinates web routing, object storage, and relational state without disk bottlenecks or unencrypted staging leaks:

3. Cryptographic Verification & Defensive Controls
- Pre-Flight SHA-256 Anti-Tamper Gate: During upload, an authoritative SHA-256 reference hash is calculated chunk-by-chunk and committed to PostgreSQL. On download, the server hashes the storage block before streaming bytes to the client. Any 1-bit variance triggers an immediate HTTP 409 Anti-Tamper block, logs a CRITICAL security event, and aborts delivery.
- CSPRNG Tokenization & At-Rest Hash Isolation: Sharing tokens are 8-digit human-friendly codes (approx. 26.4 bits entropy) generated via Python's secrets module (formatted as XXXX-XXXX). To protect active links against database disclosure, raw tokens are returned solely to the uploader and never saved in plaintext; only their 256-bit SHA-256 digests are indexed in PostgreSQL.
- In-Memory Multi-File & Folder Bundling: Users can drag-and-drop entire directory trees or multiple files up to 100 MB. FileGuard compresses them on the fly into an organized ZIP archive in memory using io.BytesIO streams, preserving folder paths without creating unencrypted temporary files on the host disk.
- Client-IP Upload Quota Enforcement: To mitigate anonymous upload abuse and resource exhaustion, client IP addresses are extracted (sanitizing reverse-proxy headers) and constrained to an aggregate 100 MB quota over a rolling 12-hour window. Excess volume is rejected with HTTP 429.
4. Digital Forensics & Audit Telemetry
The administrative module provides structured security monitoring and tamper investigation capabilities:
- Interactive Bit-Flip Attack Simulator: Enables evaluators to inject controlled 1-byte mutations into stored objects to observe real-time detection, HTTP 409 blocking, and automated forensic alert logging.
- Local Host Filesystem Inode & Metadata Auditing: Cross-references database timestamps with low-level OS stat attributes (ctime, mtime, atime) across the host storage staging tier to uncover unauthorized out-of-band administrative tampering.
- Security Audit Event Logger: Records events across five severity tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL) and four outcomes (SUCCESS, BLOCKED, WARNING, FAILURE) with client IP telemetry.
5. Cloud Infrastructure & Storage Engineering
- Multi-Threaded S3 Multipart Transfers: Configured boto3 TransferConfig with 10 parallel threads and 256 KB memory buffers, drastically reducing latency for large document packages and video files.
- 10 GB Capacity Monitor & 90% Threshold Alert: Continuously tallies active storage consumption against Backblaze B2 bucket limits, displaying real-time metrics and an automated 7-day usage trajectory chart.
- Automated Conditional Schema Migrations: Embedded DDL migration handlers dynamically apply schema adjustments during deployment cycles, preventing schema drift on serverless PostgreSQL.
6. Privacy-First Client Vault & User Experience
- Dual-Tab LocalStorage Vault (/history): Records 'Uploaded By Me' and 'Shared With Me' directly in client-side localStorage. No user accounts, passwords, or personal profiling exist on the server.
- Live Batch Status Synchronization (/api/files/batch-status): Queries up to 50 local tokens in a single JSON payload to update live status badges (Active, Expired, Revoked) and 1-second countdown tickers.
- 1-Click Early Remote Revocation: Uploaders can immediately purge their active files from Backblaze B2 ahead of the 12-hour deadline, instantly invalidating the link.
7. Verification, Testing & Team Contributions
FileGuard was validated with an automated Pytest test suite of 48 test cases covering functional, cryptographic integrity, security penetration (OWASP WSTG v4.2), and SEO domains (100% pass rate):


Team Member Contributions (Listed Alphabetically)
- Aditya Abhijit (Student ID: 245811404): Engineered the SHA-256 cryptographic pre-flight verification pipeline; built the OS filesystem inode metadata auditing module; created the interactive bit-flip tampering simulator; designed the structured security audit event logger; developed automated test suites for file tampering and missing file detection.
- Deeptanil Sinha (Student ID: 245811402): Designed the end-to-end full-stack architecture and Neo-Brutalist UI; engineered the in-memory streaming ZIP packager for folder uploads; implemented client-IP quota controls; integrated Neon Serverless PostgreSQL and Backblaze B2 S3 multipart transfers; developed the client-side localStorage vault with batch status synchronization.
8. Conclusion & Academic Verification
FileGuard demonstrates that temporary file sharing can achieve robust security without sacrificing user convenience or privacy. By coupling strict 12-hour automated purging, transparent AES-256-GCM encryption at rest, in-memory folder compression, pre-flight cryptographic validation, and anonymous client-side vaults, FileGuard provides a resilient reference implementation for Information & Network Security. A live preview can be inspected at: https://files.deeptanil.in
| Subsystem | Core Technology | Security Function & Implementation |
| --- | --- | --- |
| Application Gateway | Python 3.14 / Flask / Gunicorn | Enforces CSPRNG tokenization, CSRF protection, nosniff & CSP defensive headers |
| Relational State | Neon Serverless PostgreSQL | Stores SHA-256 token digests, storage UUIDs, password hashes, and expiration timestamps |
| Cloud Storage | Backblaze B2 S3 (boto3) | Multi-threaded multipart streaming (10 threads, 256 KB memory buffer) with transparent AES-256-GCM encryption at rest |
| Integrity Engine | SHA-256 Pre-Flight Gate | Dynamic byte-level hash verification halting altered downloads before delivery (HTTP 409) |
| Abuse Mitigation | Flask-Limiter / Client-IP Quota | Strict rate limiting and 100 MB per rolling 12-hour quota allowance per client device (HTTP 429) |
| Testing Domain | Test Cases Executed | Observed Outcome & Status |
| --- | --- | --- |
| Cryptographic Integrity | Pre-flight match, bit-flip tampering, corrupted stream abort | 100% Pass — HTTP 409 Anti-Tamper successfully verified |
| Authoritative Expiration | 12-hr deadline expiry, uncleaned disk access, purge sweeper | 100% Pass — HTTP 410 enforced; cloud storage unlinked |
| Penetration & Hardening (OWASP WSTG v4.2) | Subnet quota, CSRF bypass, path traversal, stored XSS, IDOR, SQL injection | 100% Pass — All 10 assessed OWASP vulnerability categories mitigated and verified resilient |
| SEO & Discovery Gates | robots.txt, sitemap.xml, llms.txt, JSON-LD Schema.org | 100% Pass — All crawler & AI discovery manifests verified |