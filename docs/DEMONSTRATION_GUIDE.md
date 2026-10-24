# FileGuard — Live Project Demonstration & Viva Voce Guide
## Evaluation Script for INS Mini-Project Reviewers

**Project:** FileGuard (Secure Temporary File Sharing with Cryptographic Integrity & Forensics)  
**Presenters:** Deeptanil Sinha (245811402) & Aaditya Abhijit (245811404)  

---

## 1. PRE-DEMONSTRATION SETUP
Before the examiners arrive:
1. Ensure virtual environment is active:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
2. Initialize database & seed admin credentials:
   ```powershell
   python scripts/init_db.py
   ```
3. Start the FileGuard application:
   ```powershell
   python run.py
   ```
   *Application loads at `http://localhost:5000`.*
4. Open two browser windows:
   - **Window 1 (Regular):** For file uploading and Administrator Operations Center (`http://localhost:5000/admin/login`). Credentials: `admin` / `FileGuard@Sec2026!`.
   - **Window 2 (Incognito / Separate Browser):** Simulating an unauthenticated recipient downloading files or scanning QR codes.

---

## 2. REPEATABLE DEMONSTRATION SEQUENCES

### Sequence 1: Normal Secure File Sharing Lifecycle
1. Navigate to `http://localhost:5000`.
2. Drag and drop a valid sample file (e.g., `sample.pdf` or `report.txt`).
3. Click **"Start Secure Upload"**. Observe the client-side progress bar and upload processing.
4. On the **Upload Success** page, highlight:
   - Unique 256-bit cryptographically random sharing link.
   - Authoritative SHA-256 reference hash pill.
   - Dynamic 12-hour expiration countdown timer.
   - Functional QR code and "Save QR Code" button.
5. Click **"Copy Link"** (notice visual copy confirmation).
6. Switch to the **Incognito Window**, paste the link, and hit Enter.
7. Point out the recipient preview screen: file metadata, countdown timer, and "Cryptographic Integrity Monitored" badge.
8. Click **"Verify & Download File"**. The file downloads intact with `nosniff` security headers.

---

### Sequence 2: File Integrity Violation & Tampering Detection
1. Log in to the Administrator Portal at `http://localhost:5000/admin/login` (admin / `FileGuard@Sec2026!`).
2. Navigate to **Forensics Workspace** (`/admin/forensics`).
3. Select the file uploaded in Sequence 1 from the left sidebar.
4. Click **"Verify Integrity"**. Point out the green verification banner:
   *"Integrity verified: the file matches its recorded reference hash."*
5. Under the dashed **INS Mini-Project Live Demonstration Controls** card, click:
   **"Demo: Corrupt Storage Bytes (Tamper)"**. Confirm the prompt.
   *(Alternatively, run `python scripts/demo_tamper.py <id>` in terminal).*
6. Notice the page refreshes:
   - Expected Hash: Remains the original reference hash.
   - Observed Hash: Has recalculated to a completely different SHA-256 string!
   - Red Alert: *"Integrity warning: the file differs from its recorded reference hash!"*
7. Now switch back to the **Recipient Incognito Window** and attempt to download the file.
8. **Demonstrate Defense:** The download is blocked! The browser receives HTTP 409 Conflict, rendering the dedicated **Download Blocked: Integrity Violation** error screen with side-by-side hash discrepancy evidence.
9. Return to the Administrator Dashboard: point out the newly filed `DOWNLOAD_BLOCKED_INTEGRITY_FAIL` critical security event.

---

### Sequence 3: Strict 12-Hour Expiration & Automated Disk Purge
1. In the **Forensics Workspace**, select an active file.
2. Click **"Demo: Fast-Forward Expiration"**. This sets the expiration timestamp 10 minutes into the past without waiting 12 real hours.
3. Switch to the **Recipient Incognito Window** and refresh the sharing link.
4. **Demonstrate Defense:** The backend rejects the request immediately with HTTP 410 Gone, rendering the **This File Has Expired** notice. Access is impossible.
5. In the Administrator Dashboard, click **"Run Purge Cleanup"** (or run `python scripts/cleanup_expired.py` in terminal).
6. Show that the physical file is securely unlinked and deleted from `storage/`, and the record status transitions to `deleted`.

---

### Sequence 4: Invalid Sharing Token Defense
1. Open a deliberately altered or guessed sharing link, e.g.:
   `http://localhost:5000/share/this-is-a-forged-random-token-attempt`
2. Show that FileGuard returns HTTP 404 with a sanitized **Invalid Sharing Token** error page.
3. Open the Administrator Security Events log: show that an `INVALID_TOKEN_ACCESS` event was captured with the client IP address.

---

## 3. VIVA VOCE QUESTIONS & EXPERT ANSWERS

### Q1: What problem does FileGuard solve?
**Answer:** Standard file sharing leaves files on servers indefinitely, lacks verification against silent file corruption or unauthorized tampering, uses predictable URLs vulnerable to IDOR enumeration, and fails to correlate application events with OS-level file-system artifacts. FileGuard provides an ephemeral, integrity-verified sharing system with digital forensics capabilities.

### Q2: Why did you choose Flask?
**Answer:** Flask provides a minimalist, robust WSGI framework with explicit control over routing, response headers, storage streams, and security middleware. Unlike heavy frameworks that abstract low-level HTTP and filesystem handling, Flask allows direct implementation of secure chunked hashing, custom CSP headers, and session controls required for an Information Security project.

### Q3: Why is SHA-256 used?
**Answer:** SHA-256 (Secure Hash Algorithm 256-bit) is a NIST-standard cryptographic hash function offering strong pre-image resistance and collision resistance ($2^{128}$ collision complexity). It generates a fixed 64-character hex digest of file contents, ensuring that any modification—even a single flipped bit—produces a completely different digest (avalanche effect).

### Q4: What is file integrity?
**Answer:** File integrity is the assurance that data stored or transmitted has remained unaltered, complete, and uncorrupted by unauthorized modification, transmission errors, or malicious tampering compared to an authoritative reference state.

### Q5: Does hashing encrypt a file?
**Answer:** No. Hashing is a one-way deterministic mathematical function that maps input bytes of arbitrary length to a fixed-size digest. It cannot be reversed or decrypted to recover the original file bytes.

### Q6: What is the difference between hashing and encryption?
**Answer:**
- **Hashing:** One-way function designed to verify integrity and detect tampering. No key is needed to compute the hash, and the operation cannot be reversed.
- **Encryption:** Two-way function designed to protect confidentiality. It transforms plaintext into ciphertext using a cryptographic key, which can be reversed (decrypted) using the appropriate key.

### Q7: How does the sharing token work?
**Answer:** Upon upload, FileGuard generates a 256-bit random URL-safe string using `secrets.token_urlsafe(32)`. The server stores only the SHA-256 hash of this token in the database. When a user requests a file, the server hashes the provided token in memory and queries the database for a matching token hash.

### Q8: Why must tokens be unpredictable?
**Answer:** If tokens are sequential (e.g., `/files/101`, `/files/102`) or predictable, attackers can enumerate valid links and download unauthorized files without authorization (Insecure Direct Object Reference / IDOR). Cryptographically random 256-bit tokens have an entropy of $2^{256}$, making brute-force guessing computationally impossible.

### Q9: How does the application enforce the 12-hour expiration?
**Answer:** When a file is uploaded, the server calculates `expires_at = uploaded_at + 12 hours` using UTC timestamps. On every subsequent access attempt (viewing or downloading), the backend checks if `current_utc_time >= expires_at`. If true, access is immediately blocked regardless of client state.

### Q10: Why is frontend-only expiration insufficient?
**Answer:** The frontend (HTML/JavaScript) executes on the client device, which is completely untrusted. An attacker can disable JavaScript, modify browser timers, or use tools like `curl` or Postman to bypass frontend restrictions. Expiration enforcement must always be evaluated authoritatively on the server.

### Q11: What happens if the cleanup worker fails?
**Answer:** The file remains protected. Because the backend checks the database expiration timestamp dynamically on every download request, an expired file will still be rejected with HTTP 410 even if the physical file has not yet been deleted from disk. Furthermore, cleanup errors are logged as `CLEANUP_OPERATION_FAILED` for administrative retry.

### Q12: How does FileGuard detect file modification?
**Answer:** During upload, FileGuard calculates and records the file's SHA-256 reference hash. Prior to serving any download, the backend recalculates the SHA-256 hash across the storage file bytes. If the observed hash does not exactly match the stored reference hash, the download is halted and flagged as tampered.

### Q13: What is the difference between file integrity monitoring and malware detection?
**Answer:** File integrity monitoring (FIM) only checks whether a file has changed relative to an initial trusted snapshot; it cannot judge whether the initial file was malicious. Malware detection uses signature databases, heuristics, and sandboxing to determine if code exhibits harmful behavior.

### Q14: What is digital forensics?
**Answer:** Digital forensics is the scientific identification, preservation, examination, analysis, and presentation of digital artifacts and metadata to reconstruct past events on computer systems for incident response or legal proceedings.

### Q15: How does file-system analysis contribute to this project?
**Answer:** It demonstrates how low-level OS storage metadata (file sizes, `st_ctime`, `st_mtime`, `st_atime`) compares against application-layer records. It exposes discrepancies between what an application believes happened and what the underlying operating system recorded, an essential technique in incident response.

### Q16: What is an audit log?
**Answer:** An audit log is an immutable, chronological security record capturing system activities, authentication attempts, file downloads, integrity failures, and administrative actions, documenting who, what, when, and the outcome of events.

### Q17: Can an attacker change both a file and its stored reference hash?
**Answer:** If an attacker compromises the web application or gains administrative access to both the storage directory and the SQLite database, yes, they could theoretically alter both. To prevent this in production enterprise environments, reference hashes must be cryptographically signed with an asymmetric private key or stored in a write-once read-many (WORM) ledger.

### Q18: What are the limitations of SQLite?
**Answer:** SQLite is a serverless, single-file database ideal for local deployments, prototypes, and low-concurrency workloads. However, it relies on file-level locks for writes, meaning high concurrent write traffic can cause database locking contention. For large production deployments, PostgreSQL or MySQL is preferred.

### Q19: What additional risks appear when the application is deployed publicly?
**Answer:** Public exposure introduces automated bot scans, Distributed Denial of Service (DDoS), credential stuffing attacks, advanced web application attacks, and potential clock drift between clustered application nodes.

### Q20: What would you improve in a production version?
**Answer:**
1. Migrate from SQLite to PostgreSQL with read replicas.
2. Add Multi-Factor Authentication (TOTP / WebAuthn) for administrative accounts.
3. Integrate client-side end-to-end encryption using the Web Crypto API before bytes leave the browser.
4. Utilize an external Object Storage service (e.g., AWS S3 with Object Lock or GCP Cloud Storage) with lifecycle expiration policies.

