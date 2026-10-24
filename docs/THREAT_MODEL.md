# FileGuard — Threat Model Document
## Lightweight Security Analysis (STRIDE Methodology)
**Target:** FileGuard Ephemeral File Sharing System  
**Authors:** Deeptanil Sinha & Aaditya Abhijit  
**Academic Year:** 2026  

---

## 1. ASSETS
1. **Uploaded Temporary Files (Data at Rest):** Ephemeral physical files residing in `storage/`.
2. **Authoritative Cryptographic Reference Hashes:** SHA-256 strings recorded at the exact moment of upload.
3. **Sharing Tokens:** 256-bit CSPRNG secrets granting access to download files before 12 hours.
4. **Administrative Credentials:** Password hashes stored using `scrypt` for administrative management.
5. **Security Audit Event Log:** Chronological records of upload, download, tampering, and authentication events.

---

## 2. TRUST BOUNDARIES
- **Boundary 1: Untrusted Public Internet <-> Public Endpoints**  
  File uploaders and recipients access `/`, `/upload`, `/share/<token>`, `/api/files`. No client is authenticated or inherently trusted.
- **Boundary 2: Public Users <-> Administrative Portal**  
  Separates public file downloaders from the `/admin/*` operations dashboard and `/admin/forensics/*` investigation tools.
- **Boundary 3: Web Server Application <-> Operating System Storage**  
  Separates the Flask runtime from the host filesystem storage directory (`storage/`).

---

## 3. THREAT ACTORS
1. **Casual Downloader:** Normal recipient accessing files via link or QR code.
2. **Malicious Public Actor:** Probing for IDOR/sequential tokens, uploading oversized files, attempting path traversal or XSS.
3. **Host Infiltrator / Malicious Local User:** Attacker with local account attempting to modify stored file bytes or inspect other users' files.
4. **Eavesdropper / Network Snooper:** Monitoring unencrypted network links (mitigated via HTTPS in production).

---

## 4. STRIDE THREAT MATRIX & MITIGATIONS

| STRIDE Category | Threat Scenario | Impact | Mitigation Implemented in FileGuard |
|---|---|---|---|
| **Spoofing** | Attacker attempts to forge administrative sessions. | Full system compromise | Session cookie protected with `HttpOnly`, `SameSite=Lax`, and `scrypt` password hashing. Admin routes require `@admin_required`. |
| **Tampering** | Stored file bytes are modified or corrupted on disk prior to recipient download. | Delivery of tampered content | Pre-flight SHA-256 integrity check executes on every download. Mismatch blocks transmission and files critical alert. |
| **Repudiation** | An attacker claims a download or administrative purge never took place. | Forensic ambiguity | Structured, append-only `SecurityEvent` audit logging captures IP address, event type, severity, and outcome. |
| **Information Disclosure** | Public user enumerates file IDs or reads filesystem storage paths. | Unauthorized data access | Predictable numeric IDs replaced with 256-bit `secrets.token_urlsafe` tokens. Tokens are stored hashed in database. Storage paths are never leaked in responses. |
| **Denial of Service** | Flooding uploads with 10 GB files or brute-forcing endpoints. | Storage exhaustion / Server outage | `MAX_CONTENT_LENGTH` enforced at web server and stream reader. Flask-Limiter enforces rate-limits on uploads and logins. |
| **Elevation of Privilege** | Normal downloader crafts requests to trigger administrative forensic actions. | Unauthorized admin access | Strict session verification and per-request CSRF token validation on all state-changing admin routes. |

---

## 5. RESIDUAL RISKS & ACCEPTABLE LIMITATIONS
- **Local File Erasure vs DoD Wipe:** Python `unlink()` unlinks filesystem pointers but does not perform multi-pass DoD 5220.22-M magnetic zeroing. Sufficient for web application ephemeral sharing; document for academic transparency.
- **Single Host Reference Hash Storage:** If the host database and host disk are compromised concurrently by root access, an attacker could rewrite both file bytes and database hashes.

