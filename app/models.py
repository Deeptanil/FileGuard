from datetime import datetime, timezone
from app.extensions import db

def utc_now():
    """Return current UTC datetime (timezone-aware converted to naive UTC for SQLite compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class FileRecord(db.Model):
    """Represents a temporary file uploaded and monitored by FileGuard."""
    __tablename__ = "file_records"

    id = db.Column(db.Integer, primary_key=True)
    storage_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    display_title = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=False)
    file_extension = db.Column(db.String(32), nullable=False)
    detected_mime_type = db.Column(db.String(128), nullable=False)
    sha256_reference = db.Column(db.String(64), nullable=False)
    share_token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)
    is_e2ee = db.Column(db.Boolean, default=False, nullable=False)
    is_encrypted_at_rest = db.Column(db.Boolean, default=True, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    status = db.Column(db.String(32), default="active", nullable=False, index=True)  # active, expired, deleted, tampered
    uploader_ip = db.Column(db.String(64), nullable=True, index=True)
    is_bundle = db.Column(db.Boolean, default=False, nullable=False)
    malware_status = db.Column(db.String(32), default="pending", nullable=False, index=True)  # pending, scanning, clean, malicious, unscanned, error
    malware_positives = db.Column(db.Integer, default=0, nullable=False)
    malware_scan_details = db.Column(db.String(255), nullable=True)
    scanned_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    security_events = db.relationship("SecurityEvent", backref="file_record", lazy="dynamic", cascade="all, delete-orphan")
    integrity_checks = db.relationship("IntegrityCheck", backref="file_record", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def display_name(self):
        """User-facing title or original filename fallback."""
        if self.display_title and self.display_title.strip():
            return self.display_title.strip()
        return self.original_filename

    @property
    def download_filename(self):
        """Authoritative filename for Content-Disposition header with proper extension guaranteed."""
        from app.security import sanitize_filename

        # If it's a bundle or ZIP archive:
        if getattr(self, "is_bundle", False) or self.file_extension == "zip" or self.detected_mime_type == "application/zip":
            if self.display_title and self.display_title.strip():
                title = self.display_title.strip()
                # If auto-generated bundle summary e.g. "screenshot.png + 1 more file"
                if " + " in title and ("more file" in title or "more files" in title):
                    return self.original_filename if (self.original_filename and self.original_filename.lower().endswith(".zip")) else "FileGuard_Bundle.zip"
                clean_name, _ = sanitize_filename(title)
                if not clean_name.lower().endswith(".zip"):
                    clean_name = f"{clean_name}.zip"
                return clean_name
            return self.original_filename if (self.original_filename and self.original_filename.lower().endswith(".zip")) else "FileGuard_Bundle.zip"

        # Single file:
        ext = (self.file_extension or "").lstrip(".").lower()
        if self.display_title and self.display_title.strip():
            clean_title, _ = sanitize_filename(self.display_title.strip())
            if ext and not clean_title.lower().endswith(f".{ext}"):
                return f"{clean_title}.{ext}"
            return clean_title

        return self.original_filename

    @property
    def has_password(self):
        """Whether download requires a password or PIN."""
        return bool(self.password_hash)

    @property
    def is_expired(self):
        """Check if file has passed its 12-hour expiration deadline."""
        return utc_now() >= self.expires_at

    @property
    def remaining_seconds(self):
        """Seconds remaining before expiration (returns 0 if expired)."""
        diff = (self.expires_at - utc_now()).total_seconds()
        return max(0, int(diff))

    def to_dict(self, include_sensitive=False):
        """Public or admin dictionary representation."""
        data = {
            "id": self.id if include_sensitive else None,
            "filename": self.original_filename,
            "display_title": self.display_name,
            "file_size": self.file_size,
            "extension": self.file_extension,
            "mime_type": self.detected_mime_type,
            "has_password": self.has_password,
            "is_e2ee": self.is_e2ee,
            "is_encrypted_at_rest": self.is_encrypted_at_rest,
            "uploaded_at": self.uploaded_at.isoformat() + "Z",
            "expires_at": self.expires_at.isoformat() + "Z",
            "remaining_seconds": self.remaining_seconds,
            "is_expired": self.is_expired,
            "status": self.status,
            "malware_status": self.malware_status,
            "malware_positives": self.malware_positives,
            "malware_scan_details": self.malware_scan_details,
            "scanned_at": self.scanned_at.isoformat() + "Z" if self.scanned_at else None
        }
        if include_sensitive:
            data.update({
                "storage_id": self.storage_id,
                "sha256_reference": self.sha256_reference,
                "share_token_hash": self.share_token_hash
            })
        return data


class SecurityEvent(db.Model):
    """Structured security audit log record for FileGuard operations."""
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    outcome = db.Column(db.String(32), nullable=False)  # SUCCESS, FAILURE, WARNING, BLOCKED
    severity = db.Column(db.String(16), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    file_record_id = db.Column(db.Integer, db.ForeignKey("file_records.id", ondelete="SET NULL"), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    sanitized_details = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat() + "Z",
            "outcome": self.outcome,
            "severity": self.severity,
            "file_record_id": self.file_record_id,
            "ip_address": self.ip_address,
            "details": self.sanitized_details
        }


class IntegrityCheck(db.Model):
    """Forensic verification history record for a managed file."""
    __tablename__ = "integrity_checks"

    id = db.Column(db.Integer, primary_key=True)
    file_record_id = db.Column(db.Integer, db.ForeignKey("file_records.id", ondelete="CASCADE"), nullable=False)
    checked_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    expected_sha256 = db.Column(db.String(64), nullable=False)
    observed_sha256 = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(16), nullable=False)  # PASS, FAIL, MISSING
    initiated_by = db.Column(db.String(64), nullable=False)  # SYSTEM_DOWNLOAD, ADMIN_MANUAL, SCHEDULED_SCAN
    details = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "file_record_id": self.file_record_id,
            "checked_at": self.checked_at.isoformat() + "Z",
            "expected_sha256": self.expected_sha256,
            "observed_sha256": self.observed_sha256,
            "result": self.result,
            "initiated_by": self.initiated_by,
            "details": self.details
        }


class Administrator(db.Model):
    """Administrative user record for security operations and forensic analysis."""
    __tablename__ = "administrators"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    active_status = db.Column(db.Boolean, default=True, nullable=False)


class BlockedHash(db.Model):
    """Quarantine blocklist for malicious, abusive, or CSAM/copyrighted SHA-256 file hashes."""
    __tablename__ = "blocked_hashes"

    id = db.Column(db.Integer, primary_key=True)
    sha256_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(128), nullable=False)  # CSAM, MALWARE, COPYRIGHT, ABUSE, USER_REPORT
    blocked_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    notes = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "sha256_hash": self.sha256_hash,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat() + "Z",
            "notes": self.notes
        }


class AbuseReport(db.Model):
    """Public content abuse or DMCA takedown submission."""
    __tablename__ = "abuse_reports"

    id = db.Column(db.Integer, primary_key=True)
    token_or_url = db.Column(db.String(255), nullable=False)
    reporter_email = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(64), nullable=False)  # csam, malware, copyright, personal_data, harassment, other
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default="pending", nullable=False)  # pending, resolved, rejected
    submitted_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "token_or_url": self.token_or_url,
            "category": self.category,
            "status": self.status,
            "submitted_at": self.submitted_at.isoformat() + "Z"
        }


