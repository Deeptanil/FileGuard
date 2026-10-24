import json
from datetime import datetime, timezone
from flask import request
from app.extensions import db
from app.models import SecurityEvent, utc_now
from app.security import get_client_ip

# Standard Event Types
EVENT_UPLOAD_SUCCESS = "FILE_UPLOAD_SUCCESS"
EVENT_UPLOAD_REJECTED = "FILE_UPLOAD_REJECTED"
EVENT_DOWNLOAD_SUCCESS = "FILE_DOWNLOAD_SUCCESS"
EVENT_DOWNLOAD_BLOCKED_EXP = "DOWNLOAD_BLOCKED_EXPIRED"
EVENT_DOWNLOAD_BLOCKED_INT = "DOWNLOAD_BLOCKED_INTEGRITY_FAIL"
EVENT_INVALID_TOKEN = "INVALID_TOKEN_ACCESS"
EVENT_INTEGRITY_CHECK_PASS = "INTEGRITY_CHECK_PASS"
EVENT_INTEGRITY_CHECK_FAIL = "INTEGRITY_CHECK_FAIL"
EVENT_FILE_MISSING = "FILE_MISSING_FROM_STORAGE"
EVENT_CLEANUP_DELETED = "CLEANUP_FILE_DELETED"
EVENT_CLEANUP_FAILED = "CLEANUP_OPERATION_FAILED"
EVENT_ADMIN_LOGIN_SUCCESS = "ADMIN_LOGIN_SUCCESS"
EVENT_ADMIN_LOGIN_FAIL = "ADMIN_LOGIN_FAIL"
EVENT_ADMIN_LOGOUT = "ADMIN_LOGOUT"
EVENT_FORENSIC_INSPECTION = "FORENSIC_INSPECTION"
EVENT_UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ADMIN_ACCESS"
EVENT_RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"


def log_security_event(
    event_type: str,
    outcome: str,
    severity: str = "INFO",
    file_record_id: int | None = None,
    details: str | dict = "",
    ip_address: str | None = None,
    commit: bool = True
) -> SecurityEvent | None:
    """
    Log a structured security audit event into the database.
    Severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL.
    """
    try:
        if isinstance(details, dict):
            sanitized_details = json.dumps(details)
        else:
            sanitized_details = str(details)

        ip = ip_address or (get_client_ip() if request else "system")

        event = SecurityEvent(
            event_type=event_type,
            timestamp=utc_now(),
            outcome=outcome,
            severity=severity,
            file_record_id=file_record_id,
            ip_address=ip,
            sanitized_details=sanitized_details[:2000]
        )
        db.session.add(event)
        if commit:
            db.session.commit()
        return event
    except Exception as e:
        # Fallback to prevent audit logging failures from cascading
        db.session.rollback()
        return None

