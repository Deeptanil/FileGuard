from app.extensions import db
from app.models import FileRecord, IntegrityCheck, utc_now
from app.storage import get_storage_path
from app.security import compute_sha256
from app.audit import (
    log_security_event,
    EVENT_INTEGRITY_CHECK_PASS,
    EVENT_INTEGRITY_CHECK_FAIL,
    EVENT_FILE_MISSING
)

def verify_file_integrity(file_record: FileRecord, initiated_by: str = "ADMIN_MANUAL") -> dict:
    """
    Perform SHA-256 cryptographic verification of a file against its reference hash.
    Records an IntegrityCheck record and generates a SecurityEvent audit log.
    
    Returns dict:
    {
        "valid": bool,
        "result": "PASS" | "FAIL" | "MISSING",
        "expected": str,
        "observed": str | None,
        "message": str
    }
    """
    path = get_storage_path(file_record.storage_id)
    expected_hash = file_record.sha256_reference

    if not path.exists():
        check = IntegrityCheck(
            file_record_id=file_record.id,
            checked_at=utc_now(),
            expected_sha256=expected_hash,
            observed_sha256=None,
            result="MISSING",
            initiated_by=initiated_by,
            details=f"File not found at storage path: {path.name}"
        )
        db.session.add(check)
        log_security_event(
            event_type=EVENT_FILE_MISSING,
            outcome="FAILURE",
            severity="HIGH",
            file_record_id=file_record.id,
            details={"error": "File missing during integrity verification", "storage_id": file_record.storage_id}
        )
        db.session.commit()
        return {
            "valid": False,
            "result": "MISSING",
            "expected": expected_hash,
            "observed": None,
            "message": "Storage error: File is missing from designated storage."
        }

    try:
        observed_hash = compute_sha256(path)
    except Exception as e:
        return {
            "valid": False,
            "result": "ERROR",
            "expected": expected_hash,
            "observed": None,
            "message": f"Error computing hash: {str(e)}"
        }

    if observed_hash == expected_hash:
        check = IntegrityCheck(
            file_record_id=file_record.id,
            checked_at=utc_now(),
            expected_sha256=expected_hash,
            observed_sha256=observed_hash,
            result="PASS",
            initiated_by=initiated_by,
            details="Cryptographic verification passed. Storage hash matches reference."
        )
        db.session.add(check)
        log_security_event(
            event_type=EVENT_INTEGRITY_CHECK_PASS,
            outcome="SUCCESS",
            severity="INFO",
            file_record_id=file_record.id,
            details={"hash": observed_hash, "initiator": initiated_by}
        )
        db.session.commit()
        return {
            "valid": True,
            "result": "PASS",
            "expected": expected_hash,
            "observed": observed_hash,
            "message": "Integrity verified: the file matches its recorded reference hash."
        }
    else:
        # Integrity violation detected!
        file_record.status = "tampered"
        check = IntegrityCheck(
            file_record_id=file_record.id,
            checked_at=utc_now(),
            expected_sha256=expected_hash,
            observed_sha256=observed_hash,
            result="FAIL",
            initiated_by=initiated_by,
            details=f"Hash mismatch! Expected {expected_hash}, observed {observed_hash}."
        )
        db.session.add(check)
        log_security_event(
            event_type=EVENT_INTEGRITY_CHECK_FAIL,
            outcome="BLOCKED",
            severity="CRITICAL",
            file_record_id=file_record.id,
            details={
                "alert": "Cryptographic integrity violation",
                "expected_hash": expected_hash,
                "observed_hash": observed_hash,
                "storage_id": file_record.storage_id
            }
        )
        db.session.commit()
        return {
            "valid": False,
            "result": "FAIL",
            "expected": expected_hash,
            "observed": observed_hash,
            "message": "Integrity warning: the file differs from its recorded reference hash."
        }


def scheduled_integrity_scan(limit: int = 20) -> list[dict]:
    """Scheduled background scan of active unexpired files."""
    records = FileRecord.query.filter_by(status="active").limit(limit).all()
    results = []
    for record in records:
        if not record.is_expired:
            res = verify_file_integrity(record, initiated_by="SCHEDULED_SCAN")
            results.append({"id": record.id, "filename": record.original_filename, **res})
    return results

