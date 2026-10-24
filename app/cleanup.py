import logging
from app.extensions import db
from app.models import FileRecord, utc_now
from app.storage import delete_stored_file, get_storage_path
from app.audit import log_security_event, EVENT_CLEANUP_DELETED, EVENT_CLEANUP_FAILED

logger = logging.getLogger(__name__)

def run_expired_files_cleanup() -> dict:
    """
    Find expired files, securely remove the physical files from server storage,
    update lifecycle records to 'deleted', and record audit events.
    """
    now = utc_now()
    # Find all active or expired records whose expires_at is in the past
    expired_records = FileRecord.query.filter(
        FileRecord.expires_at <= now,
        FileRecord.status != "deleted"
    ).all()

    stats = {
        "found": len(expired_records),
        "deleted_storage": 0,
        "missing_storage": 0,
        "failed": 0
    }

    for record in expired_records:
        try:
            path = get_storage_path(record.storage_id)
            storage_existed = path.exists()

            if storage_existed:
                deleted = delete_stored_file(record.storage_id)
                if deleted:
                    stats["deleted_storage"] += 1
                else:
                    stats["failed"] += 1
            else:
                stats["missing_storage"] += 1

            record.status = "deleted"
            db.session.commit()

            log_security_event(
                event_type=EVENT_CLEANUP_DELETED,
                outcome="SUCCESS",
                severity="INFO",
                file_record_id=record.id,
                details={
                    "storage_id": record.storage_id,
                    "filename": record.original_filename,
                    "storage_file_existed": storage_existed
                }
            )
        except Exception as e:
            stats["failed"] += 1
            logger.error(f"Error during cleanup of file record {record.id}: {str(e)}")
            log_security_event(
                event_type=EVENT_CLEANUP_FAILED,
                outcome="FAILURE",
                severity="HIGH",
                file_record_id=record.id,
                details={"error": str(e), "storage_id": record.storage_id}
            )

    return stats

