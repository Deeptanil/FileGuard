from app.extensions import db
from app.models import FileRecord, utc_now

def is_file_expired(file_record: FileRecord) -> bool:
    """
    Authoritative server-side expiration check.
    Returns True if current UTC time >= file's expiration timestamp, or if status is expired/deleted.
    """
    if file_record.status in ("expired", "deleted"):
        return True

    if utc_now() >= file_record.expires_at:
        if file_record.status == "active":
            file_record.status = "expired"
            db.session.commit()
        return True

    return False

