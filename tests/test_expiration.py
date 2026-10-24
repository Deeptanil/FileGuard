import io
from datetime import timedelta
from app.models import FileRecord, utc_now, SecurityEvent
from app.cleanup import run_expired_files_cleanup
from app.storage import get_storage_path
from app.security import hash_token

def upload_for_cleanup(client, filename="temp.txt", content=b"Temporary cleanup payload"):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_clean_test"
    data = {
        "file": (io.BytesIO(content), filename),
        "csrf_token": "csrf_clean_test"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    token = res.get_json()["token"]
    record = FileRecord.query.filter_by(share_token_hash=hash_token(token)).first()
    return token, record


def test_20_expired_files_deleted_from_storage(client, db_session):
    """Test 20: Expired files are deleted from physical storage by the cleanup worker."""
    token, record = upload_for_cleanup(client)
    path = get_storage_path(record.storage_id)
    assert path.exists()

    # Expire file
    record.expires_at = utc_now() - timedelta(hours=1)
    db_session.commit()

    stats = run_expired_files_cleanup()
    assert stats["deleted_storage"] >= 1
    assert not path.exists()

    reloaded = FileRecord.query.get(record.id)
    assert reloaded.status == "deleted"


def test_21_expired_files_inaccessible_after_restart(app, client, db_session):
    """Test 21: Expired files cannot be accessed after an application restart."""
    token, record = upload_for_cleanup(client)
    record.expires_at = utc_now() - timedelta(minutes=10)
    db_session.commit()

    # Create fresh test client to simulate restart
    fresh_client = app.test_client()
    res = fresh_client.get(f"/api/files/{token}/download")
    assert res.status_code == 410


def test_22_cleanup_does_not_delete_active_files(client, db_session):
    """Test 22: Cleanup does not delete active files that have not yet reached expiration."""
    token, record = upload_for_cleanup(client)
    path = get_storage_path(record.storage_id)
    assert path.exists()

    # File is still within 12-hour window
    stats = run_expired_files_cleanup()
    # Active file must remain untouched
    assert path.exists()
    reloaded = FileRecord.query.get(record.id)
    assert reloaded.status == "active"


def test_23_missing_expired_files_handled_gracefully(client, db_session):
    """Test 23: Missing expired files are handled gracefully during cleanup without crashes."""
    token, record = upload_for_cleanup(client)
    path = get_storage_path(record.storage_id)

    # Manually remove file from disk prior to cleanup
    if path.exists():
        path.unlink()

    # Expire record
    record.expires_at = utc_now() - timedelta(hours=2)
    db_session.commit()

    # Cleanup must run smoothly and record missing file count
    stats = run_expired_files_cleanup()
    assert stats["missing_storage"] >= 1
    reloaded = FileRecord.query.get(record.id)
    assert reloaded.status == "deleted"


def test_24_cleanup_audit_events_recorded(client, db_session):
    """Test 24: Cleanup executions record audit events."""
    token, record = upload_for_cleanup(client)
    record.expires_at = utc_now() - timedelta(hours=1)
    db_session.commit()

    run_expired_files_cleanup()

    event = SecurityEvent.query.filter_by(
        file_record_id=record.id,
        event_type="CLEANUP_FILE_DELETED"
    ).first()
    assert event is not None
    assert event.outcome == "SUCCESS"

