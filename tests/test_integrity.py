import io
from app.models import FileRecord, SecurityEvent, IntegrityCheck
from app.integrity import verify_file_integrity
from app.storage import get_storage_path
from app.security import hash_token

def upload_for_integrity(client, filename="doc.txt", content=b"Original trustworthy file bytes"):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_int_test"
    data = {
        "file": (io.BytesIO(content), filename),
        "csrf_token": "csrf_int_test"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]
    record = FileRecord.query.filter_by(share_token_hash=hash_token(token)).first()
    return token, record


def test_14_newly_uploaded_file_passes_integrity(client, db_session):
    """Test 14: A newly uploaded file passes integrity verification."""
    token, record = upload_for_integrity(client)
    result = verify_file_integrity(record)
    assert result["valid"] is True
    assert result["result"] == "PASS"
    assert result["expected"] == result["observed"]


def test_15_modifying_file_causes_verification_failure(client, db_session):
    """Test 15: Modifying a test file causes verification to fail."""
    token, record = upload_for_integrity(client)
    path = get_storage_path(record.storage_id)

    # Tamper with the physical file directly on disk
    with open(path, "ab") as f:
        f.write(b"CORRUPTED_BYTES")

    result = verify_file_integrity(record)
    assert result["valid"] is False
    assert result["result"] == "FAIL"
    assert result["expected"] != result["observed"]
    assert record.status == "tampered"


def test_16_missing_file_reported_correctly(client, db_session):
    """Test 16: A missing file is reported correctly."""
    token, record = upload_for_integrity(client)
    path = get_storage_path(record.storage_id)

    # Delete the physical file from disk while leaving database record intact
    path.unlink()

    result = verify_file_integrity(record)
    assert result["valid"] is False
    assert result["result"] == "MISSING"


def test_17_failed_integrity_creates_security_event(client, db_session):
    """Test 17: A failed integrity check creates a structured security event."""
    token, record = upload_for_integrity(client)
    path = get_storage_path(record.storage_id)

    with open(path, "ab") as f:
        f.write(b"UNAUTHORIZED_MODIFICATION")

    verify_file_integrity(record)

    event = SecurityEvent.query.filter_by(
        file_record_id=record.id,
        event_type="INTEGRITY_CHECK_FAIL"
    ).first()

    assert event is not None
    assert event.severity == "CRITICAL"
    assert event.outcome == "BLOCKED"


def test_18_reference_hash_not_overwritten_after_mismatch(client, db_session):
    """Test 18: The original reference hash is NOT silently overwritten after a mismatch."""
    token, record = upload_for_integrity(client)
    original_reference_hash = record.sha256_reference
    path = get_storage_path(record.storage_id)

    with open(path, "ab") as f:
        f.write(b"TAMPER_ATTEMPT")

    verify_file_integrity(record)

    # Reload from database to ensure no overwrite
    reloaded_record = FileRecord.query.get(record.id)
    assert reloaded_record.sha256_reference == original_reference_hash


def test_19_failed_integrity_blocks_downloads(client, db_session):
    """Test 19: A failed integrity check blocks downloads when enforcement is enabled."""
    token, record = upload_for_integrity(client)
    path = get_storage_path(record.storage_id)

    # Tamper with storage bytes
    with open(path, "ab") as f:
        f.write(b"MALICIOUS_INJECTION")

    # Recipient attempts to download the modified file
    response = client.get(f"/api/files/{token}/download")
    assert response.status_code == 409  # Conflict / Integrity Mismatch
    assert b"Download Blocked" in response.data or b"integrity" in response.data.lower()

