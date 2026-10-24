import io
import hashlib
from datetime import timedelta
from app.models import FileRecord, utc_now
from app.security import hash_token

def get_client_with_csrf(client):
    """Establish a session and return client with CSRF header."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid_csrf_token_value_123"
    return "valid_csrf_token_value_123"


def test_1_valid_file_uploads_successfully(client, db_session):
    """Test 1: A valid file uploads successfully."""
    csrf = get_client_with_csrf(client)
    data = {
        "file": (io.BytesIO(b"Hello FileGuard Test Content"), "test_file.txt"),
        "csrf_token": csrf
    }
    response = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "token" in json_data
    assert "share_url" in json_data
    assert json_data["filename"] == "test_file.txt"


def test_2_correct_sha256_hash_calculated(client, db_session):
    """Test 2: The application calculates and stores the correct SHA-256 hash."""
    csrf = get_client_with_csrf(client)
    content = b"Cryptographic Integrity Reference Content 2026"
    expected_hash = hashlib.sha256(content).hexdigest()

    data = {
        "file": (io.BytesIO(content), "integrity_doc.txt"),
        "csrf_token": csrf
    }
    response = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert response.status_code == 201
    json_data = response.get_json()

    # Verify response hash matches actual content hash
    assert json_data["sha256_reference"] == expected_hash

    # Verify database record matches
    token_h = hash_token(json_data["token"])
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    assert record is not None
    assert record.sha256_reference == expected_hash


def test_3_unique_sharing_token_generated(client, db_session):
    """Test 3: The application creates a unique, unpredictable sharing token."""
    csrf = get_client_with_csrf(client)
    tokens = set()
    for i in range(3):
        data = {
            "file": (io.BytesIO(f"Unique File Content {i}".encode()), f"unique_{i}.txt"),
            "csrf_token": csrf
        }
        res = client.post("/api/files", data=data, content_type="multipart/form-data")
        assert res.status_code == 201
        token = res.get_json()["token"]
        assert len(token) == 9 and token[4] == "-" and token.replace("-", "").isdigit()
        assert token not in tokens
        tokens.add(token)


def test_4_expiration_is_12_hours(client, db_session):
    """Test 4: The expiration timestamp is 12 hours after the upload timestamp."""
    csrf = get_client_with_csrf(client)
    data = {
        "file": (io.BytesIO(b"Expiration Check Bytes"), "expire_check.txt"),
        "csrf_token": csrf
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    json_data = res.get_json()

    token_h = hash_token(json_data["token"])
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    assert record is not None

    diff = record.expires_at - record.uploaded_at
    # Allow small 1-2 second delta for execution time
    assert abs(diff.total_seconds() - (12 * 3600)) < 2


def test_5_oversized_file_rejected(client, db_session, monkeypatch, app):
    """Test 5: An oversized file is rejected."""
    csrf = get_client_with_csrf(client)
    # Temporarily set limit to 100 bytes for fast testing
    monkeypatch.setitem(app.config, "MAX_CONTENT_LENGTH", 100)

    large_content = b"A" * 150
    data = {
        "file": (io.BytesIO(large_content), "large.txt"),
        "csrf_token": csrf
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code in (413, 400)


def test_6_disallowed_file_type_rejected(client, db_session):
    """Test 6: A disallowed file type (.exe, .sh) is rejected."""
    csrf = get_client_with_csrf(client)
    data = {
        "file": (io.BytesIO(b"binary executable payload"), "malware.exe"),
        "csrf_token": csrf
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "Disallowed file type" in res.get_json()["error"]


def test_7_empty_upload_handled_safely(client, db_session):
    """Test 7: An empty or malformed upload is handled safely."""
    csrf = get_client_with_csrf(client)
    data = {
        "file": (io.BytesIO(b""), "empty.txt"),
        "csrf_token": csrf
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 400

